# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os

from alembic import command as alembic_api
from alembic import script as alembic_script
import fixtures
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures
from oslo_log import log as logging
import sqlalchemy

from keystone.common import sql
from keystone.common.sql import upgrades
import keystone.conf
from keystone.tests import unit

# We need to import all of these so the tables are registered. It would be
# easier if these were all in a central location :(
import keystone.application_credential.backends.sql  # noqa: F401
import keystone.assignment.backends.sql  # noqa: F401
import keystone.assignment.role_backends.sql_model  # noqa: F401
import keystone.catalog.backends.sql  # noqa: F401
import keystone.credential.backends.sql  # noqa: F401
import keystone.endpoint_policy.backends.sql  # noqa: F401
import keystone.federation.backends.sql  # noqa: F401
import keystone.identity.backends.sql_model  # noqa: F401
import keystone.identity.mapping_backends.sql  # noqa: F401
import keystone.limit.backends.sql  # noqa: F401
import keystone.oauth1.backends.sql  # noqa: F401
import keystone.policy.backends.sql  # noqa: F401
import keystone.resource.backends.sql_model  # noqa: F401
import keystone.resource.config_backends.sql  # noqa: F401
import keystone.revoke.backends.sql  # noqa: F401
import keystone.trust.backends.sql  # noqa: F401

LOG = logging.getLogger(__name__)


class DBOperationNotAllowed(Exception):
    pass


class BannedDBSchemaOperations(fixtures.Fixture):
    """Ban some operations for migrations."""

    def __init__(self, banned_ops, revision):
        super().__init__()
        self._banned_ops = banned_ops or {}
        self._revision = revision

    @staticmethod
    def _explode(op, revision):
        def fail(*a, **kw):
            msg = "Operation '%s' is not allowed in migration %s"
            raise DBOperationNotAllowed(msg % (op, revision))

        return fail

    def setUp(self):
        super().setUp()
        for op in self._banned_ops:
            self.useFixture(
                fixtures.MonkeyPatch(
                    'alembic.op.%s' % op, self._explode(op, self._revision),
                )
            )


class KeystoneMigrationsWalk(
    test_fixtures.OpportunisticDBTestMixin,
):
    # Migrations can take a long time, particularly on underpowered CI nodes.
    # Give them some breathing room.
    TIMEOUT_SCALING_FACTOR = 4

    BANNED_OPS = {
        'expand': [
            'alter_column',
            'drop_column',
            'drop_constraint',
            'drop_index',
            'drop_table',
            'drop_table_comment',
            # 'execute',
            'rename_table',
        ],
        'contract': {
            'add_column',
            'bulk_insert',
            'create_check_constraint',
            'create_exclude_constraint',
            'create_foreign_key',
            'create_index',
            'create_primary_key',
            'create_table',
            'create_table_comment',
            'create_unique_constraint',
            # 'execute',
            'rename_table',
        },
    }

    BANNED_OP_EXCEPTIONS = [
        # NOTE(xek, henry-nash): Reviewers: DO NOT ALLOW THINGS TO BE ADDED
        # HERE UNLESS JUSTIFICATION CAN BE PROVIDED AS TO WHY THIS WILL NOT
        # CAUSE PROBLEMS FOR ROLLING UPGRADES.
    ]

    def setUp(self):
        super().setUp()
        self.engine = enginefacade.writer.get_engine()
        self.config = upgrades._find_alembic_conf()
        self.init_version = upgrades.ALEMBIC_INIT_VERSION

        # TODO(stephenfin): Do we need this? I suspect not since we're using
        # enginefacade.write.get_engine() directly above
        # Override keystone's context manager to be oslo.db's global context
        # manager.
        sql.core._TESTING_USE_GLOBAL_CONTEXT_MANAGER = True
        self.addCleanup(setattr,
                        sql.core, '_TESTING_USE_GLOBAL_CONTEXT_MANAGER', False)
        self.addCleanup(sql.cleanup)

    def _migrate_up(self, connection, revision):
        version = revision.revision

        if version == self.init_version:  # no tests for the initial revision
            alembic_api.upgrade(self.config, version)
            return

        self.assertIsNotNone(
            getattr(self, '_check_%s' % version, None),
            (
                'DB Migration %s does not have a test; you must add one'
            ) % version,
        )

        pre_upgrade = getattr(self, '_pre_upgrade_%s' % version, None)
        if pre_upgrade:
            pre_upgrade(connection)

        banned_ops = []
        if version not in self.BANNED_OP_EXCEPTIONS:
            # there should only ever be one label, but this is safer
            for branch_label in revision.branch_labels:
                banned_ops.extend(self.BANNED_OPS[branch_label])

        # SQLite migrations are running in batch mode, which mean we recreate a
        # table in all migrations. As such, we can't really blacklist things so
        # don't even try.
        if self.FIXTURE.DRIVER == 'sqlite':
            banned_ops = []

        with BannedDBSchemaOperations(banned_ops, version):
            alembic_api.upgrade(self.config, version)

        post_upgrade = getattr(self, '_check_%s' % version, None)
        if post_upgrade:
            post_upgrade(connection)

    def _pre_upgrade_e25ffa003242(self, connection):
        """This is a no-op migration."""
        pass

    def _check_e25ffa003242(self, connection):
        """This is a no-op migration."""
        pass

    def _pre_upgrade_29e87d24a316(self, connection):
        """This is a no-op migration."""
        pass

    def _check_29e87d24a316(self, connection):
        """This is a no-op migration."""
        pass

    # 2023.2 bobcat

    _99de3849d860_removed_constraints = {
        'access_rule': 'access_rule_external_id_key',
        'trust': 'duplicate_trust_constraint_expanded',
    }

    def _pre_upgrade_99de3849d860(self, connection):
        inspector = sqlalchemy.inspect(connection)
        for table, constraint in (
            self._99de3849d860_removed_constraints.items()
        ):
            constraints = [
                x['name'] for x in
                inspector.get_unique_constraints(table)
            ]
            self.assertIn(constraint, constraints)

    def _check_99de3849d860(self, connection):
        inspector = sqlalchemy.inspect(connection)
        for table, constraint in (
            self._99de3849d860_removed_constraints.items()
        ):
            constraints = [
                x['name'] for x in
                inspector.get_unique_constraints(table)
            ]
            self.assertNotIn(constraint, constraints)

    def _pre_upgrade_b4f8b3f584e0(self, connection):
        inspector = sqlalchemy.inspect(connection)
        constraints = inspector.get_unique_constraints('trust')
        self.assertNotIn(
            'duplicate_trust_constraint',
            {x['name'] for x in constraints},
        )

        all_constraints = []
        for c in constraints:
            all_constraints + c.get('column_names', [])

        not_allowed_constraints = ['trustor_user_id', 'trustee_user_id',
                                   'project_id', 'impersonation', 'expires_at',
                                   ]
        for not_c in not_allowed_constraints:
            self.assertNotIn(not_c, all_constraints)

    def _check_b4f8b3f584e0(self, connection):
        inspector = sqlalchemy.inspect(connection)
        constraints = inspector.get_unique_constraints('trust')
        self.assertIn(
            'duplicate_trust_constraint',
            {x['name'] for x in constraints},
        )
        constraint = [
            x for x in constraints if x['name'] ==
            'duplicate_trust_constraint'
        ][0]
        self.assertEqual(
            [
                'trustor_user_id',
                'trustee_user_id',
                'project_id',
                'impersonation',
                'expires_at',
            ],
            constraint['column_names'],
        )

    def _pre_upgrade_c88cdce8f248(self, connection):
        if connection.engine.name != 'mysql':
            return

        # NOTE(stephenfin): Even though the migration is written to handle
        # names generated by both alembic and sqlalchemy-migrate, we only check
        # for the former here since we don't apply sqlalchemy-migrate
        # migrations anymore
        inspector = sqlalchemy.inspect(connection)
        indexes = inspector.get_indexes('project_tag')
        self.assertIn('project_id', {x['name'] for x in indexes})

    def _check_c88cdce8f248(self, connection):
        # This migration only applies to MySQL
        if connection.engine.name != 'mysql':
            return

        inspector = sqlalchemy.inspect(connection)
        indexes = inspector.get_indexes('project_tag')
        self.assertNotIn('project_id', {x['name'] for x in indexes})

    def _pre_upgrade_11c3b243b4cb(self, connection):
        inspector = sqlalchemy.inspect(connection)
        columns = inspector.get_columns('service_provider')
        found = False
        for column in columns:
            if column['name'] != 'relay_state_prefix':
                continue

            # The default should initially be set to the CONF value
            self.assertIsNotNone(column['default'])
            found = True
        self.assertTrue(found, 'Failed to find column')

    def _check_11c3b243b4cb(self, connection):
        inspector = sqlalchemy.inspect(connection)
        columns = inspector.get_columns('service_provider')
        found = False
        for column in columns:
            if column['name'] != 'relay_state_prefix':
                continue

            # The default should now be unset
            self.assertIsNone(column['default'])
            found = True
        self.assertTrue(found, 'Failed to find column')

    def _pre_upgrade_47147121(self, connection):
        inspector = sqlalchemy.inspect(connection)
        columns = inspector.get_columns('mapping')

        all_column_names = []
        for c in columns:
            all_column_names.append(c.get('name'))

        self.assertNotIn('schema_version', all_column_names)

    def _check_47147121(self, connection):
        inspector = sqlalchemy.inspect(connection)
        columns = inspector.get_columns('mapping')

        all_column_names = []
        for c in columns:
            all_column_names.append(c.get('name'))

        self.assertIn('schema_version', all_column_names)

    def test_single_base_revision(self):
        """Ensure we only have a single base revision.

        There's no good reason for us to have diverging history, so validate
        that only one base revision exists. This will prevent simple errors
        where people forget to specify the base revision. If this fail for
        your change, look for migrations that do not have a 'revises' line in
        them.
        """
        script = alembic_script.ScriptDirectory.from_config(self.config)
        self.assertEqual(1, len(script.get_bases()))

    def test_head_revisions(self):
        """Ensure we only have a two head revisions.

        There's no good reason for us to have diverging history beyond the
        expand and contract branches, so validate that only these head
        revisions exist. This will prevent merge conflicts adding additional
        head revision points. If this fail for your change, look for migrations
        with the duplicate 'revises' line in them.
        """
        script = alembic_script.ScriptDirectory.from_config(self.config)
        self.assertEqual(2, len(script.get_heads()))

    def test_walk_versions(self):
        with self.engine.begin() as connection:
            self.config.attributes['connection'] = connection
            script = alembic_script.ScriptDirectory.from_config(self.config)
            revisions = [x for x in script.walk_revisions()]

            # for some reason, 'walk_revisions' gives us the revisions in
            # reverse chronological order so we have to invert this
            revisions.reverse()
            self.assertEqual(revisions[0].revision, self.init_version)

            for revision in revisions:
                LOG.info('Testing revision %s', revision.revision)
                self._migrate_up(connection, revision)

    def _get_head_from_file(self, branch):
        path = os.path.join(
            os.path.dirname(upgrades.__file__),
            'migrations',
            'versions',
            f'{branch.upper()}_HEAD',
        )

        with open(path) as fh:
            return fh.read().strip()

    def test_db_version_alembic(self):
        upgrades.offline_sync_database_to_version(engine=self.engine)

        for branch in (upgrades.EXPAND_BRANCH, upgrades.CONTRACT_BRANCH):
            head = self._get_head_from_file(branch)
            self.assertEqual(head, upgrades.get_db_version(branch))


class TestMigrationsWalkSQLite(
    KeystoneMigrationsWalk,
    test_fixtures.OpportunisticDBTestMixin,
    unit.TestCase,
):
    pass


class TestMigrationsWalkMySQL(
    KeystoneMigrationsWalk,
    test_fixtures.OpportunisticDBTestMixin,
    unit.TestCase,
):
    FIXTURE = test_fixtures.MySQLOpportunisticFixture


class TestMigrationsWalkPostgreSQL(
    KeystoneMigrationsWalk,
    test_fixtures.OpportunisticDBTestMixin,
    unit.TestCase,
):
    FIXTURE = test_fixtures.PostgresqlOpportunisticFixture
