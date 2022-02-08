# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime
import textwrap

import migrate
from oslo_log import log
import sqlalchemy as sql

from keystone.assignment.backends import sql as assignment_sql
from keystone.common import sql as ks_sql
import keystone.conf
from keystone.identity.mapping_backends import mapping as mapping_backend

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

# FIXME(stephenfin): Remove this as soon as we're done reworking the
# migrations. Until then, this is necessary to allow us to use the native
# sqlalchemy-migrate tooling (which won't register opts). Alternatively, maybe
# the server default *shouldn't* rely on a (changeable) config option value?
try:
    service_provider_relay_state_prefix_default = CONF.saml.relay_state_prefix
except Exception:
    service_provider_relay_state_prefix_default = 'ss:mem:'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if migrate_engine.name == 'mysql':
        # In Folsom we explicitly converted migrate_version to UTF8.
        migrate_engine.execute(
            'ALTER TABLE migrate_version CONVERT TO CHARACTER SET utf8'
        )
        # Set default DB charset to UTF8.
        migrate_engine.execute(
            'ALTER DATABASE %s DEFAULT CHARACTER SET utf8'
            % migrate_engine.url.database
        )

    application_credential = sql.Table(
        'application_credential',
        meta,
        sql.Column(
            'internal_id', sql.Integer, primary_key=True, nullable=False
        ),
        sql.Column('id', sql.String(length=64), nullable=False),
        sql.Column('name', sql.String(length=255), nullable=False),
        sql.Column('secret_hash', sql.String(length=255), nullable=False),
        sql.Column('description', sql.Text),
        sql.Column('user_id', sql.String(length=64), nullable=False),
        sql.Column('project_id', sql.String(64), nullable=True),
        sql.Column('expires_at', ks_sql.DateTimeInt()),
        sql.Column('system', sql.String(64), nullable=True),
        sql.Column('unrestricted', sql.Boolean),
        sql.UniqueConstraint(
            'user_id', 'name', name='duplicate_app_cred_constraint'
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    assignment = sql.Table(
        'assignment',
        meta,
        sql.Column(
            'type',
            sql.Enum(
                assignment_sql.AssignmentType.USER_PROJECT,
                assignment_sql.AssignmentType.GROUP_PROJECT,
                assignment_sql.AssignmentType.USER_DOMAIN,
                assignment_sql.AssignmentType.GROUP_DOMAIN,
                name='type',
            ),
            nullable=False,
        ),
        sql.Column('actor_id', sql.String(64), nullable=False),
        sql.Column('target_id', sql.String(64), nullable=False),
        sql.Column('role_id', sql.String(64), nullable=False),
        sql.Column('inherited', sql.Boolean, default=False, nullable=False),
        sql.PrimaryKeyConstraint(
            'type',
            'actor_id',
            'target_id',
            'role_id',
            'inherited',
        ),
        sql.Index('ix_actor_id', 'actor_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    access_rule = sql.Table(
        'access_rule',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column('service', sql.String(64)),
        sql.Column('path', sql.String(128)),
        sql.Column('method', sql.String(16)),
        sql.Column('external_id', sql.String(64)),
        sql.Column('user_id', sql.String(64)),
        sql.UniqueConstraint(
            'external_id',
            name='access_rule_external_id_key',
        ),
        sql.UniqueConstraint(
            'user_id',
            'service',
            'path',
            'method',
            name='duplicate_access_rule_for_user_constraint',
        ),
        sql.Index('user_id', 'user_id'),
        sql.Index('external_id', 'external_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    config_register = sql.Table(
        'config_register',
        meta,
        sql.Column('type', sql.String(64), primary_key=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    consumer = sql.Table(
        'consumer',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('description', sql.String(64), nullable=True),
        sql.Column('secret', sql.String(64), nullable=False),
        sql.Column('extra', sql.Text(), nullable=False),
    )

    credential = sql.Table(
        'credential',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('user_id', sql.String(length=64), nullable=False),
        sql.Column('project_id', sql.String(length=64)),
        sql.Column('type', sql.String(length=255), nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('key_hash', sql.String(64), nullable=False),
        sql.Column(
            'encrypted_blob',
            ks_sql.Text,
            nullable=False,
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    group = sql.Table(
        'group',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('domain_id', sql.String(length=64), nullable=False),
        sql.Column('name', sql.String(length=64), nullable=False),
        sql.Column('description', sql.Text),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        migrate.UniqueConstraint(
            'domain_id',
            'name',
            name='ixu_group_name_domain_id',
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    id_mapping = sql.Table(
        'id_mapping',
        meta,
        sql.Column('public_id', sql.String(64), primary_key=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.Column('local_id', sql.String(64), nullable=False),
        sql.Column(
            'entity_type',
            sql.Enum(
                mapping_backend.EntityType.USER,
                mapping_backend.EntityType.GROUP,
                name='entity_type',
            ),
            nullable=False,
        ),
        migrate.UniqueConstraint(
            'domain_id',
            'local_id',
            'entity_type',
            name='domain_id',
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    identity_provider = sql.Table(
        'identity_provider',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('enabled', sql.Boolean, nullable=False),
        sql.Column('description', sql.Text(), nullable=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.Column('authorization_ttl', sql.Integer, nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    idp_remote_ids = sql.Table(
        'idp_remote_ids',
        meta,
        sql.Column(
            'idp_id',
            sql.String(64),
            sql.ForeignKey(identity_provider.c.id, ondelete='CASCADE'),
        ),
        sql.Column('remote_id', sql.String(255), primary_key=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    mapping = sql.Table(
        'mapping',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('rules', sql.Text(), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    policy = sql.Table(
        'policy',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('type', sql.String(length=255), nullable=False),
        sql.Column('blob', ks_sql.JsonBlob, nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    policy_association = sql.Table(
        'policy_association',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('policy_id', sql.String(64), nullable=False),
        sql.Column('endpoint_id', sql.String(64), nullable=True),
        sql.Column('service_id', sql.String(64), nullable=True),
        sql.Column('region_id', sql.String(64), nullable=True),
        sql.UniqueConstraint('endpoint_id', 'service_id', 'region_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    project = sql.Table(
        'project',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('name', sql.String(length=64), nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('description', sql.Text),
        sql.Column('enabled', sql.Boolean),
        sql.Column(
            'domain_id',
            sql.String(length=64),
            sql.ForeignKey(
                'project.id',
                name='project_domain_id_fkey',
            ),
            nullable=False,
        ),
        sql.Column(
            'parent_id',
            sql.String(64),
            sql.ForeignKey(
                'project.id',
                name='project_parent_id_fkey',
            ),
            nullable=True,
        ),
        sql.Column(
            'is_domain',
            sql.Boolean,
            nullable=False,
            server_default='0',
            default=False,
        ),
        migrate.UniqueConstraint(
            'domain_id',
            'name',
            name='ixu_project_name_domain_id',
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    project_endpoint = sql.Table(
        'project_endpoint',
        meta,
        sql.Column(
            'endpoint_id', sql.String(64), primary_key=True, nullable=False
        ),
        sql.Column(
            'project_id', sql.String(64), primary_key=True, nullable=False
        ),
    )

    project_option = sql.Table(
        'project_option',
        meta,
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey(project.c.id, ondelete='CASCADE'),
            nullable=False,
            primary_key=True,
        ),
        sql.Column(
            'option_id', sql.String(4), nullable=False, primary_key=True
        ),
        sql.Column('option_value', ks_sql.JsonBlob, nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    # NOTE(lamt) To allow tag name to be case sensitive for MySQL, the 'name'
    # column needs to use collation, which is incompatible with Postgresql.
    # Using unicode to mirror nova's server tag:
    # https://github.com/openstack/nova/blob/master/nova/db/sqlalchemy/models.py
    project_tag = sql.Table(
        'project_tag',
        meta,
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey(project.c.id, ondelete='CASCADE'),
            nullable=False,
            primary_key=True,
        ),
        sql.Column('name', sql.Unicode(255), nullable=False, primary_key=True),
        sql.UniqueConstraint('project_id', 'name'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    region = sql.Table(
        'region',
        meta,
        sql.Column('id', sql.String(255), primary_key=True),
        sql.Column('description', sql.String(255), nullable=False),
        sql.Column('parent_region_id', sql.String(255), nullable=True),
        sql.Column('extra', sql.Text()),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    registered_limit = sql.Table(
        'registered_limit',
        meta,
        sql.Column('id', sql.String(length=64), nullable=False),
        sql.Column('service_id', sql.String(255)),
        sql.Column('region_id', sql.String(64), nullable=True),
        sql.Column('resource_name', sql.String(255)),
        sql.Column('default_limit', sql.Integer, nullable=False),
        sql.Column('description', sql.Text),
        sql.Column('internal_id', sql.Integer, primary_key=True),
        # NOTE(stephenfin): Name chosen to preserve backwards compatibility
        # with names used for primary key unique constraints
        sql.UniqueConstraint('id', name='registered_limit_id_key'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    request_token = sql.Table(
        'request_token',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('request_secret', sql.String(64), nullable=False),
        sql.Column('verifier', sql.String(64), nullable=True),
        sql.Column('authorizing_user_id', sql.String(64), nullable=True),
        sql.Column('requested_project_id', sql.String(64), nullable=False),
        sql.Column('role_ids', sql.Text(), nullable=True),
        sql.Column(
            'consumer_id',
            sql.String(64),
            sql.ForeignKey(consumer.c.id),
            nullable=False,
            index=True,
        ),
        sql.Column('expires_at', sql.String(64), nullable=True),
    )

    revocation_event = sql.Table(
        'revocation_event',
        meta,
        sql.Column('id', sql.Integer, primary_key=True),
        sql.Column('domain_id', sql.String(64)),
        sql.Column('project_id', sql.String(64)),
        sql.Column('user_id', sql.String(64)),
        sql.Column('role_id', sql.String(64)),
        sql.Column('trust_id', sql.String(64)),
        sql.Column('consumer_id', sql.String(64)),
        sql.Column('access_token_id', sql.String(64)),
        sql.Column('issued_before', sql.DateTime(), nullable=False),
        sql.Column('expires_at', sql.DateTime()),
        sql.Column('revoked_at', sql.DateTime(), nullable=False),
        sql.Column('audit_id', sql.String(32), nullable=True),
        sql.Column('audit_chain_id', sql.String(32), nullable=True),
        # NOTE(stephenfin): The '_new' suffix here is due to migration 095,
        # which changed the 'id' column from String(64) to Integer. It did this
        # by creating a 'revocation_event_new' table and populating it with
        # data from the 'revocation_event' table before deleting the
        # 'revocation_event' table and renaming the 'revocation_event_new'
        # table to 'revocation_event'. Because the 'revoked_at' column had
        # 'index=True', sqlalchemy automatically generated the index name as
        # 'ix_{table}_{column}'. However, when intitially created, '{table}'
        # was 'revocation_event_new' so the index got that name. We may wish to
        # rename this eventually.
        sql.Index('ix_revocation_event_new_revoked_at', 'revoked_at'),
        sql.Index('ix_revocation_event_issued_before', 'issued_before'),
        sql.Index(
            'ix_revocation_event_project_id_issued_before',
            'project_id',
            'issued_before',
        ),
        sql.Index(
            'ix_revocation_event_user_id_issued_before',
            'user_id',
            'issued_before',
        ),
        sql.Index(
            'ix_revocation_event_audit_id_issued_before',
            'audit_id',
            'issued_before',
        ),
    )

    role = sql.Table(
        'role',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('name', sql.String(length=255), nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column(
            'domain_id',
            sql.String(64),
            nullable=False,
            server_default='<<null>>',
        ),
        sql.Column('description', sql.String(255), nullable=True),
        migrate.UniqueConstraint(
            'name',
            'domain_id',
            name='ixu_role_name_domain_id',
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    role_option = sql.Table(
        'role_option',
        meta,
        sql.Column(
            'role_id',
            sql.String(64),
            sql.ForeignKey(role.c.id, ondelete='CASCADE'),
            nullable=False,
            primary_key=True,
        ),
        sql.Column(
            'option_id', sql.String(4), nullable=False, primary_key=True
        ),
        sql.Column('option_value', ks_sql.JsonBlob, nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    sensitive_config = sql.Table(
        'sensitive_config',
        meta,
        sql.Column('domain_id', sql.String(64), primary_key=True),
        sql.Column('group', sql.String(255), primary_key=True),
        sql.Column('option', sql.String(255), primary_key=True),
        sql.Column('value', ks_sql.JsonBlob.impl, nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    service = sql.Table(
        'service',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('type', sql.String(length=255)),
        sql.Column(
            'enabled',
            sql.Boolean,
            nullable=False,
            default=True,
            server_default='1',
        ),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    service_provider = sql.Table(
        'service_provider',
        meta,
        sql.Column('auth_url', sql.String(256), nullable=False),
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('enabled', sql.Boolean, nullable=False),
        sql.Column('description', sql.Text(), nullable=True),
        sql.Column('sp_url', sql.String(256), nullable=False),
        sql.Column(
            'relay_state_prefix',
            sql.String(256),
            nullable=False,
            server_default=service_provider_relay_state_prefix_default,
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    system_assignment = sql.Table(
        'system_assignment',
        meta,
        sql.Column('type', sql.String(64), nullable=False),
        sql.Column('actor_id', sql.String(64), nullable=False),
        sql.Column('target_id', sql.String(64), nullable=False),
        sql.Column('role_id', sql.String(64), nullable=False),
        sql.Column('inherited', sql.Boolean, default=False, nullable=False),
        sql.PrimaryKeyConstraint(
            'type', 'actor_id', 'target_id', 'role_id', 'inherited'
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    token = sql.Table(
        'token',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('expires', sql.DateTime, default=None),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('valid', sql.Boolean, default=True, nullable=False),
        sql.Column('trust_id', sql.String(length=64)),
        sql.Column('user_id', sql.String(length=64)),
        sql.Index('ix_token_expires', 'expires'),
        sql.Index('ix_token_expires_valid', 'expires', 'valid'),
        sql.Index('ix_token_user_id', 'user_id'),
        sql.Index('ix_token_trust_id', 'trust_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    trust = sql.Table(
        'trust',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('trustor_user_id', sql.String(length=64), nullable=False),
        sql.Column('trustee_user_id', sql.String(length=64), nullable=False),
        sql.Column('project_id', sql.String(length=64)),
        sql.Column('impersonation', sql.Boolean, nullable=False),
        sql.Column('deleted_at', sql.DateTime),
        sql.Column('expires_at', sql.DateTime),
        sql.Column('remaining_uses', sql.Integer, nullable=True),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('expires_at_int', ks_sql.DateTimeInt()),
        sql.UniqueConstraint(
            'trustor_user_id',
            'trustee_user_id',
            'project_id',
            'impersonation',
            'expires_at',
            'expires_at_int',
            name='duplicate_trust_constraint_expanded',
        ),
        sql.Column(
            'redelegated_trust_id',
            sql.String(64),
            nullable=True,
        ),
        sql.Column(
            'redelegation_count',
            sql.Integer,
            nullable=True,
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    trust_role = sql.Table(
        'trust_role',
        meta,
        sql.Column(
            'trust_id', sql.String(length=64), primary_key=True, nullable=False
        ),
        sql.Column(
            'role_id', sql.String(length=64), primary_key=True, nullable=False
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    user = sql.Table(
        'user',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('enabled', sql.Boolean),
        sql.Column('default_project_id', sql.String(length=64)),
        sql.Column('created_at', sql.DateTime(), nullable=True),
        sql.Column('last_active_at', sql.Date(), nullable=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.UniqueConstraint('id', 'domain_id', name='ixu_user_id_domain_id'),
        sql.Index('ix_default_project_id', 'default_project_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    user_group_membership = sql.Table(
        'user_group_membership',
        meta,
        sql.Column(
            'user_id',
            sql.String(length=64),
            sql.ForeignKey(
                user.c.id,
                name='fk_user_group_membership_user_id',
            ),
            primary_key=True,
        ),
        sql.Column(
            'group_id',
            sql.String(length=64),
            sql.ForeignKey(
                group.c.id,
                name='fk_user_group_membership_group_id',
            ),
            primary_key=True,
        ),
        # NOTE(stevemar): The index was named 'group_id' in
        # 050_fk_consistent_indexes.py and needs to be preserved
        sql.Index('group_id', 'group_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    user_option = sql.Table(
        'user_option',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey(user.c.id, ondelete='CASCADE'),
            nullable=False,
            primary_key=True,
        ),
        sql.Column(
            'option_id', sql.String(4), nullable=False, primary_key=True
        ),
        sql.Column('option_value', ks_sql.JsonBlob, nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    whitelisted_config = sql.Table(
        'whitelisted_config',
        meta,
        sql.Column('domain_id', sql.String(64), primary_key=True),
        sql.Column('group', sql.String(255), primary_key=True),
        sql.Column('option', sql.String(255), primary_key=True),
        sql.Column('value', ks_sql.JsonBlob.impl, nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    access_token = sql.Table(
        'access_token',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('access_secret', sql.String(64), nullable=False),
        sql.Column(
            'authorizing_user_id', sql.String(64), nullable=False, index=True
        ),
        sql.Column('project_id', sql.String(64), nullable=False),
        sql.Column('role_ids', sql.Text(), nullable=False),
        sql.Column(
            'consumer_id',
            sql.String(64),
            sql.ForeignKey(consumer.c.id),
            nullable=False,
            index=True,
        ),
        sql.Column('expires_at', sql.String(64), nullable=True),
    )

    application_credential_role = sql.Table(
        'application_credential_role',
        meta,
        sql.Column(
            'application_credential_id',
            sql.Integer,
            sql.ForeignKey(
                application_credential.c.internal_id, ondelete='CASCADE'
            ),
            primary_key=True,
            nullable=False,
        ),
        sql.Column(
            'role_id', sql.String(length=64), primary_key=True, nullable=False
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    application_credential_access_rule = sql.Table(
        'application_credential_access_rule',
        meta,
        sql.Column(
            'application_credential_id',
            sql.Integer,
            sql.ForeignKey(
                application_credential.c.internal_id, ondelete='CASCADE'
            ),
            primary_key=True,
            nullable=False,
        ),
        sql.Column(
            'access_rule_id',
            sql.Integer,
            sql.ForeignKey(access_rule.c.id, ondelete='CASCADE'),
            primary_key=True,
            nullable=False,
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    endpoint = sql.Table(
        'endpoint',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('legacy_endpoint_id', sql.String(length=64)),
        sql.Column('interface', sql.String(length=8), nullable=False),
        sql.Column(
            'service_id',
            sql.String(length=64),
            sql.ForeignKey(
                service.c.id,
                name='endpoint_service_id_fkey',
            ),
            nullable=False,
        ),
        sql.Column('url', sql.Text, nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column(
            'enabled',
            sql.Boolean,
            nullable=False,
            default=True,
            server_default='1',
        ),
        sql.Column(
            'region_id',
            sql.String(length=255),
            sql.ForeignKey(
                region.c.id,
                name='fk_endpoint_region_id',
            ),
            nullable=True,
        ),
        # NOTE(stevemar): The index was named 'service_id' in
        # 050_fk_consistent_indexes.py and needs to be preserved
        sql.Index('service_id', 'service_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    endpoint_group = sql.Table(
        'endpoint_group',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(255), nullable=False),
        sql.Column('description', sql.Text, nullable=True),
        sql.Column('filters', sql.Text(), nullable=False),
    )

    expiring_user_group_membership = sql.Table(
        'expiring_user_group_membership',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey(user.c.id),
            primary_key=True,
        ),
        sql.Column(
            'group_id',
            sql.String(64),
            sql.ForeignKey(group.c.id),
            primary_key=True,
        ),
        sql.Column(
            'idp_id',
            sql.String(64),
            sql.ForeignKey(identity_provider.c.id, ondelete='CASCADE'),
            primary_key=True,
        ),
        sql.Column('last_verified', sql.DateTime(), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    federation_protocol = sql.Table(
        'federation_protocol',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column(
            'idp_id',
            sql.String(64),
            sql.ForeignKey(identity_provider.c.id, ondelete='CASCADE'),
            primary_key=True,
        ),
        sql.Column('mapping_id', sql.String(64), nullable=False),
        sql.Column('remote_id_attribute', sql.String(64)),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    implied_role = sql.Table(
        'implied_role',
        meta,
        sql.Column(
            'prior_role_id',
            sql.String(length=64),
            sql.ForeignKey(
                role.c.id,
                name='implied_role_prior_role_id_fkey',
                ondelete='CASCADE',
            ),
            primary_key=True,
        ),
        sql.Column(
            'implied_role_id',
            sql.String(length=64),
            sql.ForeignKey(
                role.c.id,
                name='implied_role_implied_role_id_fkey',
                ondelete='CASCADE',
            ),
            primary_key=True,
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    limit = sql.Table(
        'limit',
        meta,
        sql.Column('id', sql.String(length=64), nullable=False),
        sql.Column('project_id', sql.String(64), nullable=True),
        sql.Column('resource_limit', sql.Integer, nullable=False),
        sql.Column('description', sql.Text),
        sql.Column('internal_id', sql.Integer, primary_key=True),
        # FIXME(stephenfin): This should have a foreign key constraint on
        # registered_limit.id, but sqlalchemy-migrate clearly didn't handle
        # creating a column with embedded FK info as was attempted in 048
        sql.Column(
            'registered_limit_id',
            sql.String(64),
        ),
        sql.Column('domain_id', sql.String(64), nullable=True),
        # NOTE(stephenfin): Name chosen to preserve backwards compatibility
        # with names used for primary key unique constraints
        sql.UniqueConstraint('id', name='limit_id_key'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    local_user = sql.Table(
        'local_user',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column(
            'user_id',
            sql.String(64),
            nullable=False,
            unique=True,
        ),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.Column('name', sql.String(255), nullable=False),
        sql.Column('failed_auth_count', sql.Integer, nullable=True),
        sql.Column('failed_auth_at', sql.DateTime(), nullable=True),
        sql.ForeignKeyConstraint(
            ['user_id', 'domain_id'],
            [user.c.id, user.c.domain_id],
            name='local_user_user_id_fkey',
            onupdate='CASCADE',
            ondelete='CASCADE',
        ),
        sql.UniqueConstraint('domain_id', 'name'),
    )

    nonlocal_user = sql.Table(
        'nonlocal_user',
        meta,
        sql.Column('domain_id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(255), primary_key=True),
        sql.Column(
            'user_id',
            sql.String(64),
            nullable=False,
        ),
        sql.ForeignKeyConstraint(
            ['user_id', 'domain_id'],
            [user.c.id, user.c.domain_id],
            name='nonlocal_user_user_id_fkey',
            onupdate='CASCADE',
            ondelete='CASCADE',
        ),
        sql.UniqueConstraint('user_id', name='ixu_nonlocal_user_user_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    password = sql.Table(
        'password',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column(
            'local_user_id',
            sql.Integer,
            sql.ForeignKey(local_user.c.id, ondelete='CASCADE'),
            nullable=False,
        ),
        sql.Column('expires_at', sql.DateTime(), nullable=True),
        sql.Column(
            'self_service',
            sql.Boolean,
            nullable=False,
            server_default='0',
            default=False,
        ),
        # NOTE(notmorgan): To support the full range of scrypt and pbkfd
        # password hash lengths, this should be closer to varchar(1500) instead
        # of varchar(255).
        sql.Column('password_hash', sql.String(255), nullable=True),
        sql.Column(
            'created_at_int',
            ks_sql.DateTimeInt(),
            nullable=False,
            default=0,
            server_default='0',
        ),
        sql.Column('expires_at_int', ks_sql.DateTimeInt(), nullable=True),
        sql.Column(
            'created_at',
            sql.DateTime(),
            nullable=False,
            default=datetime.datetime.utcnow,
        ),
    )

    project_endpoint_group = sql.Table(
        'project_endpoint_group',
        meta,
        sql.Column(
            'endpoint_group_id',
            sql.String(64),
            sql.ForeignKey(endpoint_group.c.id),
            nullable=False,
        ),
        sql.Column('project_id', sql.String(64), nullable=False),
        sql.PrimaryKeyConstraint('endpoint_group_id', 'project_id'),
    )

    federated_user = sql.Table(
        'federated_user',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey(user.c.id, ondelete='CASCADE'),
            nullable=False,
        ),
        sql.Column(
            'idp_id',
            sql.String(64),
            sql.ForeignKey(identity_provider.c.id, ondelete='CASCADE'),
            nullable=False,
        ),
        sql.Column('protocol_id', sql.String(64), nullable=False),
        sql.Column('unique_id', sql.String(255), nullable=False),
        sql.Column('display_name', sql.String(255), nullable=True),
        sql.ForeignKeyConstraint(
            ['protocol_id', 'idp_id'],
            [federation_protocol.c.id, federation_protocol.c.idp_id],
            name='federated_user_protocol_id_fkey',
            ondelete='CASCADE',
        ),
        sql.UniqueConstraint('idp_id', 'protocol_id', 'unique_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    # create all tables
    tables = [
        access_rule,
        application_credential,
        assignment,
        config_register,
        consumer,
        credential,
        group,
        id_mapping,
        identity_provider,
        idp_remote_ids,
        mapping,
        policy,
        policy_association,
        project,
        project_endpoint,
        project_option,
        project_tag,
        region,
        registered_limit,
        request_token,
        revocation_event,
        role,
        role_option,
        sensitive_config,
        service,
        service_provider,
        system_assignment,
        token,
        trust,
        trust_role,
        user,
        user_group_membership,
        user_option,
        whitelisted_config,

        access_token,
        application_credential_access_rule,
        application_credential_role,
        endpoint,
        endpoint_group,
        expiring_user_group_membership,
        federation_protocol,
        implied_role,
        limit,
        local_user,
        nonlocal_user,
        password,
        project_endpoint_group,

        federated_user,
    ]

    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise

    fkeys = []

    if migrate_engine.name == 'sqlite':
        # NOTE(stevemar): We need to keep this FK constraint due to 073, but
        # only for sqlite, once we collapse 073 we can remove this constraint
        fkeys.append(
            {
                'columns': [assignment.c.role_id],
                'references': [role.c.id],
                'name': 'fk_assignment_role_id',
            },
        )

    for fkey in fkeys:
        migrate.ForeignKeyConstraint(
            columns=fkey['columns'],
            refcolumns=fkey['references'],
            name=fkey.get('name'),
            ondelete=fkey.get('ondelete'),
            onupdate=fkey.get('onupdate'),
        ).create()

    # TODO(stephenfin): Remove these procedures in a future contract migration

    if migrate_engine.name == 'postgresql':
        error_message = (
            'Credential migration in progress. Cannot perform '
            'writes to credential table.'
        )
        credential_update_trigger = textwrap.dedent(f"""
        CREATE OR REPLACE FUNCTION keystone_read_only_update()
          RETURNS trigger AS
        $BODY$
        BEGIN
          IF NEW.encrypted_blob IS NULL THEN
            RAISE EXCEPTION '{error_message}';
          END IF;
          IF NEW.encrypted_blob IS NOT NULL AND OLD.blob IS NULL THEN
            RAISE EXCEPTION '{error_message}';
          END IF;
          RETURN NEW;
        END
        $BODY$ LANGUAGE plpgsql;
        """)
        migrate_engine.execute(credential_update_trigger)

        error_message = (
            'Identity provider migration in progress. Cannot '
            'insert new rows into the identity_provider table at '
            'this time.'
        )
        identity_provider_insert_trigger = textwrap.dedent(f"""
        CREATE OR REPLACE FUNCTION keystone_read_only_insert()
          RETURNS trigger AS
        $BODY$
        BEGIN
          RAISE EXCEPTION '{error_message}';
        END
        $BODY$ LANGUAGE plpgsql;
        """)
        migrate_engine.execute(identity_provider_insert_trigger)

        federated_user_insert_trigger = textwrap.dedent("""
        CREATE OR REPLACE FUNCTION update_federated_user_domain_id()
            RETURNS trigger AS
        $BODY$
        BEGIN
            UPDATE "user" SET domain_id = (
                SELECT domain_id FROM identity_provider WHERE id = NEW.idp_id)
                WHERE id = NEW.user_id and domain_id IS NULL;
            RETURN NULL;
        END
        $BODY$ LANGUAGE plpgsql;
        """)
        migrate_engine.execute(federated_user_insert_trigger)

        local_user_insert_trigger = textwrap.dedent("""
        CREATE OR REPLACE FUNCTION update_user_domain_id()
            RETURNS trigger AS
        $BODY$
        BEGIN
            UPDATE "user" SET domain_id = NEW.domain_id
                WHERE id = NEW.user_id;
            RETURN NULL;
        END
        $BODY$ LANGUAGE plpgsql;
        """)
        migrate_engine.execute(local_user_insert_trigger)

    # FIXME(stephenfin): Remove these indexes. They're left over from attempts
    # to remove foreign key constraints in past migrations. Apparently
    # sqlalchemy-migrate didn't do the job fully and left behind indexes
    if migrate_engine.name == 'mysql':
        sql.Index('region_id', registered_limit.c.region_id).create()

        # FIXME(stephenfin): This should be dropped when we add the FK
        # constraint to this column
        sql.Index('registered_limit_id', limit.c.registered_limit_id).create()

        # FIXME(stephenfin): These are leftover from when we removed a FK
        # constraint and should probable be dropped
        sql.Index('domain_id', identity_provider.c.domain_id).create()
        sql.Index('domain_id', user.c.domain_id).create()
