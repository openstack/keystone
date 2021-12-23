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


import migrate
from oslo_log import log
import sqlalchemy as sql

from keystone.assignment.backends import sql as assignment_sql
from keystone.common import sql as ks_sql
import keystone.conf
from keystone.identity.mapping_backends import mapping as mapping_backend

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

NULL_DOMAIN_ID = '<<keystone.domain.root>>'


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
            sql.ForeignKey('consumer.id'),
            nullable=False,
            index=True,
        ),
        sql.Column('expires_at', sql.String(64), nullable=True),
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
        sql.Column('blob', ks_sql.JsonBlob, nullable=False),
        sql.Column('type', sql.String(length=255), nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    endpoint = sql.Table(
        'endpoint',
        meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('legacy_endpoint_id', sql.String(length=64)),
        sql.Column('interface', sql.String(length=8), nullable=False),
        sql.Column('service_id', sql.String(length=64), nullable=False),
        sql.Column('url', sql.Text, nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column(
            'enabled',
            sql.Boolean,
            nullable=False,
            default=True,
            server_default='1',
        ),
        sql.Column('region_id', sql.String(length=255), nullable=True),
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

    federated_user = sql.Table(
        'federated_user',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey('user.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sql.Column(
            'idp_id',
            sql.String(64),
            sql.ForeignKey('identity_provider.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sql.Column('protocol_id', sql.String(64), nullable=False),
        sql.Column('unique_id', sql.String(255), nullable=False),
        sql.Column('display_name', sql.String(255), nullable=True),
        sql.UniqueConstraint('idp_id', 'protocol_id', 'unique_id'),
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
            sql.ForeignKey('identity_provider.id', ondelete='CASCADE'),
            primary_key=True,
        ),
        sql.Column('mapping_id', sql.String(64), nullable=False),
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

    identity_provider = sql.Table(
        'identity_provider',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('enabled', sql.Boolean, nullable=False),
        sql.Column('description', sql.Text(), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    idp_remote_ids = sql.Table(
        'idp_remote_ids',
        meta,
        sql.Column(
            'idp_id',
            sql.String(64),
            sql.ForeignKey('identity_provider.id', ondelete='CASCADE'),
        ),
        sql.Column('remote_id', sql.String(255), primary_key=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    implied_role = sql.Table(
        'implied_role',
        meta,
        sql.Column('prior_role_id', sql.String(length=64), primary_key=True),
        sql.Column('implied_role_id', sql.String(length=64), primary_key=True),
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
            sql.ForeignKey('user.id', ondelete='CASCADE'),
            nullable=False,
            unique=True,
        ),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.Column('name', sql.String(255), nullable=False),
        sql.Column('failed_auth_count', sql.Integer, nullable=True),
        sql.Column('failed_auth_at', sql.DateTime(), nullable=True),
        sql.UniqueConstraint('domain_id', 'name'),
    )

    mapping = sql.Table(
        'mapping',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('rules', sql.Text(), nullable=False),
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
        sql.Column('password', sql.String(128), nullable=True),
        sql.Column('created_at', sql.DateTime(), nullable=True),
        sql.Column('expires_at', sql.DateTime(), nullable=True),
        sql.Column(
            'self_service',
            sql.Boolean,
            nullable=False,
            server_default='0',
            default=False,
        ),
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
        sql.Column('domain_id', sql.String(length=64), nullable=False),
        sql.Column('parent_id', sql.String(64), nullable=True),
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

    project_endpoint_group = sql.Table(
        'project_endpoint_group',
        meta,
        sql.Column(
            'endpoint_group_id',
            sql.String(64),
            sql.ForeignKey('endpoint_group.id'),
            nullable=False,
        ),
        sql.Column('project_id', sql.String(64), nullable=False),
        sql.PrimaryKeyConstraint('endpoint_group_id', 'project_id'),
    )

    config_register = sql.Table(
        'config_register',
        meta,
        sql.Column('type', sql.String(64), primary_key=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
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
            sql.ForeignKey('consumer.id'),
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
        migrate.UniqueConstraint(
            'name',
            'domain_id',
            name='ixu_role_name_domain_id',
        ),
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
            server_default=CONF.saml.relay_state_prefix,
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
        sql.Index(
            'ix_token_expires_valid', 'expires', 'valid'
        ),
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
        sql.UniqueConstraint(
            'trustor_user_id',
            'trustee_user_id',
            'project_id',
            'impersonation',
            'expires_at',
            name='duplicate_trust_constraint',
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
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    nonlocal_user = sql.Table(
        'nonlocal_user',
        meta,
        sql.Column('domain_id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(255), primary_key=True),
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey(user.c.id, ondelete='CASCADE'),
            nullable=False,
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    user_group_membership = sql.Table(
        'user_group_membership',
        meta,
        sql.Column('user_id', sql.String(length=64), primary_key=True),
        sql.Column('group_id', sql.String(length=64), primary_key=True),
        # NOTE(stevemar): The index was named 'group_id' in
        # 050_fk_consistent_indexes.py and needs to be preserved
        sql.Index('group_id', 'group_id'),
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

    # create all tables
    tables = [
        credential,
        endpoint,
        group,
        policy,
        project,
        role,
        service,
        token,
        trust,
        trust_role,
        user,
        user_group_membership,
        region,
        assignment,
        id_mapping,
        whitelisted_config,
        sensitive_config,
        config_register,
        policy_association,
        identity_provider,
        federation_protocol,
        mapping,
        service_provider,
        idp_remote_ids,
        consumer,
        request_token,
        access_token,
        revocation_event,
        project_endpoint,
        endpoint_group,
        project_endpoint_group,
        implied_role,
        local_user,
        password,
        federated_user,
        nonlocal_user,
    ]

    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise

    fkeys = [
        {
            'columns': [endpoint.c.service_id],
            'references': [service.c.id],
        },
        {
            'columns': [user_group_membership.c.group_id],
            'references': [group.c.id],
            'name': 'fk_user_group_membership_group_id',
        },
        {
            'columns': [user_group_membership.c.user_id],
            'references': [user.c.id],
            'name': 'fk_user_group_membership_user_id',
        },
        {
            'columns': [project.c.domain_id],
            'references': [project.c.id],
        },
        {
            'columns': [endpoint.c.region_id],
            'references': [region.c.id],
            'name': 'fk_endpoint_region_id',
        },
        {
            'columns': [project.c.parent_id],
            'references': [project.c.id],
            'name': 'project_parent_id_fkey',
        },
        {
            'columns': [implied_role.c.prior_role_id],
            'references': [role.c.id],
            'ondelete': 'CASCADE',
        },
        {
            'columns': [implied_role.c.implied_role_id],
            'references': [role.c.id],
            'ondelete': 'CASCADE',
        },
        {
            'columns': [
                federated_user.c.protocol_id,
                federated_user.c.idp_id,
            ],
            'references': [
                federation_protocol.c.id,
                federation_protocol.c.idp_id,
            ],
        },
    ]

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
        ).create()

    # data generation

    def _generate_root_domain_project():
        # Generate a project that will act as a root for all domains, in order
        # for use to be able to use a FK constraint on domain_id. Projects
        # acting as a domain will not reference this as their parent_id, just
        # as domain_id.
        #
        # This special project is filtered out by the driver, so is never
        # visible to the manager or API.

        project_ref = {
            'id': NULL_DOMAIN_ID,
            'name': NULL_DOMAIN_ID,
            'enabled': False,
            'description': '',
            'domain_id': NULL_DOMAIN_ID,
            'is_domain': True,
            'parent_id': None,
            'extra': '{}',
        }
        return project_ref

    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    root_domain_project = _generate_root_domain_project()
    new_entry = project.insert().values(**root_domain_project)
    session.execute(new_entry)
    session.commit()

    session.close()
