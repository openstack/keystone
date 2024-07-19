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

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config
from sqlalchemy import pool

from keystone.common.sql import core
from keystone.common.sql.migrations import autogen

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# interpret the config file for Python logging unless we're told not to;
# this line sets up loggers basically.
if config.attributes.get('configure_logger', True):
    fileConfig(config.config_file_name)

# keystone model MetaData object
target_metadata = core.ModelBase.metadata


def include_object(object, name, type_, reflected, compare_to):
    BORKED_COLUMNS = ()

    BORKED_UNIQUE_CONSTRAINTS = ()

    BORKED_FK_CONSTRAINTS = (
        # removed fks
        ('application_credential_access_rule', ['access_rule_id']),
        ('limit', ['registered_limit_id']),
        ('registered_limit', ['service_id']),
        ('registered_limit', ['region_id']),
        ('endpoint', ['region_id']),
        # added fks
        ('application_credential_access_rule', ['access_rule_id']),
        ('endpoint', ['region_id']),
        ('assignment', ['role_id']),
    )

    BORKED_INDEXES = (
        # removed indexes
        ('access_rule', ['external_id']),
        ('access_rule', ['user_id']),
        ('revocation_event', ['revoked_at']),
        ('system_assignment', ['actor_id']),
        ('user', ['default_project_id']),
        # added indexes
        ('access_rule', ['external_id']),
        ('access_rule', ['user_id']),
        ('access_token', ['consumer_id']),
        ('endpoint', ['service_id']),
        ('revocation_event', ['revoked_at']),
        ('user', ['default_project_id']),
        ('user_group_membership', ['group_id']),
        (
            'trust',
            [
                'trustor_user_id',
                'trustee_user_id',
                'project_id',
                'impersonation',
                'expires_at',
                'expires_at_int',
            ],
        ),
    )

    # NOTE(stephenfin): By skipping these items, we skip *all* changes to the
    # affected item. However, we only want to skip the actual things we know
    # about untl we have enough time to fix them. These issues are listed in
    # keystone.tests.unit.common.sql.test_upgrades.KeystoneModelsMigrationsSync
    # However, this isn't an issue since the test is more specific and will
    # catch other issues and anyone making changes to the columns and hoping to
    # autogenerate them would need to fix the latent issue first anyway.
    if type_ == 'column':
        return (object.table.name, name) not in BORKED_COLUMNS

    if type_ == 'unique_constraint':
        columns = [c.name for c in object.columns]
        return (object.table.name, columns) not in BORKED_UNIQUE_CONSTRAINTS

    if type_ == 'foreign_key_constraint':
        columns = [c.name for c in object.columns]
        return (object.table.name, columns) not in BORKED_FK_CONSTRAINTS

    if type_ == 'index':
        columns = [c.name for c in object.columns]
        return (object.table.name, columns) not in BORKED_INDEXES

    return True


def include_name(name, type_, parent_names):
    """Determine which tables or columns to skip.

    This is used where we have migrations that are out-of-sync with the models.
    """
    REMOVED_TABLES = ('token',)

    if type_ == 'table':
        return name not in REMOVED_TABLES

    return True


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine, though an
    Engine is acceptable here as well.  By skipping the Engine creation we
    don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        render_as_batch=True,
        include_name=include_name,
        include_object=include_object,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a connection
    with the context.

    This is modified from the default based on the below, since we want to
    share an engine when unit testing so in-memory database testing actually
    works.

    https://alembic.sqlalchemy.org/en/latest/cookbook.html#connection-sharing
    """
    connectable = config.attributes.get('connection', None)

    if connectable is None:
        # only create Engine if we don't have a Connection from the outside
        connectable = engine_from_config(
            config.get_section(config.config_ini_section),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,
                include_name=include_name,
                include_object=include_object,
                process_revision_directives=autogen.process_revision_directives,  # noqa: E501
            )

            with context.begin_transaction():
                context.run_migrations()
    else:
        context.configure(
            connection=connectable,
            target_metadata=target_metadata,
            render_as_batch=True,
            include_name=include_name,
            include_object=include_object,
            process_revision_directives=autogen.process_revision_directives,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
