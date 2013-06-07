import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker

from keystone.common.sql import migration_helpers


def rename_with_constraints(meta, legacy_project_table_name,
                            new_project_table_name,
                            legacy_user_project_membership_table_name,
                            new_user_project_membership_table_name):
    # Not all RDBMSs support renaming a table that has foreign key constraints
    # on it, so drop FK constraints before renaming and then replace FKs
    # afterwards.

    credential_table = sql.Table('credential', meta, autoload=True)
    group_project_meta_table = sql.Table('group_project_metadata', meta,
                                         autoload=True)
    project_table = sql.Table(legacy_project_table_name, meta, autoload=True)
    user_project_membership_table = sql.Table(
        legacy_user_project_membership_table_name, meta, autoload=True)
    user_table = sql.Table('user', meta, autoload=True)

    constraints = [{'table': credential_table,
                    'fk_column': 'project_id',
                    'ref_column': project_table.c.id},
                   {'table': group_project_meta_table,
                    'fk_column': 'project_id',
                    'ref_column': project_table.c.id},
                   {'table': user_project_membership_table,
                    'fk_column': 'tenant_id',
                    'ref_column': project_table.c.id},
                   {'table': user_project_membership_table,
                    'fk_column': 'user_id',
                    'ref_column': user_table.c.id}]

    renames = {
        new_project_table_name: project_table,
        new_user_project_membership_table_name: user_project_membership_table}

    migration_helpers.rename_tables_with_constraints(renames, constraints,
                                                     meta.bind)


def upgrade_with_rename(meta, migrate_engine):
    legacy_project_table_name = 'tenant'
    new_project_table_name = 'project'
    legacy_user_project_membership_table_name = 'user_tenant_membership'
    new_user_project_membership_table_name = 'user_project_membership'
    rename_with_constraints(meta, legacy_project_table_name,
                            new_project_table_name,
                            legacy_user_project_membership_table_name,
                            new_user_project_membership_table_name)


def downgrade_with_rename(meta, migrate_engine):
    legacy_project_table_name = 'project'
    new_project_table_name = 'tenant'
    legacy_user_project_membership_table_name = 'user_project_membership'
    new_user_project_membership_table_name = 'user_tenant_membership'
    rename_with_constraints(meta, legacy_project_table_name,
                            new_project_table_name,
                            legacy_user_project_membership_table_name,
                            new_user_project_membership_table_name)


def upgrade_with_copy(meta, migrate_engine):
    sql.Table('user', meta, autoload=True)
    project_table = sql.Table(
        'project',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column('description', sql.Text(), nullable=True),
        sql.Column('enabled', sql.types.Boolean, default=True))
    project_table.create(migrate_engine, checkfirst=True)

    user_project_membership_table = sql.Table(
        'user_project_membership',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey('user.id'),
            primary_key=True),
        sql.Column(
            'tenant_id',
            sql.String(64),
            sql.ForeignKey('project.id'),
            primary_key=True))
    user_project_membership_table.create(migrate_engine, checkfirst=True)

    session = sessionmaker(bind=migrate_engine)()

    tenant_table = sql.Table('tenant', meta, autoload=True)
    insert = project_table.insert()
    for tenant in session.query(tenant_table):
        insert.execute({'id': tenant.id,
                        'name': tenant.name,
                        'extra': tenant.extra,
                        'description': tenant.description,
                        'enabled': tenant.enabled})

    user_tenant_membership_table = sql.Table('user_tenant_membership',
                                             meta,
                                             autoload=True)
    insert = user_project_membership_table.insert()
    for user_id, tenant_id in session.query(user_tenant_membership_table):
        insert.execute({'user_id': user_id, 'tenant_id': tenant_id})

    session.commit()
    session.close()

    user_tenant_membership_table.drop()
    tenant_table.drop()


def downgrade_with_copy(meta, migrate_engine):
    sql.Table('user', meta, autoload=True)
    tenant_table = sql.Table(
        'tenant',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column('description', sql.Text(), nullable=True),
        sql.Column('enabled', sql.types.Boolean))
    tenant_table.create(migrate_engine, checkfirst=True)

    user_tenant_membership_table = sql.Table(
        'user_tenant_membership',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey('user.id'),
            primary_key=True),
        sql.Column(
            'tenant_id',
            sql.String(64),
            sql.ForeignKey('tenant.id'),
            primary_key=True))
    user_tenant_membership_table.create(migrate_engine, checkfirst=True)

    session = sessionmaker(bind=migrate_engine)()

    project_table = sql.Table('project', meta, autoload=True)
    insert = tenant_table.insert()
    for project in session.query(project_table):
        insert.values(project).execute()
    project_table.drop()

    user_project_membership_table = sql.Table('user_project_membership',
                                              meta,
                                              autoload=True)
    insert = user_tenant_membership_table.insert()
    for membership in session.query(user_project_membership_table):
        insert.execute(membership)
    user_project_membership_table.drop()

    session.commit()
    session.close()


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    if migrate_engine.name == "sqlite":
        upgrade_with_copy(meta, migrate_engine)
    else:
        upgrade_with_rename(meta, migrate_engine)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    if migrate_engine.name == "sqlite":
        downgrade_with_copy(meta, migrate_engine)
    else:
        downgrade_with_rename(meta, migrate_engine)
