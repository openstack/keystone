import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker


def upgrade_with_rename(meta, migrate_engine):
    legacy_table = sql.Table('tenant', meta, autoload=True)
    legacy_table.rename('project')
    legacy_table = sql.Table('user_tenant_membership', meta, autoload=True)
    legacy_table.rename('user_project_membership')


def downgrade_with_rename(meta, migrate_engine):
    upgrade_table = sql.Table('project', meta, autoload=True)
    upgrade_table.rename('tenant')
    upgrade_table = sql.Table('user_project_membership', meta, autoload=True)
    upgrade_table.rename('user_tenant_membership')


def upgrade_with_copy(meta, migrate_engine):
    legacy_table = sql.Table('user', meta, autoload=True)
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
    for membership in session.query(user_tenant_membership_table):
        insert.execute(membership)

    session.commit()
    session.close()

    user_tenant_membership_table.drop()
    tenant_table.drop()


def downgrade_with_copy(meta, migrate_engine):
    legacy_table = sql.Table('user', meta, autoload=True)
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
