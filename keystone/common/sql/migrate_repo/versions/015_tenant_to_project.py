import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    legacy_table = sql.Table('tenant', meta, autoload=True)
    legacy_table.rename('project')
    legacy_table = sql.Table('user_tenant_membership', meta, autoload=True)
    legacy_table.rename('user_project_membership')


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    upgrade_table = sql.Table('project', meta, autoload=True)
    upgrade_table.rename('tenant')
    upgrade_table = sql.Table('user_project_membership', meta, autoload=True)
    upgrade_table.rename('user_tenant_membership')
