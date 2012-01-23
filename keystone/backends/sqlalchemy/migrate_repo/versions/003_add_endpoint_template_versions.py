"""
Adds support for versioning endpoint templates
"""
# pylint: disable=C0103,R0801


import sqlalchemy
import migrate


meta = sqlalchemy.MetaData()

endpoint_template = {}
endpoint_template['id'] = sqlalchemy.Column('id', sqlalchemy.Integer,
        primary_key=True)
endpoint_template['region'] = sqlalchemy.Column('region',
        sqlalchemy.String(255))
endpoint_template['service_id'] = sqlalchemy.Column('service_id',
        sqlalchemy.Integer)
endpoint_template['public_url'] = sqlalchemy.Column('public_url',
        sqlalchemy.String(2000))
endpoint_template['admin_url'] = sqlalchemy.Column('admin_url',
        sqlalchemy.String(2000))
endpoint_template['internal_url'] = sqlalchemy.Column('internal_url',
        sqlalchemy.String(2000))
endpoint_template['enabled'] = sqlalchemy.Column('enabled',
        sqlalchemy.Boolean)
endpoint_template['is_global'] = sqlalchemy.Column('is_global',
        sqlalchemy.Boolean)
endpoint_templates = sqlalchemy.Table('endpoint_templates', meta,
        *endpoint_template.values())

version_id = sqlalchemy.Column('version_id', sqlalchemy.String(20),
        nullable=True)
version_list = sqlalchemy.Column('version_list', sqlalchemy.String(2000),
        nullable=True)
version_info = sqlalchemy.Column('version_info', sqlalchemy.String(500),
        nullable=True)


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.create_column(version_id, endpoint_templates)
    assert endpoint_templates.c.version_id is version_id

    migrate.create_column(version_list, endpoint_templates)
    assert endpoint_templates.c.version_list is version_list

    migrate.create_column(version_info, endpoint_templates)
    assert endpoint_templates.c.version_info is version_info


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.drop_column(version_id, endpoint_templates)
    assert not hasattr(endpoint_templates.c, 'version_id')

    migrate.drop_column(version_list, endpoint_templates)
    assert not hasattr(endpoint_templates.c, 'version_list')

    migrate.drop_column(version_info, endpoint_templates)
    assert not hasattr(endpoint_templates.c, 'version_info')
