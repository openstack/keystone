# pylint: disable=C0103,R0801


import sqlalchemy


meta = sqlalchemy.MetaData()


# services

service = {}
service['id'] = sqlalchemy.Column('id', sqlalchemy.Integer,
        primary_key=True, autoincrement=True)
service['name'] = sqlalchemy.Column('name', sqlalchemy.String(255),
        unique=True)
service['type'] = sqlalchemy.Column('type', sqlalchemy.String(255))
service['desc'] = sqlalchemy.Column('desc', sqlalchemy.String(255))
services = sqlalchemy.Table('services', meta, *service.values())

sqlalchemy.UniqueConstraint(service['name'])


# roles

role = {}
role['id'] = sqlalchemy.Column('id', sqlalchemy.Integer,
        primary_key=True, autoincrement=True)
role['name'] = sqlalchemy.Column('name', sqlalchemy.String(255))
role['desc'] = sqlalchemy.Column('desc', sqlalchemy.String(255))
role['service_id'] = sqlalchemy.Column('service_id', sqlalchemy.Integer)
roles = sqlalchemy.Table('roles', meta, *role.values())

sqlalchemy.UniqueConstraint(role['name'], role['service_id'])

sqlalchemy.ForeignKeyConstraint(
        [role['service_id']],
        [service['id']])


# tenants

tenant = {}
tenant['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
        autoincrement=True)
tenant['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
tenant['desc'] = sqlalchemy.Column('desc', sqlalchemy.String(255))
tenant['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
tenants = sqlalchemy.Table('tenants', meta, *tenant.values())

sqlalchemy.UniqueConstraint(tenant['name'])


# users

user = {}
user['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
        autoincrement=True)
user['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
user['password'] = sqlalchemy.Column('password', sqlalchemy.String(255))
user['email'] = sqlalchemy.Column('email', sqlalchemy.String(255))
user['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
user['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
users = sqlalchemy.Table('users', meta, *user.values())

sqlalchemy.UniqueConstraint(user['name'])

sqlalchemy.ForeignKeyConstraint(
        [user['tenant_id']],
        [tenant['id']])


# credentials

credential = {}
credential['id'] = sqlalchemy.Column('id', sqlalchemy.Integer,
        primary_key=True, autoincrement=True)
credential['user_id'] = sqlalchemy.Column('user_id', sqlalchemy.Integer)
credential['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer,
        nullable=True)
credential['type'] = sqlalchemy.Column('type', sqlalchemy.String(20))
credential['key'] = sqlalchemy.Column('key', sqlalchemy.String(255))
credential['secret'] = sqlalchemy.Column('secret', sqlalchemy.String(255))
credentials = sqlalchemy.Table('credentials', meta, *credential.values())

sqlalchemy.ForeignKeyConstraint(
        [credential['user_id']],
        [user['id']])
sqlalchemy.ForeignKeyConstraint(
        [credential['tenant_id']],
        [tenant['id']])


# tokens

token = {}
token['id'] = sqlalchemy.Column('id', sqlalchemy.String(255), primary_key=True,
        unique=True)
token['user_id'] = sqlalchemy.Column('user_id', sqlalchemy.Integer)
token['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
token['expires'] = sqlalchemy.Column('expires', sqlalchemy.DateTime)
tokens = sqlalchemy.Table('token', meta, *token.values())


# endpoint_templates

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

sqlalchemy.ForeignKeyConstraint(
        [endpoint_template['service_id']], [service['id']])


# endpoints

endpoint = {}
endpoint['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True)
endpoint['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
endpoint['endpoint_template_id'] = sqlalchemy.Column('endpoint_template_id',
        sqlalchemy.Integer)
endpoints = sqlalchemy.Table('endpoints', meta, *endpoint.values())

sqlalchemy.UniqueConstraint(
        endpoint['endpoint_template_id'], endpoint['tenant_id'])

sqlalchemy.ForeignKeyConstraint(
        [endpoint['endpoint_template_id']],
        [endpoint_template['id']])


# user_roles

user_role = {}
user_role['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True)
user_role['user_id'] = sqlalchemy.Column('user_id', sqlalchemy.Integer)
user_role['role_id'] = sqlalchemy.Column('role_id', sqlalchemy.Integer)
user_role['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
user_roles = sqlalchemy.Table('user_roles', meta, *user_role.values())

sqlalchemy.UniqueConstraint(
        user_role['user_id'], user_role['role_id'], user_role['tenant_id'])

sqlalchemy.ForeignKeyConstraint(
        [user_role['user_id']],
        [user['id']])
sqlalchemy.ForeignKeyConstraint(
        [user_role['role_id']],
        [role['id']])
sqlalchemy.ForeignKeyConstraint(
        [user_role['tenant_id']],
        [tenant['id']])


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    user_roles.create()
    endpoints.create()
    roles.create()
    services.create()
    tenants.create()
    users.create()
    credentials.create()
    tokens.create()
    endpoint_templates.create()


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    user_roles.drop()
    endpoints.drop()
    roles.drop()
    services.drop()
    tenants.drop()
    users.drop()
    credentials.drop()
    tokens.drop()
    endpoint_templates.drop()
