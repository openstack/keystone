"""
Data migration to populate users.uid with existing users.id values.
"""
# pylint: disable=C0103,R0801


import sqlalchemy


meta = sqlalchemy.MetaData()


# define the previous state of users

user = {}
user['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
    autoincrement=True)
user['uid'] = sqlalchemy.Column('uid', sqlalchemy.String(255), unique=False,
    nullable=True)
user['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
user['password'] = sqlalchemy.Column('password', sqlalchemy.String(255))
user['email'] = sqlalchemy.Column('email', sqlalchemy.String(255))
user['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
user['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
users = sqlalchemy.Table('users', meta, *user.values())


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    dusers = users.select().execute()
    for duser in dusers:
        whereclause = "`id`='%s'" % (duser.id)
        values = {'uid': str(duser.id)}

        users.update(whereclause=whereclause, values=values).execute()


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    users.update(values={'uid': None}).execute()
