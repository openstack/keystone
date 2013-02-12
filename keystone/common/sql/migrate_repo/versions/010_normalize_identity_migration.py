# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
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

import json

from sqlalchemy import MetaData, Table
from sqlalchemy.orm import sessionmaker


DISABLED_VALUES = ['false', 'disabled', 'no', '0']


def is_enabled(enabled):
    # no explicit value means enabled
    if enabled is True or enabled is None:
        return True
    if isinstance(enabled, basestring) and enabled.lower() in DISABLED_VALUES:
        return False
    return bool(enabled)


def downgrade_user_table(meta, migrate_engine, session):
    user_table = Table('user', meta, autoload=True)
    for user in session.query(user_table).all():
        extra = json.loads(user.extra)
        extra['password'] = user.password
        extra['enabled'] = '%r' % user.enabled
        values = {'extra': json.dumps(extra)}
        update = user_table.update().\
            where(user_table.c.id == user.id).\
            values(values)
        migrate_engine.execute(update)


def downgrade_tenant_table(meta, migrate_engine, session):
    tenant_table = Table('tenant', meta, autoload=True)
    for tenant in session.query(tenant_table).all():
        extra = json.loads(tenant.extra)
        extra['description'] = tenant.description
        extra['enabled'] = '%r' % tenant.enabled
        values = {'extra': json.dumps(extra)}
        update = tenant_table.update().\
            where(tenant_table.c.id == tenant.id).\
            values(values)
        migrate_engine.execute(update)


def upgrade_user_table(meta, migrate_engine, session):
    user_table = Table('user', meta, autoload=True)
    for user in session.query(user_table).all():
        extra = json.loads(user.extra)
        values = {'password': extra.pop('password', None),
                  'enabled': extra.pop('enabled', True),
                  'extra': json.dumps(extra)}
        update = user_table.update().\
            where(user_table.c.id == user.id).\
            values(values)
        migrate_engine.execute(update)


def upgrade_tenant_table(meta, migrate_engine, session):
    tenant_table = Table('tenant', meta, autoload=True)
    for tenant in session.query(tenant_table):
        extra = json.loads(tenant.extra)
        values = {'description': extra.pop('description', None),
                  'enabled': extra.pop('enabled', True),
                  'extra': json.dumps(extra)}
        update = tenant_table.update().\
            where(tenant_table.c.id == tenant.id).\
            values(values)
        migrate_engine.execute(update)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    session = sessionmaker(bind=migrate_engine)()
    upgrade_user_table(meta, migrate_engine, session)
    upgrade_tenant_table(meta, migrate_engine, session)
    session.commit()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    session = sessionmaker(bind=migrate_engine)()
    downgrade_user_table(meta, migrate_engine, session)
    downgrade_tenant_table(meta, migrate_engine, session)
    session.commit()
