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

disabled_values = ['false', 'disabled', 'no', '0']


def is_enabled(enabled):
    #no explicit value means enabled
    if enabled is None:
        return 1
    if enabled is str:
        if str(enabled).lower() in disabled_values:
            return 0
    if enabled:
        return 1
    else:
        return 0


def downgrade_user_table(meta, migrate_engine):
    user_table = Table('user', meta, autoload=True)
    maker = sessionmaker(bind=migrate_engine)
    session = maker()
    user_data = []
    for a_user in session.query(user_table):
        id, name, extra, password, enabled = a_user
        extra_parsed = json.loads(extra)
        extra_parsed['password'] = password
        extra_parsed['enabled'] = "%r" % enabled
        user_data.append((password,
                          json.dumps(extra_parsed),
                          is_enabled(enabled), id))
    for user in user_data:
        session.execute("update user "
                        "set extra = '%s' "
                        "where id = '%s'" %
                        user)

    session.commit()


def downgrade_tenant_table(meta, migrate_engine):
    tenant_table = Table('tenant', meta, autoload=True)
    maker = sessionmaker(bind=migrate_engine)
    session = maker()
    tenant_data = []
    for a_tenant in session.query(tenant_table):
        id, name, extra, password, enabled = a_tenant
        extra_parsed = json.loads(extra)
        extra_parsed['description'] = description
        extra_parsed['enabled'] = "%r" % enabled
        tenant_data.append((password,
                            json.dumps(extra_parsed),
                            is_enabled(enabled), id))
    for tenant in tenant_data:
        session.execute("update tenant "
                        "set extra = '%s' "
                        "where id = '%s'" %
                        tenant)

    session.commit()


def upgrade_user_table(meta, migrate_engine):
    user_table = Table('user', meta, autoload=True)
    maker = sessionmaker(bind=migrate_engine)
    session = maker()

    new_user_data = []
    for a_user in session.query(user_table):
        id, name, extra, password, enabled = a_user
        extra_parsed = json.loads(extra)
        if 'password' in extra_parsed:
            password = extra_parsed['password']
            extra_parsed.pop('password')
        if 'enabled' in extra_parsed:
            enabled = extra_parsed['enabled']
            extra_parsed.pop('enabled')
        new_user_data.append((password,
                              json.dumps(extra_parsed),
                              is_enabled(enabled), id))
    for new_user in new_user_data:
        session.execute("update user "
                        "set password = '%s', extra = '%s', enabled = '%s' "
                        "where id = '%s'" %
                        new_user)
    session.commit()


def upgrade_tenant_table(meta, migrate_engine):
    tenant_table = Table('tenant', meta, autoload=True)

    maker = sessionmaker(bind=migrate_engine)
    session = maker()
    new_tenant_data = []
    for a_tenant in session.query(tenant_table):
        id, name, extra, description, enabled = a_tenant
        extra_parsed = json.loads(extra)
        if 'description' in extra_parsed:
            description = extra_parsed['description']
            extra_parsed.pop('description')
        if 'enabled' in extra_parsed:
            enabled = extra_parsed['enabled']
            extra_parsed.pop('enabled')
        new_tenant_data.append((description,
                                json.dumps(extra_parsed),
                                is_enabled(enabled), id))
    for new_tenant in new_tenant_data:
        session.execute("update tenant "
                        "set description = '%s', extra = '%s', enabled = '%s' "
                        "where id = '%s'" %
                        new_tenant)
    session.commit()


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    upgrade_user_table(meta, migrate_engine)
    upgrade_tenant_table(meta, migrate_engine)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    downgrade_user_table(meta, migrate_engine)
    downgrade_tenant_table(meta, migrate_engine)
