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
import string

from sqlalchemy import Column, MetaData, String, Table, Text, types
from sqlalchemy.orm import sessionmaker


#this won't work on sqlite.  It doesn't support dropping columns
def downgrade_user_table(meta, migrate_engine):
    user_table = Table('user', meta, autoload=True)
    user_table.columns["password"].drop()
    user_table.columns["enabled"].drop()


def downgrade_tenant_table(meta, migrate_engine):
    tenant_table = Table('tenant', meta, autoload=True)
    tenant_table.columns["description"].drop()
    tenant_table.columns["enabled"].drop()


def upgrade_user_table(meta, migrate_engine):
    user_table = Table('user', meta, autoload=True)
    user_table.create_column(Column("password", String(128)))
    user_table.create_column(Column("enabled", types.Boolean,
                                    default=True))


def upgrade_tenant_table(meta, migrate_engine):
    tenant_table = Table('tenant', meta, autoload=True)
    tenant_table.create_column(Column("description", Text()))
    tenant_table.create_column(Column("enabled", types.Boolean))


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
