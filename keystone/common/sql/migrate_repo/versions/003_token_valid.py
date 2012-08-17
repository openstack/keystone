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


from migrate import *
from sqlalchemy import *


from keystone.common import sql


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind

    meta = MetaData()
    meta.bind = migrate_engine
    dialect = migrate_engine.url.get_dialect().name
    token = Table('token', meta, autoload=True)
    valid = Column("valid", Boolean(), ColumnDefault(True), nullable=False)
    token.create_column(valid)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    token = Table('token', meta, autoload=True)
    token.drop_column('valid')
