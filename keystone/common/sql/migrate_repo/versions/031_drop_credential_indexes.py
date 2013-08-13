# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

import sqlalchemy


def upgrade(migrate_engine):
    #This migration is relevant only for mysql because for all other
    #migrate engines these indexes were successfully dropped.
    if migrate_engine.name != 'mysql':
        return
    meta = sqlalchemy.MetaData(bind=migrate_engine)
    table = sqlalchemy.Table('credential', meta, autoload=True)
    for index in table.indexes:
        index.drop()


def downgrade(migrate_engine):
    if migrate_engine.name != 'mysql':
        return
    meta = sqlalchemy.MetaData(bind=migrate_engine)
    table = sqlalchemy.Table('credential', meta, autoload=True)
    index = sqlalchemy.Index('user_id', table.c['user_id'])
    index.create()
    index = sqlalchemy.Index('credential_project_id_fkey',
                             table.c['project_id'])
    index.create()
