# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from sqlalchemy import Column, MetaData, String, Table


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    token = Table('token', meta, autoload=True)
    old_id_col = token.c.id
    old_id_col.alter(name='id_hash')
    # Note: We obtain a new metadata reference to avoid
    # sqlalchemy.exc.ArgumentError:
    # Trying to redefine primary-key column 'id' as a non-primary-key...
    meta = MetaData()
    meta.bind = migrate_engine
    token = Table('token', meta, autoload=True)
    new_id = Column("id", String(2048))
    token.create_column(new_id)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    token = Table('token', meta, autoload=True)
    token.drop_column('id')
    token = Table('token', meta, autoload=True)
    id_col = token.c.id_hash
    id_col.alter(name='id')
