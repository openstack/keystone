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

import sqlalchemy as orm


def upgrade(migrate_engine):
    meta = orm.MetaData()
    meta.bind = migrate_engine
    idp_table = orm.Table('identity_provider', meta, autoload=True)
    remote_id_table = orm.Table(
        'idp_remote_ids',
        meta,
        orm.Column('idp_id',
                   orm.String(64),
                   orm.ForeignKey('identity_provider.id',
                                  ondelete='CASCADE')),
        orm.Column('remote_id',
                   orm.String(255),
                   primary_key=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    remote_id_table.create(migrate_engine, checkfirst=True)

    select = orm.sql.select([idp_table.c.id, idp_table.c.remote_id]).where(
        idp_table.c.remote_id.isnot(None))

    for identity in migrate_engine.execute(select):
        remote_idp_entry = {'idp_id': identity.id,
                            'remote_id': identity.remote_id}
        remote_id_table.insert(remote_idp_entry).execute()

    idp_table.drop_column('remote_id')
