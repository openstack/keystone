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

import sqlalchemy as sql

from keystone.credential.providers import fernet as credential_fernet


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    credential_table = sql.Table('credential', meta, autoload=True)
    credentials = list(credential_table.select().execute())

    for credential in credentials:
        crypto, keys = credential_fernet.get_multi_fernet_keys()
        primary_key_hash = credential_fernet.primary_key_hash(keys)
        encrypted_blob = crypto.encrypt(credential['blob'].encode('utf-8'))
        values = {
            'encrypted_blob': encrypted_blob,
            'key_hash': primary_key_hash
        }
        update = credential_table.update().where(
            credential_table.c.id == credential.id
        ).values(values)
        session.execute(update)
        session.commit()
    session.close()
