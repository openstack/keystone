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

from keystone.common.sql import upgrades

import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    credential_table = sql.Table('credential', meta, autoload=True)
    credential_table.c.blob.drop()

    if upgrades.USE_TRIGGERS:
        if migrate_engine.name == 'postgresql':
            drop_credential_update_trigger = (
                'DROP TRIGGER credential_update_read_only on credential;'
            )
            drop_credential_insert_trigger = (
                'DROP TRIGGER credential_insert_read_only on credential;'
            )
        elif migrate_engine.name == 'mysql':
            drop_credential_update_trigger = (
                'DROP TRIGGER credential_update_read_only;'
            )
            drop_credential_insert_trigger = (
                'DROP TRIGGER credential_insert_read_only;'
            )
        else:
            # NOTE(lbragstad, henry-nash): Apparently sqlalchemy and sqlite
            # behave weird when using triggers, which is why we use the `IF
            # EXISTS` conditional here.  I think what is happening is that the
            # credential_table.c.blob.drop() causes sqlalchemy to create a new
            # credential table - but it doesn't copy the triggers over, which
            # causes the DROP TRIGGER statement to fail without `IF EXISTS`
            # because the trigger doesn't exist in the new table(?!).
            drop_credential_update_trigger = (
                'DROP TRIGGER IF EXISTS credential_update_read_only;'
            )
            drop_credential_insert_trigger = (
                'DROP TRIGGER IF EXISTS credential_insert_read_only;'
            )
        migrate_engine.execute(drop_credential_update_trigger)
        migrate_engine.execute(drop_credential_insert_trigger)

    # NOTE(lbragstad): We close these so that they are not nullable because
    # Newton code (and anything after) would always populate these values.
    credential_table.c.encrypted_blob.alter(nullable=False)
    credential_table.c.key_hash.alter(nullable=False)
