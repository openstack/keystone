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

import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    application_credential_table = sql.Table(
        'application_credential', meta, autoload=True
    )
    if migrate_engine.name == 'sqlite':
        old_table = sql.Table('application_credential', meta, autoload=True)
        new_table = sql.Table('application_credential_temp', meta,
                              autoload=True)
        old_table.drop()
        new_table.rename('application_credential')
    else:
        table = application_credential_table
        # NOTE(cmurphy) because of lb#1744948, some deployments could already
        # have made it past the expand step and be stuck on the contract step.
        # If necessary, do the expand step here.
        # At this point this API is not yet exposed and there should be no data
        # in this table.
        if 'unrestricted' not in table.columns:
            unrestricted = sql.Column('unrestricted', sql.Boolean())
            table.create_column(unrestricted)
        column = table.c.allow_application_credential_creation
        column.drop()
