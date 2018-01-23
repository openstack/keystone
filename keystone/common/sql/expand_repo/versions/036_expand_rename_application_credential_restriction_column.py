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


def upgrade(migrate_engine):

    meta = sql.MetaData()
    meta.bind = migrate_engine

    table = sql.Table(
        'application_credential', meta, autoload=True
    )
    # MySQL and PostgreSQL can handle a column rename.
    # Only Sqlite is special. Since Sqlite can't support an online upgrade
    # anyway, just brute-force the migration by copying the table.
    if migrate_engine.name == 'sqlite':
        old_table = table

        args = []
        for column in old_table.columns:
            if column.name != 'allow_application_credential_creation':
                args.append(column.copy())
        unrestricted = sql.Column('unrestricted', sql.Boolean)
        args.append(unrestricted)
        constraint = sql.UniqueConstraint('user_id', 'name',
                                          name='duplicate_app_cred_constraint')
        args.append(constraint)
        new_table = sql.Table('application_credential_temp',
                              old_table.metadata, *args)
        new_table.create(migrate_engine, checkfirst=True)
    else:
        unrestricted = sql.Column('unrestricted', sql.Boolean())
        table.create_column(unrestricted)
