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

    # You can specify primary keys when creating tables, however adding
    # auto-increment integer primary keys for existing tables is not
    # cross-engine compatibility supported. Thus, the approach is to:
    # (1) create a new revocation_event table with an int pkey,
    # (2) migrate data from the old table to the new table,
    # (3) delete the old revocation_event table
    # (4) rename the new revocation_event table
    revocation_table = sql.Table('revocation_event', meta, autoload=True)

    revocation_table_new = sql.Table(
        'revocation_event_new',
        meta,
        sql.Column('id', sql.Integer, primary_key=True),
        sql.Column('domain_id', sql.String(64)),
        sql.Column('project_id', sql.String(64)),
        sql.Column('user_id', sql.String(64)),
        sql.Column('role_id', sql.String(64)),
        sql.Column('trust_id', sql.String(64)),
        sql.Column('consumer_id', sql.String(64)),
        sql.Column('access_token_id', sql.String(64)),
        sql.Column('issued_before', sql.DateTime(), nullable=False),
        sql.Column('expires_at', sql.DateTime()),
        sql.Column('revoked_at', sql.DateTime(), index=True, nullable=False),
        sql.Column('audit_id', sql.String(32), nullable=True),
        sql.Column('audit_chain_id', sql.String(32), nullable=True))
    revocation_table_new.create(migrate_engine, checkfirst=True)

    revocation_table_new.insert().from_select(['domain_id',
                                               'project_id',
                                               'user_id',
                                               'role_id',
                                               'trust_id',
                                               'consumer_id',
                                               'access_token_id',
                                               'issued_before',
                                               'expires_at',
                                               'revoked_at',
                                               'audit_id',
                                               'audit_chain_id'],
                                              revocation_table.select())

    revocation_table.drop()
    revocation_table_new.rename('revocation_event')
