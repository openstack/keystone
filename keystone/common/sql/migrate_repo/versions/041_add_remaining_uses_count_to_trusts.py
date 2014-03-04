# Copyright (c) 2014 Matthieu Huin <mhu@enovance.com>
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


def downgrade_trust_table_with_column_drop(meta, migrate_engine):
    trust_table = sqlalchemy.Table('trust', meta, autoload=True)
    # delete trusts with a limited use count, we are downgrading so uses
    # will not be tracked anymore.
    d = trust_table.delete(trust_table.c.remaining_uses >= 0)
    d.execute()
    trust_table.drop_column('remaining_uses')


def upgrade_trust_table(meta, migrate_engine):

    trust_table = sqlalchemy.Table('trust', meta, autoload=True)
    trust_table.create_column(sqlalchemy.Column('remaining_uses',
                              sqlalchemy.Integer(),
                              nullable=True))


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    upgrade_trust_table(meta, migrate_engine)


def downgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    downgrade_trust_table_with_column_drop(meta, migrate_engine)
