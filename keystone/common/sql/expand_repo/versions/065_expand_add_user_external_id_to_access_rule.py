# Copyright 2019 SUSE Linux GmbH
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

import migrate
import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    access_rule = sql.Table('access_rule', meta, autoload=True)

    external_id = sql.Column('external_id', sql.String(64))
    access_rule.create_column(external_id)
    sql.Index('external_id', access_rule.c.external_id).create()
    unique_constraint_id = migrate.UniqueConstraint('external_id',
                                                    table=access_rule)
    unique_constraint_id.create()

    user_id = sql.Column('user_id', sql.String(64))
    access_rule.create_column(user_id)
    sql.Index('user_id', access_rule.c.user_id).create()
    unique_constraint_rule_for_user = migrate.UniqueConstraint(
        'user_id', 'service', 'path', 'method',
        name='duplicate_access_rule_for_user_constraint',
        table=access_rule)
    unique_constraint_rule_for_user.create()
