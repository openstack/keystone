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

import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    request_token_table = sql.Table('request_token', meta, autoload=True)
    request_token_table.c.requested_roles.alter(nullable=True)
    request_token_table.c.requested_roles.alter(name="role_ids")
    access_token_table = sql.Table('access_token', meta, autoload=True)
    access_token_table.c.requested_roles.alter(name="role_ids")
