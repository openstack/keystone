# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from sqlalchemy import MetaData


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = MetaData()
    meta.bind = migrate_engine

    if migrate_engine.name == "mysql":
        tables = ['tenant', 'user', 'role', 'token', 'service', 'metadata',
                  'ec2_credential', 'endpoint', 'user_tenant_membership']
        sql = "SET foreign_key_checks = 0;"

        for table in tables:
            sql += "ALTER TABLE %s CONVERT TO CHARACTER SET utf8;" % table
        sql += "SET foreign_key_checks = 1;"
        sql += "ALTER DATABASE %s DEFAULT CHARACTER SET utf8;" \
            % migrate_engine.url.database
        migrate_engine.execute(sql)


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    if migrate_engine.name == "mysql":
        tables = ['tenant', 'user', 'role', 'token', 'service', 'metadata',
                  'ec2_credential', 'endpoint', 'user_tenant_membership']
        sql = "SET foreign_key_checks = 0;"

        for table in tables:
            sql += "ALTER TABLE %s CONVERT TO CHARACTER SET latin1;" % table
        sql += "SET foreign_key_checks = 1;"
        sql += "ALTER DATABASE %s DEFAULT CHARACTER SET latin1;" \
            % migrate_engine.url.database
