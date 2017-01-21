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

from keystone.common.sql import upgrades


MYSQL_INSERT_TRIGGER = """
CREATE TRIGGER federated_user_insert_trigger
AFTER INSERT
    ON federated_user FOR EACH ROW
BEGIN
    UPDATE user SET domain_id = (
        SELECT domain_id FROM identity_provider WHERE id = NEW.idp_id)
        WHERE id = NEW.user_id and domain_id IS NULL;
END;
"""

SQLITE_INSERT_TRIGGER = """
CREATE TRIGGER federated_user_insert_trigger
AFTER INSERT
    ON federated_user
BEGIN
    UPDATE user SET domain_id = (
        SELECT domain_id FROM identity_provider WHERE id = NEW.idp_id)
        WHERE id = NEW.user_id and domain_id IS NULL;
END;
"""

POSTGRESQL_INSERT_TRIGGER = """
CREATE OR REPLACE FUNCTION update_federated_user_domain_id()
    RETURNS trigger AS
$BODY$
BEGIN
    UPDATE "user" SET domain_id = (
        SELECT domain_id FROM identity_provider WHERE id = NEW.idp_id)
        WHERE id = NEW.user_id and domain_id IS NULL;
    RETURN NULL;
END
$BODY$ LANGUAGE plpgsql;

CREATE TRIGGER federated_user_insert_trigger AFTER INSERT ON federated_user
FOR EACH ROW
EXECUTE PROCEDURE update_federated_user_domain_id();
"""


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if upgrades.USE_TRIGGERS:
        if migrate_engine.name == 'postgresql':
            insert_trigger = POSTGRESQL_INSERT_TRIGGER
        elif migrate_engine.name == 'sqlite':
            insert_trigger = SQLITE_INSERT_TRIGGER
        else:
            insert_trigger = MYSQL_INSERT_TRIGGER
        migrate_engine.execute(insert_trigger)
