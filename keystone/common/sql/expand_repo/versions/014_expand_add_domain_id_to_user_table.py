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

# define the local_user triggers for insert and update
MYSQL_LOCAL_USER_INSERT_TRIGGER = """
CREATE TRIGGER local_user_after_insert_trigger
AFTER INSERT
    ON local_user FOR EACH ROW
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id IS NULL;
END;
"""

MYSQL_LOCAL_USER_UPDATE_TRIGGER = """
CREATE TRIGGER local_user_after_update_trigger
AFTER UPDATE
    ON local_user FOR EACH ROW
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id <> NEW.domain_id;
END;
"""

SQLITE_LOCAL_USER_INSERT_TRIGGER = """
CREATE TRIGGER local_user_after_insert_trigger
AFTER INSERT
    ON local_user
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id IS NULL;
END;
"""

SQLITE_LOCAL_USER_UPDATE_TRIGGER = """
CREATE TRIGGER local_user_after_update_trigger
AFTER UPDATE
    ON local_user
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id <> NEW.domain_id;
END;
"""

POSTGRESQL_LOCAL_USER_INSERT_TRIGGER = """
CREATE OR REPLACE FUNCTION update_user_domain_id()
    RETURNS trigger AS
$BODY$
BEGIN
    UPDATE "user" SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id;
    RETURN NULL;
END
$BODY$ LANGUAGE plpgsql;

CREATE TRIGGER local_user_after_insert_trigger AFTER INSERT ON local_user
FOR EACH ROW
EXECUTE PROCEDURE update_user_domain_id();
"""

POSTGRESQL_LOCAL_USER_UPDATE_TRIGGER = """
CREATE TRIGGER local_user_after_update_trigger AFTER UPDATE ON local_user
FOR EACH ROW
EXECUTE PROCEDURE update_user_domain_id();
"""

MYSQL_NONLOCAL_USER_INSERT_TRIGGER = """
CREATE TRIGGER nonlocal_user_after_insert_trigger
AFTER INSERT
    ON nonlocal_user FOR EACH ROW
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id IS NULL;
END;
"""

# define the nonlocal_user triggers for insert and update
MYSQL_NONLOCAL_USER_UPDATE_TRIGGER = """
CREATE TRIGGER nonlocal_user_after_update_trigger
AFTER UPDATE
    ON nonlocal_user FOR EACH ROW
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id <> NEW.domain_id;
END;
"""

SQLITE_NONLOCAL_USER_INSERT_TRIGGER = """
CREATE TRIGGER nonlocal_user_after_insert_trigger
AFTER INSERT
    ON nonlocal_user
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id IS NULL;
END;
"""

SQLITE_NONLOCAL_USER_UPDATE_TRIGGER = """
CREATE TRIGGER nonlocal_user_after_update_trigger
AFTER UPDATE
    ON nonlocal_user
BEGIN
    UPDATE user SET domain_id = NEW.domain_id
        WHERE id = NEW.user_id and domain_id <> NEW.domain_id;
END;
"""

POSTGRESQL_NONLOCAL_USER_INSERT_TRIGGER = """
CREATE TRIGGER nonlocal_user_after_insert_trigger AFTER INSERT ON nonlocal_user
FOR EACH ROW
EXECUTE PROCEDURE update_user_domain_id();
"""

POSTGRESQL_NONLOCAL_USER_UPDATE_TRIGGER = """
CREATE TRIGGER nonlocal_user_after_update_trigger AFTER UPDATE ON nonlocal_user
FOR EACH ROW
EXECUTE PROCEDURE update_user_domain_id();
"""


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user = sql.Table('user', meta, autoload=True)
    project = sql.Table('project', meta, autoload=True)
    domain_id = sql.Column('domain_id', sql.String(64),
                           sql.ForeignKey(project.c.id), nullable=True)
    user.create_column(domain_id)

    if upgrades.USE_TRIGGERS:
        if migrate_engine.name == 'postgresql':
            local_user_insert_trigger = POSTGRESQL_LOCAL_USER_INSERT_TRIGGER
            local_user_update_trigger = POSTGRESQL_LOCAL_USER_UPDATE_TRIGGER
            nonlocal_user_insert_trigger = (
                POSTGRESQL_NONLOCAL_USER_INSERT_TRIGGER)
            nonlocal_user_update_trigger = (
                POSTGRESQL_NONLOCAL_USER_UPDATE_TRIGGER)
        elif migrate_engine.name == 'sqlite':
            local_user_insert_trigger = SQLITE_LOCAL_USER_INSERT_TRIGGER
            local_user_update_trigger = SQLITE_LOCAL_USER_UPDATE_TRIGGER
            nonlocal_user_insert_trigger = SQLITE_NONLOCAL_USER_INSERT_TRIGGER
            nonlocal_user_update_trigger = SQLITE_NONLOCAL_USER_UPDATE_TRIGGER
        else:
            local_user_insert_trigger = MYSQL_LOCAL_USER_INSERT_TRIGGER
            local_user_update_trigger = MYSQL_LOCAL_USER_UPDATE_TRIGGER
            nonlocal_user_insert_trigger = MYSQL_NONLOCAL_USER_INSERT_TRIGGER
            nonlocal_user_update_trigger = MYSQL_NONLOCAL_USER_UPDATE_TRIGGER
        migrate_engine.execute(local_user_insert_trigger)
        migrate_engine.execute(local_user_update_trigger)
        migrate_engine.execute(nonlocal_user_insert_trigger)
        migrate_engine.execute(nonlocal_user_update_trigger)
