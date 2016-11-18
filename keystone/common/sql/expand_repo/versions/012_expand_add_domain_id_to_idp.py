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
CREATE TRIGGER idp_insert_read_only BEFORE INSERT ON identity_provider
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = '%s';
END;
"""

SQLITE_INSERT_TRIGGER = """
CREATE TRIGGER idp_insert_read_only BEFORE INSERT ON identity_provider
BEGIN
  SELECT RAISE (ABORT, '%s');
END;
"""

POSTGRESQL_INSERT_TRIGGER = """
CREATE OR REPLACE FUNCTION keystone_read_only_insert()
  RETURNS trigger AS
$BODY$
BEGIN
  RAISE EXCEPTION '%s';
END
$BODY$ LANGUAGE plpgsql;

CREATE TRIGGER idp_insert_read_only BEFORE INSERT ON identity_provider
FOR EACH ROW
EXECUTE PROCEDURE keystone_read_only_insert();
"""


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    idp = sql.Table('identity_provider', meta, autoload=True)
    project = sql.Table('project', meta, autoload=True)
    domain_id = sql.Column('domain_id', sql.String(64),
                           sql.ForeignKey(project.c.id), nullable=True)
    idp.create_column(domain_id)

    if upgrades.USE_TRIGGERS:
        # Setting idp to be read-only to prevent old code from creating an idp
        # without a domain_id during an upgrade. This should be okay as it is
        # highly unlikely that an idp would be created during the migration and
        # the impact from preventing creations is minor.
        error_message = ('Identity provider migration in progress. Cannot '
                         'insert new rows into the identity_provider table at '
                         'this time.')
        if migrate_engine.name == 'postgresql':
            idp_insert_trigger = POSTGRESQL_INSERT_TRIGGER % error_message
        elif migrate_engine.name == 'sqlite':
            idp_insert_trigger = SQLITE_INSERT_TRIGGER % error_message
        else:
            idp_insert_trigger = MYSQL_INSERT_TRIGGER % error_message
        migrate_engine.execute(idp_insert_trigger)
