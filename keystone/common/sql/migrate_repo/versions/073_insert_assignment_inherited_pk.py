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
from sqlalchemy.orm import sessionmaker

from keystone.assignment.backends import sql as assignment_sql


def upgrade(migrate_engine):
    """Inserts inherited column to assignment table PK contraints.

    For non-SQLite databases, it changes the constraint in the existing table.

    For SQLite, since changing constraints is not supported, it recreates the
    assignment table with the new PK constraint and migrates the existing data.

    """

    ASSIGNMENT_TABLE_NAME = 'assignment'

    metadata = sql.MetaData()
    metadata.bind = migrate_engine

    # Retrieve the existing assignment table
    assignment_table = sql.Table(ASSIGNMENT_TABLE_NAME, metadata,
                                 autoload=True)

    if migrate_engine.name == 'sqlite':
        ACTOR_ID_INDEX_NAME = 'ix_actor_id'
        TMP_ASSIGNMENT_TABLE_NAME = 'tmp_assignment'

        # Define the new assignment table with a temporary name
        new_assignment_table = sql.Table(
            TMP_ASSIGNMENT_TABLE_NAME, metadata,
            sql.Column('type', sql.Enum(
                assignment_sql.AssignmentType.USER_PROJECT,
                assignment_sql.AssignmentType.GROUP_PROJECT,
                assignment_sql.AssignmentType.USER_DOMAIN,
                assignment_sql.AssignmentType.GROUP_DOMAIN,
                name='type'),
                nullable=False),
            sql.Column('actor_id', sql.String(64), nullable=False),
            sql.Column('target_id', sql.String(64), nullable=False),
            sql.Column('role_id', sql.String(64), sql.ForeignKey('role.id'),
                       nullable=False),
            sql.Column('inherited', sql.Boolean, default=False,
                       nullable=False),
            sql.PrimaryKeyConstraint('type', 'actor_id', 'target_id',
                                     'role_id', 'inherited'),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

        # Create the new assignment table
        new_assignment_table.create(migrate_engine, checkfirst=True)

        # Change the index from the existing assignment table to the new one
        sql.Index(ACTOR_ID_INDEX_NAME, assignment_table.c.actor_id).drop()
        sql.Index(ACTOR_ID_INDEX_NAME,
                  new_assignment_table.c.actor_id).create()

        # Instantiate session
        maker = sessionmaker(bind=migrate_engine)
        session = maker()

        # Migrate existing data
        insert = new_assignment_table.insert().from_select(
            assignment_table.c, select=session.query(assignment_table))
        session.execute(insert)
        session.commit()

        # Drop the existing assignment table, in favor of the new one
        assignment_table.deregister()
        assignment_table.drop()

        # Finally, rename the new table to the original assignment table name
        new_assignment_table.rename(ASSIGNMENT_TABLE_NAME)
    elif migrate_engine.name == 'ibm_db_sa':
        # Recreate the existing constraint, marking the inherited column as PK
        # for DB2.

        # This is a workaround to the general case in the else statement below.
        # Due to a bug in the DB2 sqlalchemy dialect, Column.alter() actually
        # creates a primary key over only the "inherited" column. This is wrong
        # because the primary key for the table actually covers other columns
        # too, not just the "inherited" column. Since the primary key already
        # exists for the table after the Column.alter() call, it causes the
        # next line to fail with an error that the primary key already exists.

        # The workaround here skips doing the Column.alter(). This causes a
        # warning message since the metadata is out of sync. We can remove this
        # workaround once the DB2 sqlalchemy dialect is fixed.
        # DB2 Issue: https://code.google.com/p/ibm-db/issues/detail?id=173

        migrate.PrimaryKeyConstraint(table=assignment_table).drop()
        migrate.PrimaryKeyConstraint(
            assignment_table.c.type, assignment_table.c.actor_id,
            assignment_table.c.target_id, assignment_table.c.role_id,
            assignment_table.c.inherited).create()
    else:
        # Recreate the existing constraint, marking the inherited column as PK
        migrate.PrimaryKeyConstraint(table=assignment_table).drop()
        assignment_table.c.inherited.alter(primary_key=True)
        migrate.PrimaryKeyConstraint(table=assignment_table).create()
