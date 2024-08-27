# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Remove duplicate constraints.

Revision ID: c88cdce8f248
Revises: 99de3849d860
Create Date: 2023-03-15 13:17:44.060715
"""

from alembic import op
from sqlalchemy.engine import reflection

# revision identifiers, used by Alembic.
revision = 'c88cdce8f248'
down_revision = '99de3849d860'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    # This only affects MySQL - PostgreSQL and SQLite were smart enough to
    # ignore the duplicate constraints
    if bind.engine.name != 'mysql':
        return

    # We want to drop a duplicate index on the 'project_tag' table. To drop an
    # index, we would normally just use drop_index like so:
    #
    #   with op.batch_alter_table('project_tag', schema=None) as batch_op:
    #       batch_op.drop_index(foo)
    #
    # However, the index wasn't explicitly named so we're not sure what 'foo'
    # is. It has two potential names:
    #
    # - If it was created by alembic, alembic will have left things up to the
    #   backend, which on MySQL means the index will have the same name as the
    #   first column the index covers [1]. Alternatively, ...
    # - If it was created by sqlalchemy-migrate then it will be called
    #   '{table_name}_{first_column_name}_key' [2]
    #
    # We need to handle both, so we need to first inspect the table to find
    # which it is.
    #
    # Note that unlike MariaDB [3], MySQL [4] doesn't support the 'ALTER TABLE
    # tbl_name DROP CONSTRAINT IF EXISTS constraint_name' syntax, which would
    # have allowed us to avoid the inspection. Boo.
    #
    # [1] https://dba.stackexchange.com/a/160712
    # [2] https://opendev.org/x/sqlalchemy-migrate/src/commit/5d1f322542cd8eb42381612765be4ed9ca8105ec/migrate/changeset/constraint.py#L199  # noqa: E501
    # [3] https://mariadb.com/kb/en/alter-table/
    # [4] https://dev.mysql.com/doc/refman/8.0/en/alter-table.html

    inspector = reflection.Inspector.from_engine(bind)
    indexes = inspector.get_indexes('project_tag')

    index_name = None
    for index in indexes:
        if index['column_names'] == ['project_id', 'name']:
            index_name = index['name']
            break
    else:
        # This should never happen *but* we silently ignore it since there's no
        # need to break user's upgrade flow, even if they've borked something
        return

    with op.batch_alter_table('project_tag', schema=None) as batch_op:
        batch_op.drop_index(index_name)
