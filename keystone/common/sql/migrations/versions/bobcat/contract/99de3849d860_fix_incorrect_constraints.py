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

"""Fix incorrect constraints.

Revision ID: 99de3849d860
Revises: e25ffa003242
Create Date: 2022-08-02 12:23:25.525035
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '99de3849d860'
down_revision = 'e25ffa003242'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('access_rule', schema=None) as batch_op:
        batch_op.drop_constraint('access_rule_external_id_key', type_='unique')

    with op.batch_alter_table('trust', schema=None) as batch_op:
        batch_op.drop_constraint(
            'duplicate_trust_constraint_expanded', type_='unique'
        )
