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

"""Remove service_provider.relay_state_prefix server default.

Revision ID: 11c3b243b4cb
Revises: b4f8b3f584e0
Create Date: 2023-07-03 12:03:21.649144
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '11c3b243b4cb'
down_revision = 'b4f8b3f584e0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('service_provider', schema=None) as batch_op:
        batch_op.alter_column('relay_state_prefix', server_default=None)
