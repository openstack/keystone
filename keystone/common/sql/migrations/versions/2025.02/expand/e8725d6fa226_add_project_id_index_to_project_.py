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

"""Add project_id index to project_endpoint_group

Revision ID: e8725d6fa226
Revises: 47147121
Create Date: 2024-09-03 11:45:01.577266
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = 'e8725d6fa226'
down_revision = '47147121'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('idx_project_id', 'project_endpoint_group', ['project_id'])
