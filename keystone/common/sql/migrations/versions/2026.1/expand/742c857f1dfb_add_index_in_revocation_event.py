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

"""Add index in revocation_event

Revision ID: 742c857f1dfb
Revises: e8725d6fa226
Create Date: 2025-11-24 10:21:03.202908
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = '742c857f1dfb'
down_revision = 'e8725d6fa226'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        'ix_revocation_event_project_id_user_id',
        'revocation_event',
        ['project_id', 'user_id'],
    )
    op.create_index(
        'ix_revocation_event_composite',
        'revocation_event',
        ['issued_before', 'user_id', 'project_id', 'audit_id'],
    )
