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

Revision ID: b4f8b3f584e0
Revises: 29e87d24a316
Create Date: 2022-08-02 12:23:25.520570
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = 'b4f8b3f584e0'
down_revision = '29e87d24a316'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('trust', schema=None) as batch_op:
        batch_op.create_unique_constraint(
            'duplicate_trust_constraint',
            [
                'trustor_user_id',
                'trustee_user_id',
                'project_id',
                'impersonation',
                'expires_at',
            ],
        )
