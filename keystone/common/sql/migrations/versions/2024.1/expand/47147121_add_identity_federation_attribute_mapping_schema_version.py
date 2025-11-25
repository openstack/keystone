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

"""Add Identity Federation attribute mapping schema version.

Revision ID: 47147121
Revises: 11c3b243b4cb
Create Date: 2023-12-12 09:00:00
"""

from alembic import op
from sqlalchemy import Column
from sqlalchemy import String

# revision identifiers, used by Alembic.
revision = '47147121'
down_revision = '11c3b243b4cb'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "mapping",
        Column(
            'schema_version', String(5), nullable=False, server_default="1.0"
        ),
    )
