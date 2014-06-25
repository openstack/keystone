# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from keystone.common import sql
from keystone.identity.mapping_backends import sql as mapping_sql

# NOTE(henry-nash): This function is defined in a separate file since it will
# be used across multiple unit test files once the full support for cross
# backend identifiers is implemented.
#
# TODO(henry-nash): Remove this comment once the full support mentioned above
# has landed, since the reason for this separate file will be obvious.


def list_id_mappings():
    """List all id_mappings for testing purposes."""

    a_session = sql.get_session()
    refs = a_session.query(mapping_sql.IDMapping).all()
    return [x.to_dict() for x in refs]
