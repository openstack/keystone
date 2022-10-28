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

import keystone.conf


CONF = keystone.conf.CONF


def symptom_database_connection_is_not_SQLite():
    """SQLite is not recommended for production deployments.

    SQLite does not enforce type checking and has limited support for
    migrations, making it unsuitable for use in keystone. Please change your
    `keystone.conf [database] connection` value to point to a supported
    database driver, such as MySQL.
    """  # noqa: D403
    return (
        CONF.database.connection is not None
        and 'sqlite' in CONF.database.connection)
