# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import os

from keystone.openstack.common.db.sqlalchemy import migration


def _repo_path():
    return os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'migrate_repo')


def db_version_control(version=None):
    return migration.db_version_control(_repo_path(), version=version)


def db_sync(version=None):
    return migration.db_sync(_repo_path(), version=version)


def db_version(version=None):
    return migration.db_version(_repo_path(), version)
