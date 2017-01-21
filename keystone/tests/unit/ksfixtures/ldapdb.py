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

import fixtures

from keystone.identity.backends.ldap import common as common_ldap
from keystone.tests.unit import fakeldap


class LDAPDatabase(fixtures.Fixture):
    """A fixture for setting up and tearing down an LDAP database."""

    def __init__(self, dbclass=fakeldap.FakeLdap):
        self._dbclass = dbclass

    def setUp(self):
        super(LDAPDatabase, self).setUp()
        self.clear()
        common_ldap.WRITABLE = True
        common_ldap._HANDLERS.clear()
        common_ldap.register_handler('fake://', self._dbclass)
        # TODO(dstanek): switch the flow here
        self.addCleanup(self.clear)
        self.addCleanup(common_ldap._HANDLERS.clear)
        self.addCleanup(self.disable_write)

    def disable_write(self):
        common_ldap.WRITABLE = False

    def clear(self):
        for shelf in fakeldap.FakeShelves:
            fakeldap.FakeShelves[shelf].clear()
