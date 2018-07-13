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

from keystone import auth
import keystone.server


class BackendLoader(fixtures.Fixture):
    """Initialize each manager and assigns them to an attribute."""

    def __init__(self, testcase):
        super(BackendLoader, self).__init__()
        self._testcase = testcase

    def setUp(self):
        super(BackendLoader, self).setUp()

        self.clear_auth_plugin_registry()
        drivers, _unused = keystone.server.setup_backends()

        for manager_name, manager in drivers.items():
            setattr(self._testcase, manager_name, manager)

        self.addCleanup(self._testcase.cleanup_instance(*list(drivers.keys())))

        del self._testcase  # break circular reference

    def clear_auth_plugin_registry(self):
        auth.core.AUTH_METHODS.clear()
        auth.core.AUTH_PLUGINS_LOADED = False
