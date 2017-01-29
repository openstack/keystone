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
from keystone.common import dependency
from keystone.common.kvs import core as kvs_core
from keystone.server import common


class BackendLoader(fixtures.Fixture):
    """Initialize each manager and assigns them to an attribute."""

    def __init__(self, testcase):
        super(BackendLoader, self).__init__()
        self._testcase = testcase

    def setUp(self):
        super(BackendLoader, self).setUp()

        # TODO(blk-u): Shouldn't need to clear the registry here, but some
        # tests call load_backends multiple times. These should be fixed to
        # only call load_backends once.
        dependency.reset()

        # TODO(morganfainberg): Shouldn't need to clear the registry here, but
        # some tests call load_backends multiple times.  Since it is not
        # possible to re-configure a backend, we need to clear the list.  This
        # should eventually be removed once testing has been cleaned up.
        kvs_core.KEY_VALUE_STORE_REGISTRY.clear()

        self.clear_auth_plugin_registry()
        drivers, _unused = common.setup_backends()

        for manager_name, manager in drivers.items():
            setattr(self._testcase, manager_name, manager)

        self.addCleanup(self._testcase.cleanup_instance(*list(drivers.keys())))

        del self._testcase  # break circular reference

    def clear_auth_plugin_registry(self):
        auth.core.AUTH_METHODS.clear()
        auth.core.AUTH_PLUGINS_LOADED = False
