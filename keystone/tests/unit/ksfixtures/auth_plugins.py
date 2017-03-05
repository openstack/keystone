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
import keystone.conf


class ConfigAuthPlugins(fixtures.Fixture):
    """A fixture for setting up and tearing down a auth plugins."""

    def __init__(self, config_fixture, methods, **method_classes):
        super(ConfigAuthPlugins, self).__init__()
        self.methods = methods
        self.config_fixture = config_fixture
        self.method_classes = method_classes

    def setUp(self):
        super(ConfigAuthPlugins, self).setUp()
        if self.methods:
            self.config_fixture.config(group='auth', methods=self.methods)
            keystone.conf.auth.setup_authentication()
        if self.method_classes:
            self.config_fixture.config(group='auth', **self.method_classes)


class LoadAuthPlugins(fixtures.Fixture):

    def __init__(self, *method_names):
        super(LoadAuthPlugins, self).__init__()
        self.method_names = method_names
        # NOTE(dstanek): This fixture will load the requested auth
        # methods as part of its setup. We need to save any existing
        # plugins so that we can restore them in the cleanup.
        self.saved = {}

    def setUp(self):
        super(LoadAuthPlugins, self).setUp()

        AUTH_METHODS = auth.core.AUTH_METHODS
        for method_name in self.method_names:
            if method_name in AUTH_METHODS:
                self.saved[method_name] = AUTH_METHODS[method_name]
            AUTH_METHODS[method_name] = auth.core.load_auth_method(
                method_name)
        auth.core.AUTH_PLUGINS_LOADED = True

    def cleanUp(self):
        AUTH_METHODS = auth.core.AUTH_METHODS
        for method_name in list(AUTH_METHODS):
            if method_name in self.saved:
                AUTH_METHODS[method_name] = self.saved[method_name]
            else:
                del AUTH_METHODS[method_name]
        auth.core.AUTH_PLUGINS_LOADED = False
