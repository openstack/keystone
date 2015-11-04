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

from keystone.common import config as common_cfg


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
            common_cfg.setup_authentication()
        if self.method_classes:
            self.config_fixture.config(group='auth', **self.method_classes)
