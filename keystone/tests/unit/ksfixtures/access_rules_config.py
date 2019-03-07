# Copyright 2019 SUSE Linux GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import fixtures


class AccessRulesConfig(fixtures.Fixture):
    """A fixture for working with JSON access rules config."""

    def __init__(self, config_fixture, rules_file=None):
        self._config_fixture = config_fixture
        self._rules_file = rules_file

    def setUp(self):
        super(AccessRulesConfig, self).setUp()
        self._config_fixture.config(group='access_rules_config',
                                    rules_file=self._rules_file)
