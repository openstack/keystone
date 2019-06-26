# Copyright 2019 SUSE Linux GmbH
#
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

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import access_rules_config

PROVIDERS = provider_api.ProviderAPIs


class AccessRulesConfigTest(unit.TestCase):

    def setUp(self):
        super(AccessRulesConfigTest, self).setUp()
        rules_file = '%s/access_rules.json' % unit.TESTCONF
        self.useFixture(access_rules_config.AccessRulesConfig(
            self.config_fixture, rules_file=rules_file))
        self.load_backends()

    def test_list_access_rules_config(self):
        rules = PROVIDERS.access_rules_config_api.list_access_rules_config()
        self.assertIn('identity', rules)
        self.assertIn('image', rules)

    def test_list_access_rules_config_for_service(self):
        rules = PROVIDERS.access_rules_config_api.list_access_rules_config(
            service='image')
        self.assertNotIn('identity', rules)
        self.assertIn('image', rules)

    def test_check_access_rule(self):
        result = PROVIDERS.access_rules_config_api.check_access_rule(
            'identity', '/v3/users', 'GET')
        self.assertTrue(result)
