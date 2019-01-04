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

import uuid

from keystone.access_rules_config.backends import json as json_driver
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import access_rules_config
from keystone.tests.unit.ksfixtures import temporaryfile


class JSONDriverTestCase(unit.TestCase):
    """Tests for validating the access rules config driver."""

    def setUp(self):
        super(JSONDriverTestCase, self).setUp()
        rules_file = '%s/access_rules.json' % unit.TESTCONF
        self.useFixture(access_rules_config.AccessRulesConfig(
            self.config_fixture, rules_file=rules_file))
        self.driver = json_driver.AccessRulesConfig()

    def test_invalid_json_raises_error(self):
        tmpfile = self.useFixture(temporaryfile.SecureTempFile())
        invalid_access_rules = tmpfile.file_name
        with open(invalid_access_rules, 'w') as f:
            f.write("This is an invalid data")
        self.useFixture(access_rules_config.AccessRulesConfig(
            self.config_fixture, rules_file=invalid_access_rules))
        self.assertRaises(exception.AccessRulesConfigFileError,
                          json_driver.AccessRulesConfig)

    def test_list_access_rules_config(self):
        rules = self.driver.list_access_rules_config()
        self.assertIn('identity', rules)
        self.assertIn('image', rules)

    def test_list_access_rules_config_for_service(self):
        rules = self.driver.list_access_rules_config(service='image')
        self.assertNotIn('identity', rules)
        self.assertIn('image', rules)

    def test_check_access_rule(self):
        result = self.driver.check_access_rule('identity', '/v3/users', 'GET')
        self.assertTrue(result)
        userid = uuid.uuid4().hex
        check_path = '/v3/users/%(userid)s' % {'userid': userid}
        result = self.driver.check_access_rule('identity', check_path, 'GET')
        self.assertTrue(result)
        img = uuid.uuid4().hex
        memb = uuid.uuid4().hex
        check_path = '/v2/images/%(img)s/members/%(memb)s' % {'img': img,
                                                              'memb': memb}
        result = self.driver.check_access_rule('image', check_path, 'PUT')
        self.assertTrue(result)
        result = self.driver.check_access_rule('image', '/servers', 'GET')
        self.assertFalse(result)
        result = self.driver.check_access_rule('glance', '/v2/images', 'GET')
        self.assertFalse(result)
        result = self.driver.check_access_rule('image', 'images', 'POST')
        self.assertFalse(result)
        projectid = uuid.uuid4().hex
        check_path = '/v3/%(projectid)s/volumes' % {'projectid': projectid}
        result = self.driver.check_access_rule('block-storage', check_path,
                                               'GET')
        self.assertTrue(result)
        check_path = '/v2/%(projectid)s/volumes' % {'projectid': projectid}
        result = self.driver.check_access_rule('block-storage', check_path,
                                               'GET')
        self.assertFalse(result)
        result = self.driver.check_access_rule('compute', '/v2.1/servers',
                                               'GET')
        self.assertTrue(result)
