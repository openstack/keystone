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

from keystone import exception


class DriverTestCase(object):
    """Test cases to validate the current policy driver behavior."""

    def setUp(self):
        super(DriverTestCase, self).setUp()

        self.policy = {'id': uuid.uuid4().hex,
                       'blob': '{"identity:create_user": "role:domain_admin"}',
                       'type': 'application/json'}
        self.driver.create_policy(self.policy['id'], self.policy)

    @property
    def driver(self):
        raise exception.NotImplemented()

    def test_list_policies(self):
        another_policy = {'id': uuid.uuid4().hex,
                          'blob': '{"compute:create": "role:project_member"}',
                          'type': 'application/json'}
        self.driver.create_policy(another_policy['id'], another_policy)

        policies = self.driver.list_policies()

        self.assertCountEqual([self.policy, another_policy], policies)

    def test_get_policy(self):
        self.assertEqual(self.policy,
                         self.driver.get_policy(self.policy['id']))

    def test_update_policy(self):
        self.policy['blob'] = ('{"identity:create_user": "role:domain_admin",'
                               '"identity:update_user": "role:domain_admin"}')

        self.driver.update_policy(self.policy['id'], self.policy)

        self.assertEqual(self.policy,
                         self.driver.get_policy(self.policy['id']))

    def test_delete_policy(self):
        self.driver.delete_policy(self.policy['id'])

        self.assertRaises(exception.PolicyNotFound,
                          self.driver.get_policy,
                          self.policy['id'])
