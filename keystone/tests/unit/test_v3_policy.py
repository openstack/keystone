# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid

from keystone.tests.unit import test_v3


class PolicyTestCase(test_v3.RestfulTestCase):
    """Test policy CRUD."""

    def setUp(self):
        super(PolicyTestCase, self).setUp()
        self.policy_id = uuid.uuid4().hex
        self.policy = self.new_policy_ref()
        self.policy['id'] = self.policy_id
        self.policy_api.create_policy(
            self.policy_id,
            self.policy.copy())

    # policy crud tests

    def test_create_policy(self):
        """Call ``POST /policies``."""
        ref = self.new_policy_ref()
        r = self.post(
            '/policies',
            body={'policy': ref})
        return self.assertValidPolicyResponse(r, ref)

    def test_list_policies(self):
        """Call ``GET /policies``."""
        r = self.get('/policies')
        self.assertValidPolicyListResponse(r, ref=self.policy)

    def test_get_policy(self):
        """Call ``GET /policies/{policy_id}``."""
        r = self.get(
            '/policies/%(policy_id)s' % {
                'policy_id': self.policy_id})
        self.assertValidPolicyResponse(r, self.policy)

    def test_update_policy(self):
        """Call ``PATCH /policies/{policy_id}``."""
        policy = self.new_policy_ref()
        policy['id'] = self.policy_id
        r = self.patch(
            '/policies/%(policy_id)s' % {
                'policy_id': self.policy_id},
            body={'policy': policy})
        self.assertValidPolicyResponse(r, policy)

    def test_delete_policy(self):
        """Call ``DELETE /policies/{policy_id}``."""
        self.delete(
            '/policies/%(policy_id)s' % {
                'policy_id': self.policy_id})
