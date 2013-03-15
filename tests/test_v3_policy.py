import uuid

import test_v3


class PolicyTestCase(test_v3.RestfulTestCase):
    """Test policy CRUD"""

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
        """POST /policies"""
        ref = self.new_policy_ref()
        r = self.post(
            '/policies',
            body={'policy': ref})
        return self.assertValidPolicyResponse(r, ref)

    def test_list_policies(self):
        """GET /policies"""
        r = self.get('/policies')
        self.assertValidPolicyListResponse(r, ref=self.policy)

    def test_list_policies_xml(self):
        """GET /policies (xml data)"""
        r = self.get('/policies', content_type='xml')
        self.assertValidPolicyListResponse(r, ref=self.policy)

    def test_get_policy(self):
        """GET /policies/{policy_id}"""
        r = self.get(
            '/policies/%(policy_id)s' % {
                'policy_id': self.policy_id})
        self.assertValidPolicyResponse(r, self.policy)

    def test_update_policy(self):
        """PATCH /policies/{policy_id}"""
        policy = self.new_policy_ref()
        policy['id'] = self.policy_id
        r = self.patch(
            '/policies/%(policy_id)s' % {
                'policy_id': self.policy_id},
            body={'policy': policy})
        self.assertValidPolicyResponse(r, policy)

    def test_delete_policy(self):
        """DELETE /policies/{policy_id}"""
        self.delete(
            '/policies/%(policy_id)s' % {
                'policy_id': self.policy_id})
