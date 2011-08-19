import unittest2 as unittest
from keystone.test.functional import common


class TestIssue85(common.KeystoneTestCase):
    """Illustrates github issue #85"""

    tenant_id = common.KeystoneTestCase._uuid()
    user_id = common.KeystoneTestCase._uuid()

    def setUp(self):
        super(TestIssue85, self).setUp()

        # Create a tenant
        self.admin_request(method='POST', path='/tenants',
            as_json={
                'tenant': {
                    'id': self.tenant_id,
                    'description': 'description',
                    'enabled': True}})

        # Create a user for a specific tenant
        self.admin_request(method='PUT', path='/users',
            as_json={
                'user': {
                    'id': self.user_id,
                    'password': 'secrete',
                    'email': 'user@openstack.org',
                    'enabled': True,
                    'tenantId': self.tenant_id}})

    def tearDown(self):
        # Delete user
        self.admin_request(method='DELETE', path='/users/%s' %
            self.user_id)

        # Delete tenant
        self.admin_request(method='DELETE', path='/tenants/%s' %
            self.tenant_id)

    def test_disabling_tenant_disables_token(self):
        """Disabling a tenant should invalidate previously-issued tokens"""
        # Authenticate as user to get a token *for a specific tenant*
        r = self.service_request(method='POST', path='/tokens',
            as_json={
                'passwordCredentials': {
                    'username': self.user_id,
                    'password': 'secrete',
                    'tenantId': self.tenant_id}})
        self.service_token = r.json['auth']['token']['id']

        # Validate and check that token belongs to tenant
        self.admin_request(path='/tokens/%s?belongsTo=%s' %
            (self.service_token, self.tenant_id))

        # Disable tenant
        r = self.admin_request(method='PUT',
            path='/tenants/%s' % self.tenant_id,
            as_json={
                'tenant': {
                    'description': 'description',
                    'enabled': False}})
        self.assertEqual(r.json['tenant']['enabled'], False)

        # Assert that token belonging to disabled tenant is invalid
        r = self.admin_request(path='/tokens/%s?belongsTo=%s' %
            (self.service_token, self.tenant_id),
            assert_status=403)
        self.assertTrue(r.json['tenantDisabled'], 'Tenant is disabled')


if __name__ == '__main__':
    unittest.main()
