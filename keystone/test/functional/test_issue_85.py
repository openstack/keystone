import unittest2 as unittest
from keystone.test.functional import common


class TestIssue85(common.FunctionalTestCase):
    """Illustrates github issue #85"""

    def test_disabling_tenant_disables_token(self):
        """Disabling a tenant should invalidate previously-issued tokens"""
        # Create a user for a specific tenant
        tenant = self.create_tenant().json['tenant']
        password = common.unique_str()
        user = self.create_user(user_password=password,
            tenant_id=tenant['id']).json['user']
        user['password'] = password

        # Authenticate as user to get a token *for a specific tenant*
        user_token = self.authenticate(user['name'], user['password'],
            tenant['id']).json['access']['token']['id']

        # Validate and check that token belongs to tenant
        print self.get_token(user_token).body
        tenant_id = self.get_token(user_token).\
            json['access']['token']['tenant']['id']
        self.assertEqual(tenant_id, tenant['id'])

        # Disable tenant
        r = self.admin_request(method='POST',
            path='/tenants/%s' % tenant['id'],
            as_json={
                'tenant': {
                    'name': tenant['name'],
                    'description': 'description',
                    'enabled': False}})
        self.assertEquals(r.json['tenant']['enabled'], False)

        # Assert that token belonging to disabled tenant is invalid
        r = self.admin_request(path='/tokens/%s?belongsTo=%s' %
            (user_token, tenant['id']), assert_status=403)
        self.assertTrue(r.json['tenantDisabled'], 'Tenant is disabled')

if __name__ == '__main__':
    unittest.main()
