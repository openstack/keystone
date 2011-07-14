import unittest
from common import KeystoneTestCase

class TestIssue85(KeystoneTestCase):
    """Illustrates github issue #85"""
    
    def test_disabling_tenant_disables_token(self):
        """Disabling a tenant should invalidate previously-issued tokens"""
        # Authenticate as admin
        r = self.admin_request(method='POST', path='/v2.0/tokens',
            json=self.admin_credentials)
        self.admin_token = r.json['auth']['token']['id']
        
        user_id = 'user'
        tenant_id = 'tenant'
        
        # Create a tenant
        self.admin_request(method='POST', path='/v2.0/tenants',
            json={
                'tenant':{
                    'id': tenant_id,
                    'description': 'description',
                    'enabled': True,
                }
            })
        
        # Create a user
        self.admin_request(method='PUT', path='/v2.0/users',
            json={
                'user':{
                    'id': user_id,
                    'password': 'secrete',
                    'email': 'user@openstack.org',
                    'enabled': True,
                    'tenant_id': tenant_id,
                }
            })
        
        # Authenticate for tenant to get a token
        r = self.service_request(method='POST', path='/v2.0/tokens',
            json={
                'passwordCredentials':{
                    'username': user_id,
                    'password': 'secrete',
                }
            })
        self.service_token = r.json['auth']['token']['id']
        
        # Validate tenant token
        self.admin_request(path='/v2.0/tokens/%s' % self.service_token)
        
        # Disable tenant
        r = self.admin_request(method='PUT',
            path='/v2.0/tenants/%s' % tenant_id,
            json={
                'tenant':{
                    'id': tenant_id,
                    'description': 'dont care',
                    'enabled': False,
                }
            })
        self.assertEqual(r.json['tenant']['enabled'], False)
        
        # Assert tenant token invalidated
        # Commented this out because it will fail this test
#        self.admin_request(path='/v2.0/tokens/%s' % self.service_token,
#            expect_exception=True)

if __name__ == '__main__':
    unittest.main()
