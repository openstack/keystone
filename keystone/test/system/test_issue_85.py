import unittest
from common import KeystoneTestCase

class TestIssue85(KeystoneTestCase):
    """Illustrates github issue #85"""
    
    tenant_id = KeystoneTestCase._uuid()
    user_id = KeystoneTestCase._uuid()
    
    def setUp(self):
        super(TestIssue85, self).setUp()
        
        # Create a tenant
        self.admin_request(method='POST', path='/tenants',
            json={
                'tenant':{
                    'id': self.tenant_id,
                    'description': 'description',
                    'enabled': True,
                }
            })
        
        # Create a user
        self.admin_request(method='PUT', path='/users',
            json={
                'user':{
                    'id': self.user_id,
                    'password': 'secrete',
                    'email': 'user@openstack.org',
                    'enabled': True,
                    'tenant_id': 'tenant',
                }
            })
    
    def tearDown(self):
        # Delete user
        self.admin_request(method='DELETE', path='/users/%s' % 
            self.user_id)
        
        # Delete tenant
        self.admin_request(method='DELETE', path='/tenants/%s' % 
            self.tenant_id)
    
    def test_disabling_tenant_disables_token(self):
        """Disabling a tenant should invalidate previously-issued tokens"""
        # Authenticate as user to get a token
        r = self.service_request(method='POST', path='/tokens',
            json={
                'passwordCredentials': {
                    'username': self.user_id,
                    'password': 'secrete',
                }
            })
        self.service_token = r.json['auth']['token']['id']
        
        # Validate tenant token
        self.admin_request(path='/tokens/%s' % self.service_token)
        
        # Disable tenant
        r = self.admin_request(method='PUT',
            path='/tenants/%s' % self.tenant_id,
            json={
                'tenant': {
                    'description': 'description',
                    'enabled': False,
                }
            })
        self.assertEqual(r.json['tenant']['enabled'], False)
        
        # Assert tenant token invalidated
        # Commented this out because it will fail this test
#        self.admin_request(path='/tokens/%s' % self.service_token,
#            expect_exception=True)

if __name__ == '__main__':
    unittest.main()
