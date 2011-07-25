import unittest
from common import KeystoneTestCase

class TestAdminAuthentication(KeystoneTestCase):
    """Test admin-side user authentication"""
    
    def setUp(self):
        """Empty method to prevent KeystoneTestCase from authenticating"""
        pass
    
    def test_bootstrapped_admin_user(self):
        """Bootstrap script should create an 'admin' user with 'Admin' role"""
        # Authenticate as admin
        r = self.admin_request(method='POST', path='/tokens',
            as_json=self.admin_credentials)
        
        # Assert we get back a token with an expiration date
        self.assertTrue(r.json['auth']['token']['id'])
        self.assertTrue(r.json['auth']['token']['expires'])

class TestAdminAuthenticationNegative(KeystoneTestCase):
    """Negative test admin-side user authentication"""
    
    user_id = KeystoneTestCase._uuid()
    user_id2 = KeystoneTestCase._uuid()
    admin_token_backup = None
    
    def test_service_token_as_admin_token(self):
        """Admin actions should fail for mere service tokens"""
        
        # Admin create a user
        self.admin_request(method='PUT', path='/users',
            as_json={
                'user': {
                    'id': self.user_id,
                    'password': 'secrete',
                    'email': self.user_id + '@openstack.org',
                    'enabled': True,
                }
            })
        
        # User authenticates to get a token
        r = self.service_request(method='POST', path='/tokens',
            as_json={
                'passwordCredentials': {
                    'username': self.user_id,
                    'password': 'secrete',
                }
            })
        self.service_token = r.json['auth']['token']['id']
        
        # Prepare to use the service token as an admin token
        self.admin_token_backup = self.admin_token
        self.admin_token = self.service_token
        
        # Try creating another user
        self.admin_request(method='PUT', path='/users', assert_status=401,
            as_json={
                'user': {
                    'id': self.user_id2,
                    'password': 'secrete',
                    'email': self.user_id2 + '@openstack.org',
                    'enabled': True,
                }
            })

    def tearDown(self):
        # Restore our admin token so we can clean up
        self.admin_token = self.admin_token_backup
         
        # Delete user
        self.admin_request(method='DELETE', path='/users/%s' % self.user_id)
    
class TestServiceAuthentication(KeystoneTestCase):
    """Test service-side user authentication"""
    
    user_id = KeystoneTestCase._uuid()
    
    def setUp(self):
        super(TestServiceAuthentication, self).setUp()
        
        # Create a user
        self.admin_request(method='PUT', path='/users',
            as_json={
                'user': {
                    'id': self.user_id,
                    'password': 'secrete',
                    'email': self.user_id + '@openstack.org',
                    'enabled': True,
                }
            })
    
    def tearDown(self):
        # Delete user
        self.admin_request(method='DELETE', path='/users/%s' % self.user_id)
    
    def test_user_auth(self):
        # Authenticate as user to get a token
        r = self.service_request(method='POST', path='/tokens',
            as_json={
                'passwordCredentials': {
                    'username': self.user_id,
                    'password': 'secrete',
                }
            })
        self.service_token = r.json['auth']['token']['id']
        
        # In the real world, the service user would then pass his/her token
        # to some service that depends on keystone, which would then need to
        # user keystone to validate the provided token.
        
        # Admin independently validates the user token
        self.admin_request(path='/tokens/%s' % self.service_token)

if __name__ == '__main__':
    unittest.main()
