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
            json=self.admin_credentials)
        
        # Assert we get back a token with an expiration date
        self.assertTrue(r.json['auth']['token']['id'])
        self.assertTrue(r.json['auth']['token']['expires'])

class TestServiceAuthentication(KeystoneTestCase):
    """Test service-side user authentication"""
    
    user_id = KeystoneTestCase._uuid()
    
    def setUp(self):
        super(TestServiceAuthentication, self).setUp()
        
        # Create a user
        self.admin_request(method='PUT', path='/users',
            json={
                'user': {
                    'id': self.user_id,
                    'password': 'secrete',
                    'email': 'user@openstack.org',
                    'enabled': True,
                }
            })
    
    def tearDown(self):
        # Delete user
        self.admin_request(method='DELETE', path='/users/%s' % self.user_id)
    
    def test_user_auth(self):
        # Authenticate as user to get a token
        r = self.service_request(method='POST', path='/tokens',
            json={
                'passwordCredentials': {
                    'username': self.user_id,
                    'password': 'secrete',
                }
            })
        self.service_token = r.json['auth']['token']['id']
        
        """In the real world, the service user would then pass his/her token
        to some service that depends on keystone, which would then need to
        user keystone to validate the provided token."""
        
        # Admin independently validates the user token
        self.admin_request(path='/tokens/%s' % self.service_token)

if __name__ == '__main__':
    unittest.main()
