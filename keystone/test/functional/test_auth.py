import unittest2 as unittest
from keystone.test.functional import common


class TestAdminAuthentication(common.FunctionalTestCase):
    """Test admin-side user authentication"""

    def setUp(self):
        """Empty method to prevent KeystoneTestCase from authenticating"""
        pass

    def test_bootstrapped_admin_user(self):
        """Bootstrap script should create an 'admin' user with 'Admin' role"""
        # Authenticate as admin
        r = self.authenticate(self.admin_username, self.admin_password)

        # Assert we get back a token with an expiration date
        self.assertTrue(r.json['access']['token']['id'])
        self.assertTrue(r.json['access']['token']['expires'])


class TestAdminAuthenticationNegative(common.FunctionalTestCase):
    """Negative test admin-side user authentication"""

    def test_service_token_as_admin_token(self):
        """Admin actions should fail for mere service tokens"""

        # Admin create a user
        password = common.unique_str()
        user = self.create_user(user_password=password).json['user']
        user['password'] = password

        # Replace our admin_token with a mere service token
        self.admin_token = self.authenticate(user['name'], user['password']).\
            json['access']['token']['id']

        # Try creating another user using the wrong token
        self.create_user(assert_status=401)


class TestServiceAuthentication(common.FunctionalTestCase):
    """Test service-side user authentication"""

    def setUp(self):
        super(TestServiceAuthentication, self).setUp()

        # Create a user
        password = common.unique_str()
        self.user = self.create_user(user_password=password).json['user']
        self.user['password'] = password

    def test_user_auth(self):
        """Admin should be able to validate a user's token"""
        # Authenticate as user to get a token
        self.service_token = self.post_token(as_json={
            'auth': {
            'passwordCredentials': {
                'username': self.user['name'],
                'password': self.user['password']}}}).\
            json['access']['token']['id']

        # In the real world, the service user would then pass his/her token
        # to some service that depends on keystone, which would then need to
        # use keystone to validate the provided token.

        # Admin independently validates the user token
        r = self.get_token(self.service_token)
        self.assertTrue(r.json['access']['token']['expires'])
        self.assertEqual(r.json['access']['token']['id'], self.service_token)
        self.assertEqual(r.json['access']['user']['id'], self.user['id'])
        self.assertEqual(r.json['access']['user']['username'],
            self.user['name'])
        self.assertEqual(r.json['access']['user']['roles'], [])

    def test_get_request_fails(self):
        """GET /tokens should return a 404 (Github issue #5)"""
        self.service_request(method='GET', path='/tokens', assert_status=404)

    def test_user_auth_with_malformed_request_body(self):
        """Authenticating with unnexpected json returns a 400"""
        # Authenticate as user to get a token
        self.post_token(assert_status=400, as_json={
            'this-is-completely-wrong': {
                'username': self.user['name'],
                'password': self.user['password']}})

    def test_user_auth_with_wrong_name(self):
        """Authenticating with an unknown username returns a 401"""
        # Authenticate as user to get a token
        self.post_token(assert_status=401, as_json={
            'auth': {'passwordCredentials': {
                'username': 'this-is-completely-wrong',
                'password': self.user['password']}}})

    def test_user_auth_with_no_name(self):
        """Authenticating without a username returns a 401"""
        # Authenticate as user to get a token
        self.post_token(assert_status=401, as_json={
            'auth': {'passwordCredentials': {
                'username': None,
                'password': self.user['password']}}})

    def test_user_auth_with_wrong_password(self):
        """Authenticating with an invalid password returns a 401"""
        # Authenticate as user to get a token
        self.post_token(assert_status=401, as_json={
            'auth': {'passwordCredentials': {
                'username': self.user['name'],
                'password': 'this-is-completely-wrong'}}})

    def test_user_auth_with_no_password(self):
        """Authenticating with an invalid password returns a 401"""
        # Authenticate as user to get a token
        self.post_token(assert_status=401, as_json={
            'auth': {'passwordCredentials': {
                'username': self.user['name'],
                'password': None}}})

    def test_user_auth_with_invalid_tenant(self):
        """Authenticating with an invalid password returns a 401"""
        # Authenticate as user to get a token
        self.post_token(assert_status=401, as_json={
            'auth': {
            'passwordCredentials': {
                'username': self.user['name'],
                'password': self.user['password'],
                },
             'tenantId': 'this-is-completely-wrong'}})


if __name__ == '__main__':
    unittest.main()
