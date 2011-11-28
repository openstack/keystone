import unittest2 as unittest
from keystone.test.functional import common


class TestGetCredentials(common.FunctionalTestCase):
    """Test Get credentials operations"""

    def setUp(self):
        super(TestGetCredentials, self).setUp()
        password = common.unique_str()
        self.user = self.create_user(user_password=password).json['user']

    def test_get_user_credentials(self):
        password_credentials = self.fetch_user_credentials(
            self.user['id']).json['credentials'][0]['passwordCredentials']
        self.assertEquals(password_credentials['username'], self.user['name'])

    def test_get_user_credentials_xml(self):
        r = self.fetch_user_credentials(self.user['id'],
            assert_status=200, headers={
            'Accept': 'application/xml'})
        self.assertEquals(r.xml.tag, '{%s}credentials' % self.xmlns)
        password_credentials =\
            r.xml.find('{%s}passwordCredentials' % self.xmlns)
        self.assertEqual(
            password_credentials.get('username'), self.user['name'])

    def test_get_user_credentials_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.fetch_user_credentials(self.user['id'], assert_status=403)

    def test_get_user_credentials_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_user_credentials(self.user['id'], assert_status=403)

    def test_get_user_credentials_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_user_credentials(self.user['name'], assert_status=403)

    def test_get_user_credentials_using_missing_token(self):
        self.admin_token = ''
        self.fetch_user_credentials(self.user['id'], assert_status=401)

    def test_get_user_credentials_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_user_credentials(self.user['id'], assert_status=401)


class TestGetPasswordCredentials(common.FunctionalTestCase):
    """Test get password credentials operations"""

    def setUp(self):
        super(TestGetPasswordCredentials, self).setUp()
        password = common.unique_str()
        self.user = self.create_user(user_password=password).json['user']

    def test_get_user_credentials(self):
        password_credentials = self.fetch_password_credentials(
            self.user['id']).json['passwordCredentials']
        self.assertEquals(password_credentials['username'], self.user['name'])

    def test_get_user_credentials_xml(self):
        r = self.fetch_password_credentials(self.user['id'],
            assert_status=200, headers={
            'Accept': 'application/xml'})
        password_credentials = r.xml
        self.assertEqual(
            password_credentials.get('username'), self.user['name'])

    def test_get_user_credentials_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.fetch_password_credentials(self.user['id'], assert_status=403)

    def test_get_user_credentials_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_password_credentials(self.user['id'], assert_status=403)

    def test_get_user_credentials_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_password_credentials(self.user['name'], assert_status=403)

    def test_get_user_credentials_using_missing_token(self):
        self.admin_token = ''
        self.fetch_password_credentials(self.user['id'], assert_status=401)

    def test_get_user_credentials_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_password_credentials(self.user['id'], assert_status=401)


class TestCreatePasswordCredentials(common.FunctionalTestCase):
    """Test create password credentials operations"""

    def setUp(self):
        super(TestCreatePasswordCredentials, self).setUp()
        password = common.unique_str()
        self.user = self.create_user(
            user_password=password).json['user']
        self.delete_user_credentials_by_type(
            self.user['id'], 'passwordCredentials')

    def test_create_password_credentials(self):
        self.create_password_credentials(
            self.user['id'], self.user['name'],
            assert_status=201)

    def test_create_password_credentials_using_empty_password(self):
        self.create_password_credentials(
            user_id=self.user['id'], user_name=self.user['name'], password='',\
            assert_status=400)

    def test_create_password_credentials_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<passwordCredentials xmlns="%s"'
            ' username="%s" password="%s"/>') % (
                self.xmlns, self.user['name'], 'passw0rd')
        self.post_credentials(self.user['id'], as_xml=data, assert_status=201)

    def test_create_password_credentials_xml_using_empty_password(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<passwordCredentials xmlns="%s"'
            ' username="%s" password="%s"/>') % (
                self.xmlns, self.user['name'], '')
        self.post_credentials(self.user['id'], as_xml=data, assert_status=400)

    def test_create_password_credentials_twice(self):
        self.create_password_credentials(self.user['id'], self.user['name'],
            assert_status=201)
        self.create_password_credentials(self.user['id'], self.user['name'],
            assert_status=400)

    def test_create_password_credentials_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.create_password_credentials(self.user['id'], self.user['name'],
            assert_status=403)

    def test_create_password_credentials_missing_token(self):
        self.admin_token = ''
        self.create_password_credentials(self.user['id'], self.user['name'],
            assert_status=401)

    def test_create_password_credentials_invalid_token(self):
        self.admin_token = common.unique_str()
        self.create_password_credentials(self.user['id'], self.user['name'],
            assert_status=401)


class TestUpdatePasswordCredentials(common.FunctionalTestCase):
    """Test update password credentials operations"""

    def setUp(self):
        super(TestUpdatePasswordCredentials, self).setUp()
        password = common.unique_str()
        self.user = self.create_user(user_password=password).json['user']

    def test_update_password_credentials(self):
        self.update_password_credentials(self.user['id'], self.user['name'],
            assert_status=200)

    def test_update_password_credentials_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<passwordCredentials xmlns="%s"'
            ' username="%s" password="%s"/>') % (
                self.xmlns, self.user['name'], 'passw0rd')
        self.post_credentials_by_type(self.user['id'], 'passwordCredentials',
            as_xml=data, assert_status=200)

    def test_update_password_credentials_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.update_password_credentials(self.user['id'], self.user['name'],
            assert_status=403)

    def test_update_password_credentials_missing_token(self):
        self.admin_token = ''
        self.update_password_credentials(self.user['id'], self.user['name'],
            assert_status=401)

    def test_update_password_credentials_invalid_token(self):
        self.admin_token = common.unique_str()
        self.update_password_credentials(self.user['id'], self.user['name'],
            assert_status=401)


class TestDeletePasswordCredentials(common.FunctionalTestCase):
    """Test delete password credentials operations"""

    def setUp(self):
        super(TestDeletePasswordCredentials, self).setUp()
        password = common.unique_str()
        self.user = self.create_user(user_password=password).json['user']

    def test_delete_password_credentials(self):
        self.delete_password_credentials(self.user['id'],
            assert_status=204)

    def test_delete_password_credentials_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.delete_password_credentials(self.user['id'],
            assert_status=403)

    def test_delete_password_credentials_missing_token(self):
        self.admin_token = ''
        self.delete_password_credentials(self.user['id'],
            assert_status=401)

    def test_delete_password_credentials_invalid_token(self):
        self.admin_token = common.unique_str()
        self.delete_password_credentials(self.user['id'],
            assert_status=401)


class TestAuthentication(common.FunctionalTestCase):
    """Test authentication after a password update."""
    def setUp(self):
        super(TestAuthentication, self).setUp()
        password = common.unique_str()
        self.user = self.create_user(user_password=password).json['user']

    def test_authentication_after_password_change(self):
        self.authenticate(self.user['name'], self.user['password'],
                    assert_status=200)
        password = common.unique_str()
        self.update_password_credentials(self.user['id'], self.user['name'],
            password=password, assert_status=200)
        self.authenticate(self.user['name'], password,
                    assert_status=200)

if __name__ == '__main__':
    unittest.main()
