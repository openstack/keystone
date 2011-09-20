import unittest2 as unittest
import keystone.logic.types.auth as auth


class TestAuth(unittest.TestCase):
    '''Unit tests for auth.py.'''

    pwd_xml = '<?xml version="1.0" encoding="UTF-8"?>\
                <auth xmlns="http://docs.openstack.org/identity/api/v2.0">\
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secret" username="disabled" \
                /></auth>'

    def test_pwd_cred_marshall(self):
        creds = auth.AuthWithPasswordCredentials.from_xml(self.pwd_xml)
        self.assertTrue(creds.password, "secret")
        self.assertTrue(creds.username, "username")


if __name__ == '__main__':
    unittest.main()
