import unittest2 as unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', '..', 'keystone')))

import keystone.logic.types.auth as auth


class TestAuth(unittest.TestCase):
    '''Unit tests for auth.py.'''

    pwd_xml = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secret" username="disabled" \
                />'

    def test_pwd_cred_marshall(self):
        creds = auth.PasswordCredentials.from_xml(self.pwd_xml)
        self.assertTrue(creds.password, "secret")
        self.assertTrue(creds.username, "username")


if __name__ == '__main__':
    unittest.main()
