import json
import unittest2 as unittest

from keystone import utils


class TestStringEmpty(unittest.TestCase):
    """Unit tests for string functions of utils.py."""

    def test_is_empty_for_a_valid_string(self):
        self.assertFalse(utils.is_empty_string('asdfgf'))

    def test_is_empty_for_a_blank_string(self):
        self.assertTrue(utils.is_empty_string(''))

    def test_is_empty_for_none(self):
        self.assertTrue(utils.is_empty_string(None))

    def test_is_empty_for_a_number(self):
        self.assertFalse(utils.is_empty_string(0))


class TestCredentialDetection(unittest.TestCase):
    """Unit tests for credential type detection"""

    def test_detects_passwordCredentials(self):
        self.content_type = "application/xml"
        self.body = '<auth '\
                    'xmlns="http://docs.openstack.org/identity/api/v2.0">'\
                    '<passwordCredentials/></auth>'
        self.assertEquals(utils.detect_credential_type(self),
                          "passwordCredentials")

    def test_detects_passwordCredentials_unwrapped(self):
        self.content_type = "application/xml"
        self.body = '<passwordCredentials '\
                    'xmlns="http://docs.openstack.org/identity/api/v2.0"/>'
        self.assertEquals(utils.detect_credential_type(self),
                          "passwordCredentials")

    def test_detects_no_creds(self):
        self.content_type = "application/xml"
        self.body = '<auth '\
                    'xmlns="http://docs.openstack.org/identity/api/v2.0"/>'
        self.assertRaises(Exception, utils.detect_credential_type, self)

    def test_detects_blank_creds(self):
        self.content_type = "application/xml"
        self.body = ''
        self.assertRaises(Exception, utils.detect_credential_type, self)

    def test_detects_anyCredentials(self):
        self.content_type = "application/xml"
        self.body = '<auth '\
                    'xmlns="http://docs.openstack.org/identity/api/v2.0">'\
                    '<anyCredentials/></auth>'
        self.assertEquals(utils.detect_credential_type(self),
                          "anyCredentials")

    def test_detects_anyCredentials_json(self):
        self.content_type = "application/json"
        self.body = json.dumps({'auth': {'anyCredentials': {}}})
        self.assertEquals(utils.detect_credential_type(self),
                          "anyCredentials")

    def test_detects_anyUnwrappedCredentials_json(self):
        self.content_type = "application/json"
        self.body = json.dumps({'anyCredentials': {}})
        self.assertEquals(utils.detect_credential_type(self),
                          "anyCredentials")

    def test_detects_anyCredentials_with_tenant_json(self):
        self.content_type = "application/json"
        self.body = json.dumps({'auth': {'tenantId': '1000',
                                         'anyCredentials': {}}})
        self.assertEquals(utils.detect_credential_type(self),
                          "anyCredentials")

    def test_detects_skips_tenant_json(self):
        self.content_type = "application/json"
        self.body = json.dumps({'auth': {'tenantId': '1000'}})
        self.assertRaises(Exception, utils.detect_credential_type, self)

        self.body = json.dumps({'auth': {'tenantName': '1000'}})
        self.assertRaises(Exception, utils.detect_credential_type, self)


if __name__ == '__main__':
    unittest.main()
