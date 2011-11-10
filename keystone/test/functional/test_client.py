import unittest

import keystone.common.exception
import keystone.client
from common import isSsl


class TestAdminClient(unittest.TestCase):
    """
    Quick functional tests for the Keystone HTTP admin client.
    """

    def setUp(self):
        """
        Run before each test.
        """
        cert_file = isSsl()
        self.client = keystone.client.AdminClient("127.0.0.1",
                                                  is_ssl=(cert_file != None),
                                                  cert_file=cert_file,
                                                  admin_name="admin",
                                                  admin_pass="secrete")

    def test_admin_validate_token(self):
        """
        Test that our admin token is valid. (HTTP GET)
        """
        token = self.client.admin_token
        result = self.client.validate_token(token)
        self.assertEquals("admin",
                          result["access"]["user"]["name"])

    def test_admin_check_token(self):
        """
        Test that our admin token is valid. (HTTP HEAD)
        """
        token = self.client.admin_token
        self.assertTrue(self.client.check_token(token))

    def test_admin_validate_token_fail(self):
        """
        Test that validating an invalid token results in None. (HTTP GET)
        """
        token = "bad_token"
        self.assertTrue(self.client.validate_token(token) is None)

    def test_admin_check_token_fail(self):
        """
        Test that checking an invalid token results in False. (HTTP HEAD)
        """
        token = "bad_token"
        self.assertFalse(self.client.check_token(token))

    def test_admin_get_token(self):
        """
        Test that we can generate a token given correct credentials.
        """
        token = self.client.get_token("admin", "secrete")
        self.assertEquals(self.client.admin_token, token)

    def test_admin_get_token_bad_auth(self):
        """
        Test incorrect credentials generates a client error.
        """
        self.assertRaises(keystone.common.exception.ClientError,
            self.client.get_token, "bad_user", "bad_pass")


class TestServiceClient(unittest.TestCase):
    """
    Quick functional tests for the Keystone HTTP service client.
    """

    def setUp(self):
        """
        Run before each test.
        """
        cert_file = isSsl()
        self.client = keystone.client.ServiceClient("127.0.0.1",
                                                    is_ssl=(cert_file != None),
                                                    cert_file=cert_file)

    def test_admin_get_token(self):
        """
        Test that we can generate a token given correct credentials.
        """
        token = self.client.get_token("admin", "secrete")
        self.assertTrue(36, len(token))

    def test_admin_get_token_bad_auth(self):
        """
        Test incorrect credentials generates a client error.
        """
        self.assertRaises(keystone.common.exception.ClientError,
            self.client.get_token, "bad_user", "bad_pass")
