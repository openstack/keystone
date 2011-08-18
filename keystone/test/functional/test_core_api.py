import unittest
from keystone.test.functional import common
from keystone import manage


class TestCoreServiceApi(common.KeystoneTestCase):
    """Tests core Keystone Service API"""

    user = None

    def setUp(self):
        self.user = common.KeystoneTestCase._uuid()
        # manage.parse_args(['--config-file=etc/keystone.conf'])
        # manage.api.add_user(self.user, 'awe4tya46')

    def tearDown(self):
        pass

    def testPostTokens(self):
        pass

    def testGetTenantsRequiresAuthentication(self):
        pass

    def testAuthenticateWithoutTenant(self):
        pass

    def testAuthenticateWithTenant(self):
        pass

    def testAuthenticateWithManyTenants(self):
        pass


class TestCoreAdminApi(common.KeystoneTestCase):
    """Tests core Keystone Service API"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testName(self):
        pass


if __name__ == "__main__":
    unittest.main()
