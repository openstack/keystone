import datetime as dt
import unittest2 as unittest

import keystone.logic.service as service
from keystone.test.unit.base import ServiceAPITest, AdminAPITest
from keystone.logic.types.fault import ItemNotFoundFault, UnauthorizedFault
from keystone.logic.types.auth import ValidateData


class TestServiceLogic(AdminAPITest):
    """Unit tests for logic/service.py."""
    def __init__(self, *args, **kwargs):
        super(TestServiceLogic, self).__init__(*args, **kwargs)
        self.api_class = service.IdentityService

    def setUp(self):
        super(TestServiceLogic, self).setUp()
        user_attrs = {'id': 'test_user',
                'password': 'test_pass',
                'email': 'test_user@example.com',
                'enabled': True,
                'tenant_id': 'tenant1'}
        self.test_user = self.fixture_create_user(**user_attrs)

    def test_get_user(self):
        user_id = self.test_user["id"]
        user = self.api.get_user(self.admin_token_id, user_id)
        # The returned user object is a different type:
        #   keystone.logic.types.user.User_Update
        self.assertEqual(self.test_user["email"], user.email)
        self.assertEqual(self.test_user["enabled"], user.enabled)
        self.assertEqual(self.test_user["id"], user.id)
        self.assertEqual(self.test_user["tenant_id"], user.tenant_id)

    def test_require_admin(self):
        user_id = self.test_user["id"]
        self.assertRaises(UnauthorizedFault, self.api.get_user,
                self.auth_token_id, user_id)

    def test_require_service_admin(self):
        self.assertRaises(UnauthorizedFault, self.api.validate_token,
                self.auth_token_id, "any_id")

    def test_has_admin_role(self):
        self.assertTrue(self.api.has_admin_role(self.admin_token_id))
        self.assertFalse(self.api.has_admin_role(self.auth_token_id))

    def test_validate_token(self):
        data = self.api.validate_token(self.admin_token_id, self.auth_token_id)
        self.assertTrue(isinstance(data, ValidateData))

    def test_remove_role_from_user(self):
        auth_userid = self.auth_user["id"]
        regular_role_id = self.role_fixtures[0]["id"]
        admin_role_id = self.role_fixtures[1]["id"]
        # Attempting to remove the admin role should raise an error.
        self.assertRaises(ItemNotFoundFault, self.api.remove_role_from_user,
                self.admin_token_id, auth_userid, admin_role_id)
        # This should run without error
        self.api.remove_role_from_user(self.admin_token_id,
                auth_userid, regular_role_id)


if __name__ == '__main__':
    unittest.main()
