import json
import unittest2 as unittest
import keystone.logic.types.auth as auth
import keystone.logic.types.fault as fault


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
        self.assertEqual(creds.password, "secret")
        self.assertEqual(creds.username, "disabled")

    def test_pwd_creds_from_json(self):
        data = json.dumps({"auth":
                               {"passwordCredentials":
                                    {"username": "foo", "password": "bar"}}})
        creds = auth.AuthWithPasswordCredentials.from_json(data)
        self.assertEqual(creds.username, "foo")
        self.assertEqual(creds.password, "bar")
        self.assertIsNone(creds.tenant_id)
        self.assertIsNone(creds.tenant_name)

    def test_pwd_creds_with_tenant_name_from_json(self):
        data = json.dumps({"auth":
                               {"tenantName": "blaa",
                                "passwordCredentials":
                                    {"username": "foo", "password": "bar"}}})
        creds = auth.AuthWithPasswordCredentials.from_json(data)
        self.assertEqual(creds.username, "foo")
        self.assertEqual(creds.password, "bar")
        self.assertIsNone(creds.tenant_id)
        self.assertEqual(creds.tenant_name, "blaa")

    def test_pwd_creds_with_tenant_id_from_json(self):
        data = json.dumps({"auth":
                               {"tenantId": "blaa",
                                "passwordCredentials":
                                    {"username": "foo", "password": "bar"}}})
        creds = auth.AuthWithPasswordCredentials.from_json(data)
        self.assertEqual(creds.username, "foo")
        self.assertEqual(creds.password, "bar")
        self.assertEqual(creds.tenant_id, "blaa")
        self.assertIsNone(creds.tenant_name)

    def test_pwd_not_both_tenant_from_json(self):
        data = json.dumps({"auth": {"tenantId": "blaa", "tenantName": "aalb"}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "not both",
                                auth.AuthWithPasswordCredentials.from_json,
                                data)

    def test_pwd_invalid_from_json(self):
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Cannot parse",
                                auth.AuthWithPasswordCredentials.from_json,
                                "")

    def test_pwd_no_auth_from_json(self):
        data = json.dumps({"foo": "bar"})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Expecting auth",
                                auth.AuthWithPasswordCredentials.from_json,
                                data)

    def test_pwd_no_creds_from_json(self):
        data = json.dumps({"auth": {}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Expecting passwordCredentials",
                                auth.AuthWithPasswordCredentials.from_json,
                                data)

    def test_pwd_invalid_attribute_from_json(self):
        data = json.dumps({"auth": {"foo": "bar"}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Invalid",
                                auth.AuthWithPasswordCredentials.from_json,
                                data)

    def test_pwd_no_username_from_json(self):
        data = json.dumps({"auth": {"passwordCredentials": {}}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Expecting passwordCredentials:username",
                                auth.AuthWithPasswordCredentials.from_json,
                                data)

    def test_pwd_no_password_from_json(self):
        data = json.dumps({"auth": {"passwordCredentials":
                                        {"username": "foo"}}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Expecting passwordCredentials:password",
                                auth.AuthWithPasswordCredentials.from_json,
                                data)

    def test_pwd_invalid_creds_attribute_from_json(self):
        data = json.dumps({"auth": {"passwordCredentials": {"bar": "foo"}}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Invalid",
                                auth.AuthWithPasswordCredentials.from_json,
                                data)

    def test_token_creds_from_json(self):
        data = json.dumps({"auth": {"token": {"id": "1"}}})
        creds = auth.AuthWithUnscopedToken.from_json(data)
        self.assertEqual(creds.token_id, "1")
        self.assertIsNone(creds.tenant_id)
        self.assertIsNone(creds.tenant_name)

    def test_token_creds_with_tenant_name_from_json(self):
        data = json.dumps({"auth":
                               {"tenantName": "blaa",
                                "token": {"id": "1"}}})
        creds = auth.AuthWithUnscopedToken.from_json(data)
        self.assertEqual(creds.token_id, "1")
        self.assertIsNone(creds.tenant_id)
        self.assertEqual(creds.tenant_name, "blaa")

    def test_token_creds_with_tenant_id_from_json(self):
        data = json.dumps({"auth":
                               {"tenantId": "blaa",
                                "token": {"id": "1"}}})
        creds = auth.AuthWithUnscopedToken.from_json(data)
        self.assertEqual(creds.token_id, "1")
        self.assertEqual(creds.tenant_id, "blaa")
        self.assertIsNone(creds.tenant_name)

    def test_token_not_both_tenant_from_json(self):
        data = json.dumps({"auth":
                               {"tenantId": "blaa",
                                "tenantName": "aalb",
                                "token": {"id": "1"}}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "not both",
                                auth.AuthWithUnscopedToken.from_json,
                                data)

    def test_token_invalid_from_json(self):
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Cannot parse",
                                auth.AuthWithUnscopedToken.from_json,
                                "")

    def test_token_no_auth_from_json(self):
        data = json.dumps({"foo": "bar"})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Expecting auth",
                                auth.AuthWithUnscopedToken.from_json,
                                data)

    def test_token_no_creds_from_json(self):
        data = json.dumps({"auth": {}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Expecting token",
                                auth.AuthWithUnscopedToken.from_json,
                                data)

    def test_token_invalid_attribute_from_json(self):
        data = json.dumps({"auth": {"foo": "bar"}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Invalid",
                                auth.AuthWithUnscopedToken.from_json,
                                data)

    def test_token_no_id_from_json(self):
        data = json.dumps({"auth": {"token": {}}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Expecting token:id",
                                auth.AuthWithUnscopedToken.from_json,
                                data)

    def test_token_invalid_token_attribute_from_json(self):
        data = json.dumps({"auth": {"token": {"bar": "foo"}}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                                "Invalid",
                                auth.AuthWithUnscopedToken.from_json,
                                data)

if __name__ == '__main__':
    unittest.main()
