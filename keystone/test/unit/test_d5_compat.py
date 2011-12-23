import json
import unittest2 as unittest
from keystone.frontends import d5_compat
import keystone.logic.types.fault as fault


class TestD5Auth(unittest.TestCase):
    """Test to make sure Keystone honors the 'unofficial' D5 API contract.

    The main differences were:
        - POST /v2.0/tokens without the "auth" wrapper
        - POST /v2.0/tokens with tenantId in the passwordCredentials object
          (instead of the auth wrapper)
        - Response for validate token was wrapped in "auth"

    TODO(zns): deprecate this once we move to the next version of the API
    """

    pwd_xml = '<?xml version="1.0" encoding="UTF-8"?>\
                <passwordCredentials\
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secret" username="disabled" \
                />'

    def test_pwd_cred_marshall(self):
        creds = d5_compat.D5AuthWithPasswordCredentials.from_xml(self.pwd_xml)
        self.assertEqual(creds.password, "secret")
        self.assertEqual(creds.username, "disabled")

    def test_pwd_creds_from_json(self):
        data = json.dumps({"passwordCredentials":
                                {"username": "foo", "password": "bar"}})
        creds = d5_compat.D5AuthWithPasswordCredentials.from_json(data)
        self.assertEqual(creds.username, "foo")
        self.assertEqual(creds.password, "bar")
        self.assertIsNone(creds.tenant_id)
        self.assertIsNone(creds.tenant_name)

    def test_pwd_creds_with_tenant_name_from_json(self):
        data = json.dumps({"passwordCredentials":
                                {"tenantName": "blaa", "username": "foo",
                                 "password": "bar"}})
        creds = d5_compat.D5AuthWithPasswordCredentials.from_json(data)
        self.assertEqual(creds.username, "foo")
        self.assertEqual(creds.password, "bar")
        self.assertIsNone(creds.tenant_id)
        self.assertEqual(creds.tenant_name, "blaa")

    def test_pwd_creds_with_tenant_id_from_json(self):
        data = json.dumps({"passwordCredentials":
                                {"tenantId": "blaa", "username": "foo",
                                 "password": "bar"}})
        creds = d5_compat.D5AuthWithPasswordCredentials.from_json(data)
        self.assertEqual(creds.username, "foo")
        self.assertEqual(creds.password, "bar")
        self.assertEqual(creds.tenant_id, "blaa")
        self.assertIsNone(creds.tenant_name)

    def test_pwd_not_both_tenant_from_json(self):
        data = json.dumps({"tenantId": "blaa", "tenantName": "aalb"})
        self.assertRaisesRegexp(fault.BadRequestFault,
                            "Expecting passwordCredentials",
                            d5_compat.D5AuthWithPasswordCredentials.from_json,
                            data)

    def test_pwd_no_creds_from_json(self):
        data = json.dumps({"auth": {}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                            "Expecting passwordCredentials",
                            d5_compat.D5AuthWithPasswordCredentials.from_json,
                            data)

    def test_pwd_invalid_attribute_from_json(self):
        data = json.dumps({"passwordCredentials": {"foo": "bar"}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                            "Invalid",
                            d5_compat.D5AuthWithPasswordCredentials.from_json,
                            data)

    def test_pwd_no_username_from_json(self):
        data = json.dumps({"passwordCredentials": {}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                            "Expecting passwordCredentials:username",
                            d5_compat.D5AuthWithPasswordCredentials.from_json,
                            data)

    def test_pwd_no_password_from_json(self):
        data = json.dumps({"passwordCredentials":
                                        {"username": "foo"}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                            "Expecting passwordCredentials:password",
                            d5_compat.D5AuthWithPasswordCredentials.from_json,
                            data)

    def test_pwd_invalid_creds_attribute_from_json(self):
        data = json.dumps({"passwordCredentials": {"bar": "foo"}})
        self.assertRaisesRegexp(fault.BadRequestFault,
                            "Invalid",
                            d5_compat.D5AuthWithPasswordCredentials.from_json,
                            data)

    def test_json_pwd_creds_from_D5(self):
        D5_data = json.dumps({"passwordCredentials":
                                {"username": "foo", "password": "bar"}})
        diablo_data = json.dumps({"auth": {"passwordCredentials":
                                {"username": "foo", "password": "bar"}}})
        creds = d5_compat.D5AuthWithPasswordCredentials.from_json(D5_data)
        diablo = creds.to_json()
        self.assertEquals(diablo, diablo_data)

    def test_json_authdata_from_D5(self):
        pass

    def test_json_validatedata_from_D5(self):
        diablo_data = {
            "access": {
                "token": {
                    "expires": "2011-12-07T21:31:49.215675",
                    "id": "92c8962a-7e9b-40d1-83eb-a2f3b6eb45c3"
                },
                "user": {
                    "id": "3",
                    "name": "admin",
                    "roles": [
                        {
                            "id": "1",
                            "name": "Admin"
                        }
                    ],
                    "username": "admin"
                }
            }
        }
        D5_data = {"auth": {
                "token": {
                    "expires": "2011-12-07T21:31:49.215675",
                    "id": "92c8962a-7e9b-40d1-83eb-a2f3b6eb45c3"
                },
                "user": {
                    "roleRefs": [
                        {
                            "id": "1",
                            "roleId": "Admin"
                        }
                    ],
                    "username": "admin"
                }
            }
        }
        creds = d5_compat.D5ValidateData.from_json(json.dumps(diablo_data))
        D5 = json.loads(creds.to_json())
        self.assertEquals(diablo_data['access'], D5['access'],
                      "D5 compat response must contain Diablo format")
        self.assertEquals(D5_data['auth'], D5['auth'],
                      "D5 compat response must contain D5 format")

    def test_no_catalog_in_response(self):
        minimal_response = {
            "access": {
                "token": {
                    "expires": "2011-12-07T21:31:49.215675",
                    "id": "92c8962a-7e9b-40d1-83eb-a2f3b6eb45c3"
                },
                "user": {
                    "id": "3",
                    "name": "admin",
                }
            }
        }
        d5 = d5_compat.D5toDiabloAuthData(init_json=minimal_response)
        self.assertTrue(d5.to_json())

if __name__ == '__main__':
    unittest.main()
