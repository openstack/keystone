import json
import unittest2 as unittest

from keystone.models import Role, UserRoleAssociation
from keystone.test import utils as testutils


class TestModelsRole(unittest.TestCase):
    '''Unit tests for keystone/models.py:Role class.'''

    def test_role(self):
        role = Role()
        self.assertEquals(str(role.__class__),
                          "<class 'keystone.models.Role'>",
                          "role should be of instance "
                          "class keystone.models.Role but instead "
                          "was '%s'" % str(role.__class__))
        self.assertIsInstance(role, dict, "")

    def test_role_static_properties(self):
        role = Role(id=1, name="the role", service_id=1, blank=None)
        self.assertEquals(role.id, "1")
        self.assertEquals(role.name, "the role")
        self.assertEquals(role.service_id, "1")
        self.assertEquals(role.description, None)
        self.assertRaises(AttributeError, getattr, role,
                          'some_bad_property')

    def test_role_properties(self):
        role = Role(id=1, name="the role", blank=None)
        role["dynamic"] = "test"
        self.assertEquals(role["dynamic"], "test")

    def test_role_json_serialization(self):
        role = Role(id=1, name="the role", blank=None)
        role["dynamic"] = "test"
        json_str = role.to_json()
        d1 = json.loads(json_str)
        d2 = {"role": {"name": "the role", "id": "1", "dynamic": "test"}}
        self.assertDictEqual(d1, d2)

    def test_role_json_serialization_mapped(self):
        role = Role(id=1, name="the role",
                    service_id="s1",
                    tenant_id="t1")
        json_str = role.to_json()
        d1 = json.loads(json_str)
        d2 = {"role": {"name": "the role", "id": "1", "serviceId": "s1",
                       "tenantId": "t1"}}
        self.assertDictEqual(d1, d2)

    def test_role_xml_serialization(self):
        role = Role(id=1, name="the role", blank=None)
        xml_str = role.to_xml()
        expected = ('<role xmlns="http://docs.openstack.org/identity/api/v2.0"'
                    ' id="1" name="the role"/>')
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str, expected),
                        msg='%s != %s' % (xml_str, expected))

    def test_role_xml_serialization_mapping(self):
        role = Role(id=1, name="the role",
                    service_id="s1",
                    tenant_id="t1")
        xml_str = role.to_xml()
        expected = ('<role xmlns="http://docs.openstack.org/identity/api/v2.0"'
                    ' id="1" name="the role" serviceId="s1" tenantId="t1"/>')
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str, expected),
                msg='%s != %s' % (xml_str,
                    expected))
        self.assertEquals(role.service_id, "s1")

    def test_role_json_deserialization(self):
        role = Role.from_json('{"name": "the role", "id": "1"}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(role, Role)
        self.assertEquals(role.id, "1")
        self.assertEquals(role.name, "the role")

        role = Role.from_json('{"role":{"name": "r1", "serviceId": "s1"}}')
        self.assertEquals(role.service_id, "s1")

    def test_role_json_deserialization_types(self):
        role = Role.from_json('{"name": "the role", "id": 1}')
        self.assertIsInstance(role, Role)
        self.assertEquals(role.id, "1",
                          "'id' should always be returned as a string")
        self.assertEquals(role.name, "the role")

    def test_role_xml_deserialization(self):
        role = Role(id=1, name="the role", blank=None)
        self.assertIsInstance(role, Role)

    def test_role_inspection(self):
        role = Role(id=1, name="the role", blank=None)
        self.assertFalse(role.inspect())

    def test_role_validation(self):
        role = Role(id=1, name="the role", blank=None)
        self.assertTrue(role.validate())

    #
    # UserRoleAssociation
    #
    def test_userroleassociation_json_serialization_mapped(self):
        ura = UserRoleAssociation(id=1, role_id=1, user_id="u1",
                    tenant_id="t1")
        json_str = ura.to_json()
        d1 = json.loads(json_str)
        d2 = {"role": {"id": 1, "roleId": 1, "userId": "u1",
                       "tenantId": "t1"}}
        self.assertDictEqual(d1, d2)


if __name__ == '__main__':
    unittest.main()
