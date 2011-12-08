import json
from lxml import etree
import unittest2 as unittest

from keystone.models import Role
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
        role = Role(id=1, name="the role", enabled=True, blank=None)
        self.assertEquals(role.id, 1)
        self.assertEquals(role.name, "the role")
        self.assertTrue(role.enabled)
        self.assertEquals(role.description, None)
        try:
            x = role.some_bad_property
        except AttributeError:
            pass
        except:
            self.assert_(False, "Invalid attribute on role should fail")

    def test_role_properties(self):
        role = Role(id=1, name="the role", blank=None)
        role["dynamic"] = "test"
        self.assertEquals(role["dynamic"], "test")

    def test_role_json_serialization(self):
        role = Role(id=1, name="the role", blank=None)
        role["dynamic"] = "test"
        json_str = role.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"role": {"name": "the role", \
                          "id": 1, "dynamic": "test"}}')
        self.assertEquals(d1, d2)

    def test_role_xml_serialization(self):
        role = Role(id=1, name="the role", blank=None)
        xml_str = role.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<role id="1" name="the role"/>'))

    def test_role_json_deserialization(self):
        role = Role.from_json('{"name": "the role", "id": 1}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(role, Role)
        self.assertEquals(role.id, 1)
        self.assertEquals(role.name, "the role")

    def test_role_xml_deserialization(self):
        role = Role(id=1, name="the role", blank=None)
        self.assertIsInstance(role, Role)

    def test_role_inspection(self):
        role = Role(id=1, name="the role", blank=None)
        self.assertIsNone(role.inspect())

    def test_role_validation(self):
        role = Role(id=1, name="the role", blank=None)
        self.assertTrue(role.validate())


if __name__ == '__main__':
    unittest.main()
