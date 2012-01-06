import json
import unittest2 as unittest

from keystone.models import Tenant
from keystone.test import utils as testutils


class TestModelsTenant(unittest.TestCase):
    '''Unit tests for keystone/models.py:Tenant class.'''

    def test_tenant(self):
        tenant = Tenant()
        self.assertEquals(str(tenant.__class__),
                          "<class 'keystone.models.Tenant'>",
                          "tenant should be of instance "
                          "class keystone.models.Tenant but instead "
                          "was '%s'" % str(tenant.__class__))
        self.assertIsInstance(tenant, dict, "")

    def test_tenant_static_properties(self):
        tenant = Tenant(id=1, name="the tenant", enabled=True, blank=None)
        self.assertEquals(tenant.id, "1")
        self.assertEquals(tenant.name, "the tenant")
        self.assertTrue(tenant.enabled)
        self.assertEquals(tenant.description, None)
        self.assertRaises(AttributeError, getattr, tenant, 'some_bad_property')

    def test_tenant_properties(self):
        tenant = Tenant(id=2, name="the tenant", blank=None)
        tenant["dynamic"] = "test"
        self.assertEquals(tenant["dynamic"], "test")

    def test_tenant_initialization(self):
        tenant = Tenant(id=3, name="the tenant", enabled=True, blank=None)
        self.assertTrue(tenant.enabled)

        tenant = Tenant(id=35, name="the tenant", enabled=0, blank=None)
        self.assertEquals(tenant.enabled, False)

        json_str = tenant.to_json()
        d1 = json.loads(json_str)
        self.assertIn('tenant', d1)
        self.assertIn('enabled', d1['tenant'])
        self.assertEquals(d1['tenant']['enabled'], False)

        tenant = Tenant(id=36, name="the tenant", enabled=False, blank=None)
        self.assertEquals(tenant.enabled, False)

    def test_tenant_json_serialization(self):
        tenant = Tenant(id=3, name="the tenant", enabled=True, blank=None)
        tenant["dynamic"] = "test"
        json_str = tenant.to_json()

        d1 = json.loads(json_str)
        d2 = {"tenant": {"name": "the tenant", "id": "3", "enabled": True,
                         "dynamic": "test"}}
        self.assertDictEqual(d1, d2)

    def test_tenant_xml_serialization(self):
        tenant = Tenant(id=4, name="the tenant", description="X", blank=None)
        xml_str = tenant.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<tenant \
                        xmlns="http://docs.openstack.org/identity/api/v2.0" \
                        id="4" name="the tenant">\
                        <description>X</description></tenant>'))

    def test_resource_json_serialization_mapping(self):
        tenant = Tenant(id=1, name="the tenant", rolegrant_id=12)
        json_str = tenant.to_json(hints={"maps": {"refId": "rolegrant_id", }})
        d1 = json.loads(json_str)
        d2 = {"tenant": {"name": "the tenant", "id": "1", "refId": 12}}
        self.assertDictEqual(d1, d2)

    def test_tenant_json_serialization_types(self):
        tenant = Tenant(id=1, name="the tenant", bool=True, int=5)
        json_str = tenant.to_json(hints={"types":
            [("bool", bool), ("int", int)]})
        d1 = json.loads(json_str)
        d2 = {"tenant": {"name": "the tenant", "id": "1", "bool": True,
                         "int": 5}}
        self.assertDictEqual(d1, d2)

    def test_tenant_xml_serialization_mapping(self):
        tenant = Tenant(id=1, name="the resource", rolegrant_id=12)
        xml_str = tenant.to_xml(hints={"maps": {"refId": "rolegrant_id", }})
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
            '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0"\
                    id="1" name="the resource" refId="12"></tenant>'))

    def test_tenant_json_deserialization(self):
        tenant = Tenant.from_json('{"tenant": {"name": "the tenant",\
                                  "id": 5, "extra": "some data"}}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(tenant, Tenant)
        self.assertEquals(tenant.id, 5)
        self.assertEquals(tenant.name, "the tenant")

    def test_tenant_xml_deserialization(self):
        tenant = Tenant.from_xml('<tenant \
                        xmlns="http://docs.openstack.org/identity/api/v2.0" \
                        enabled="true" id="6" name="the tenant">\
                        <description>qwerty text</description></tenant>',
                            hints={
                                "contract_attributes": ['id', 'name'],
                                "types": [("id", int),
                                    ("description", str)]})
        self.assertIsInstance(tenant, Tenant)
        self.assertEquals(tenant.id, 6)
        self.assertEquals(tenant.name, "the tenant")
        self.assertEquals(tenant.description, "qwerty text")

    def test_tenant_xml_deserialization_hintless(self):
        tenant = Tenant.from_xml('<tenant \
                        xmlns="http://docs.openstack.org/identity/api/v2.0" \
                        enabled="none" id="7" name="the tenant">\
                        <description>qwerty text</description></tenant>')
        self.assertIsInstance(tenant, Tenant)
        self.assertEquals(tenant.id, "7")
        self.assertEquals(tenant.name, "the tenant")
        self.assertEquals(tenant.description, "qwerty text")

    def test_tenant_inspection(self):
        tenant = Tenant(id=8, name="the tenant", blank=None)
        self.assertFalse(tenant.inspect())

    def test_tenant_validation(self):
        tenant = Tenant(id=9, name="the tenant", blank=None)
        self.assertTrue(tenant.validate())

    def test_tenant_description_values(self):
        tenant = Tenant(id=10, name="the tenant")
        self.assertIsNone(tenant.description,
                          "Uninitialized description should be None")
        xml = tenant.to_dom()
        desc = xml.find("{http://docs.openstack.org/identity/api/v2.0}"
                             "description")
        self.assertIsNone(desc,
                          "Uninitialized description should not exist in xml")

        tenant = Tenant(id=10, name="the tenant", description=None)
        self.assertIsNone(tenant.description,
                          "Description initialized to None should be None")
        xml = tenant.to_dom()
        desc = xml.find("{http://docs.openstack.org/identity/api/v2.0}"
                             "description")
        self.assertIsNone(desc,
                          "Uninitialized description should not exist in xml")

        tenant = Tenant(id=10, name="the tenant", description='')
        self.assertEquals(tenant.description, '',
            'Description initialized to empty string should be empty string')
        xml = tenant.to_dom()
        desc = xml.find("description")
        self.assertEquals(desc.text, '',
                          "Blank Description should show as blank tag in xml")

        tenant = Tenant(id=10, name="the tenant", description=None)
        xml = tenant.to_xml(hints={"tags": ["description"]})
        xml = tenant.to_dom()
        desc = xml.find("description")
        self.assertEquals(desc, None,
                          "'None' Description should show as empty tag in xml")


if __name__ == '__main__':
    unittest.main()
