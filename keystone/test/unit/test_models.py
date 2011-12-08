import json
from lxml import etree
import unittest2 as unittest

from keystone.models import Resource
from keystone.test import utils as testutils


class TestModels(unittest.TestCase):
    '''Unit tests for keystone/models.py.'''

    def test_resource(self):
        resource = Resource()
        self.assertEquals(str(resource.__class__),
                          "<class 'keystone.models.Resource'>",
                          "Resource should be of instance "
                          "class keystone.models.Resource but instead "
                          "was '%s'" % str(resource.__class__))
        self.assertIsInstance(resource, dict, "")

    def test_resource_static_properties(self):
        resource = Resource(id=1, name="the resource", blank=None)
        self.assertEquals(resource.id, 1)
        self.assertEquals(resource.name, "the resource")
        try:
            x = resource.some_bad_property
        except AttributeError:
            pass
        except:
            self.assert_(False, "Invalid attribute on resource should fail")

    def test_resource_keys(self):
        resource = Resource(id=1, name="the resource", blank=None)
        self.assertEquals(resource.id, 1)
        self.assertEquals(resource['id'], 1)

        self.assertTrue('id' in resource)
        self.assertTrue(hasattr(resource, 'id'))

        resource['dynamic'] = '1'
        self.assertEquals(resource['dynamic'], '1')

        self.assertTrue('dynamic' in resource)

    def test_resource_dynamic_properties(self):
        resource = Resource(id=1, name="the resource", blank=None)
        resource["dynamic"] = "test"
        self.assertEquals(resource["dynamic"], "test")
        self.assertEquals(resource["name"], "the resource")

    def test_resource_json_serialization(self):
        resource = Resource(id=1, name="the resource", blank=None)
        json_str = resource.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"resource": {"name": "the resource", "id": 1}}')
        self.assertEquals(d1, d2)

    def test_resource_xml_serialization(self):
        resource = Resource(id=1, name="the resource", blank=None)
        xml_str = resource.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<resource id="1" name="the resource"/>'))

    def test_resource_xml_deserialization(self):
        resource = Resource.from_xml('<Resource blank="" id="1" \
                                     name="the resource"/>',
                            hints={
                                "contract_attributes": ['id', 'name'],
                                "types": [("id", int)]})
        self.assertIsInstance(resource, Resource)
        self.assertEquals(resource.id, 1)
        self.assertEquals(resource.name, "the resource")

    def test_resource_json_deserialization(self):
        resource = Resource.from_json('{"resource": {"name": "the resource", \
                                      "id": 1}}',
                            hints={
                                "contract_attributes": ['id', 'name'],
                                "types": [("id", int)]})
        self.assertIsInstance(resource, Resource)
        self.assertEquals(resource.id, 1)
        self.assertEquals(resource.name, "the resource")

    def test_resource_inspection(self):
        resource = Resource(id=1, name="the resource", blank=None)
        self.assertIsNone(resource.inspect())

    def test_resource_validation(self):
        resource = Resource(id=1, name="the resource", blank=None)
        self.assertTrue(resource.validate())


if __name__ == '__main__':
    unittest.main()
