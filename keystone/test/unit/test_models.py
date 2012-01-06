import json
import unittest2 as unittest

from keystone.models import AttrDict, Resource
from keystone.test import utils as testutils


class TestModels(unittest.TestCase):
    '''Unit tests for keystone/models.py.'''

    def test_attrdict_class(self):
        ad = AttrDict()
        ad.id = 1
        self.assertEqual(ad.id, 1)
        ad._sa_instance_state = AttrDict()
        self.assertIsInstance(ad._sa_instance_state, AttrDict)

    def test_resource(self):
        resource = Resource()
        self.assertEquals(str(resource.__class__),
                          "<class 'keystone.models.Resource'>",
                          "Resource should be of instance "
                          "class keystone.models.Resource but instead "
                          "was '%s'" % str(resource.__class__))
        self.assertIsInstance(resource, dict, "")
        resource._sa_instance_state = AttrDict()
        self.assertIsInstance(resource._sa_instance_state, AttrDict)

    def test_resource_respresentation(self):
        resource = Resource(id=1, name="John")
        self.assertIn(resource.__repr__(), [
                    "<Resource(id=1, name='John')>",
                    "<Resource(name='John', id=1)>"])
        self.assertIn(resource.__str__(), [
                    "{'resource': {'name': 'John', 'id': 1}}",
                    "{'resource': {'id': 1, 'name': 'John'}}"])
        self.assertEqual(resource['resource']['id'], 1)

    def test_resource_static_properties(self):
        resource = Resource(id=1, name="the resource", blank=None)
        self.assertEquals(resource.id, 1)
        self.assertEquals(resource.name, "the resource")
        self.assertRaises(AttributeError, getattr, resource,
                          'some_bad_property')

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
        self.assertDictEqual(d1, d2)

    def test_resource_json_serialization_mapping(self):
        resource = Resource(id=1, name="the resource", rolegrant_id=12)
        json_str = resource.to_json(hints={"maps": {"refId": "rolegrant_id",
                                                    }})
        d1 = json.loads(json_str)
        d2 = {"resource": {"name": "the resource", "id": 1, "refId": 12}}
        self.assertDictEqual(d1, d2)

    def test_resource_json_serialization_types(self):
        resource = Resource(id=1, name="the resource", bool=True, int=5)
        json_str = resource.to_json(hints={"types":
            [("bool", bool), ("int", int)]})
        d1 = json.loads(json_str)
        d2 = {"resource": {"name": "the resource", "id": 1, "bool": True,
                           "int": 5}}
        self.assertDictEqual(d1, d2)

    def test_resource_xml_serialization(self):
        resource = Resource(id=1, name="the resource", blank=None)
        xml_str = resource.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<resource id="1" name="the resource"/>'))

    def test_resource_xml_serialization_mapping(self):
        resource = Resource(id=1, name="the resource", rolegrant_id=12)
        xml_str = resource.to_xml(hints={"maps": {"refId": "rolegrant_id", }})
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<resource id="1" name="the resource" refId="12"/>'))

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
        self.assertFalse(resource.inspect())

    def test_resource_validation(self):
        resource = Resource(id=1, name="the resource", blank=None)
        self.assertTrue(resource.validate())


if __name__ == '__main__':
    unittest.main()
