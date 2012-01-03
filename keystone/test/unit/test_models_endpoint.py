import json
import unittest2 as unittest

from keystone.models import Endpoint
from keystone.test import utils as testutils


class TestModelsEndpoint(unittest.TestCase):
    '''Unit tests for keystone/models.py:Endpoint class.'''

    def test_endpoint(self):
        endpoint = Endpoint()
        self.assertEquals(str(endpoint.__class__),
                          "<class 'keystone.models.Endpoint'>",
                          "endpoint should be of instance "
                          "class keystone.models.Endpoint but instead "
                          "was '%s'" % str(endpoint.__class__))
        self.assertIsInstance(endpoint, dict, "")

    def test_endpoint_static_properties(self):
        endpoint = Endpoint(id=1, name="the endpoint", enabled=True,
                            blank=None)
        self.assertEquals(endpoint.id, 1)
        self.assertEquals(endpoint.name, "the endpoint")
        self.assertTrue(endpoint.enabled)
        self.assertRaises(AttributeError, getattr, endpoint,
                          'some_bad_property')

    def test_endpoint_properties(self):
        endpoint = Endpoint(id=2, name="the endpoint", blank=None)
        endpoint["dynamic"] = "test"
        self.assertEquals(endpoint["dynamic"], "test")

    def test_endpoint_json_serialization(self):
        endpoint = Endpoint(id=3, name="the endpoint", blank=None)
        endpoint["dynamic"] = "test"
        json_str = endpoint.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"endpoint": {"name": "the endpoint", \
                          "id": 3, "dynamic": "test"}}')
        self.assertDictEqual(d1, d2)

    def test_endpoint_xml_serialization(self):
        endpoint = Endpoint(id=4, name="the endpoint", blank=None)
        xml_str = endpoint.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<endpoint name="the endpoint" id="4"/>'))

    def test_endpoint_json_deserialization(self):
        endpoint = Endpoint.from_json('{"name": "the endpoint", "id": 5}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(endpoint, Endpoint)
        self.assertEquals(endpoint.id, 5)
        self.assertEquals(endpoint.name, "the endpoint")

    def test_endpoint_json_deserialization_rootless(self):
        endpoint = Endpoint.from_json('{"endpoint": {"name": "the endpoint", \
                                      "id": 6}}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(endpoint, Endpoint)
        self.assertEquals(endpoint.id, 6)
        self.assertEquals(endpoint.name, "the endpoint")

    def test_endpoint_xml_deserialization(self):
        endpoint = Endpoint(id=7, name="the endpoint", blank=None)
        self.assertIsInstance(endpoint, Endpoint)

    def test_endpoint_inspection(self):
        endpoint = Endpoint(id=8, name="the endpoint", blank=None)
        self.assertFalse(endpoint.inspect())

    def test_endpoint_validation(self):
        endpoint = Endpoint(id=9, name="the endpoint", blank=None)
        self.assertTrue(endpoint.validate())


if __name__ == '__main__':
    unittest.main()
