import json
from lxml import etree
import unittest2 as unittest

from keystone.models import Service
from keystone.test import utils as testutils


class TestModelsService(unittest.TestCase):
    '''Unit tests for keystone/models.py:Service class.'''

    def test_service(self):
        service = Service()
        self.assertEquals(str(service.__class__),
                          "<class 'keystone.models.Service'>",
                          "service should be of instance "
                          "class keystone.models.Service but instead "
                          "was '%s'" % str(service.__class__))
        self.assertIsInstance(service, dict, "")

    def test_service_static_properties(self):
        service = Service(id=1, name="the service", blank=None)
        self.assertEquals(service.id, 1)
        self.assertEquals(service.name, "the service")
        try:
            x = service.some_bad_property
        except AttributeError:
            pass
        except:
            self.assert_(False, "Invalid attribute on service should fail")

    def test_service_properties(self):
        service = Service(id=1, name="the service", blank=None)
        service["dynamic"] = "test"
        self.assertEquals(service["dynamic"], "test")

    def test_service_json_serialization(self):
        service = Service(id=1, name="the service", blank=None)
        service["dynamic"] = "test"
        json_str = service.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"service": {"name": "the service", \
                          "id": 1, "dynamic": "test"}}')
        self.assertEquals(d1, d2)

    def test_service_xml_serialization(self):
        service = Service(id=1, name="the service", blank=None)
        xml_str = service.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                    '<service id="1" name="the service" />'))

    def test_service_json_deserialization(self):
        service = Service.from_json('{"name": "the service", "id": 1}',
                            hints={
                                "contract_attributes": ['id', 'name'],
                                "types": [("id", int)]})
        self.assertIsInstance(service, Service)
        self.assertEquals(service.id, 1)
        self.assertEquals(service.name, "the service")

    def test_service_xml_deserialization(self):
        service = Service(id=1, name="the service", blank=None)
        self.assertIsInstance(service, Service)

    def test_service_inspection(self):
        service = Service(id=1, name="the service", blank=None)
        self.assertIsNone(service.inspect())

    def test_service_validation(self):
        service = Service(id=1, name="the service", blank=None)
        self.assertTrue(service.validate())


if __name__ == '__main__':
    unittest.main()
