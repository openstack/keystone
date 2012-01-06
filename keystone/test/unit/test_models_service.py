import json
import unittest2 as unittest

from keystone.logic.types import fault
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
        service = Service(id=1, name="the service", type="compute", blank=None)
        self.assertEquals(service.id, "1")
        self.assertEquals(service.name, "the service")
        self.assertRaises(AttributeError, getattr, service,
                          'some_bad_property')

    def test_service_properties(self):
        service = Service(id=1, name="the service", type="compute", blank=None)
        service["dynamic"] = "test"
        self.assertEquals(service["dynamic"], "test")

    def test_service_json_serialization(self):
        service = Service(id=1, name="the service", type="compute", blank=None)
        service["dynamic"] = "test"
        json_str = service.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"OS-KSADM:service": {"name": "the service", \
                          "id": "1", "dynamic": "test", "type": "compute"}}')
        self.assertDictEqual(d1, d2)

    def test_service_xml_serialization(self):
        service = Service(id=1, name="the service", type="compute", blank=None)
        xml_str = service.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                    '<service \
            xmlns="http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0" \
            id="1" name="the service" type="compute"/>'))

    def test_service_json_deserialization(self):
        service = Service.from_json('{"name": "the service", "id": 1,\
                                    "type": "compute"}',
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
        service = Service(id=1, name="the service", type="compute")
        self.assertFalse(service.inspect())

    def test_service_validation_from_json(self):
        self.assertRaises(fault.BadRequestFault, Service.from_json,
                          '{"name": "", "id": 1}')
        self.assertRaises(fault.BadRequestFault, Service.from_json,
                          '{"type": None, "id": 1}')

    def test_service_validation_from_xml(self):
        self.assertRaises(fault.BadRequestFault, Service.from_xml,
                          '<service \
            xmlns="http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0" \
            id="1" name="the service" type=""/>')
        self.assertRaises(fault.BadRequestFault, Service.from_xml,
                          '<service \
            xmlns="http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0" \
            id="1" name="" type="compute"/>')

    def test_service_validation(self):
        service = Service(id=1, name="the service", type="compute")
        self.assertTrue(service.validate())


if __name__ == '__main__':
    unittest.main()
