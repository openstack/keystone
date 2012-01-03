import json
import unittest2 as unittest

from keystone.models import EndpointTemplate
from keystone.test import utils as testutils


class TestModelsEndpointTemplate(unittest.TestCase):
    '''Unit tests for keystone/models.py:EndpointTemplate class.'''

    def test_endpointtemplate(self):
        endpointtemplate = EndpointTemplate()
        self.assertEquals(str(endpointtemplate.__class__),
                          "<class 'keystone.models.EndpointTemplate'>",
                          "endpointtemplate should be of instance "
                          "class keystone.models.EndpointTemplate but instead "
                          "was '%s'" % str(endpointtemplate.__class__))
        self.assertIsInstance(endpointtemplate, dict, "")

    def test_endpointtemplate_static_properties(self):
        endpointtemplate = EndpointTemplate(id=1, name="the endpointtemplate",
                                            enabled=True, blank=None)
        self.assertEquals(endpointtemplate.id, 1)
        self.assertEquals(endpointtemplate.name, "the endpointtemplate")
        self.assertTrue(endpointtemplate.enabled)
        self.assertEquals(endpointtemplate.admin_url, None)
        self.assertRaises(AttributeError, getattr, endpointtemplate,
                          'some_bad_property')

    def test_endpointtemplate_properties(self):
        endpointtemplate = EndpointTemplate(id=1, name="the endpointtemplate",
                                            blank=None)
        endpointtemplate["dynamic"] = "test"
        self.assertEquals(endpointtemplate["dynamic"], "test")

    def test_endpointtemplate_json_serialization(self):
        endpointtemplate = EndpointTemplate(id=1, name="the endpointtemplate",
                                            blank=None)
        endpointtemplate["dynamic"] = "test"
        json_str = endpointtemplate.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"endpointtemplate": {"name": "the endpointtemplate",\
                          "id": 1, "dynamic": "test"}}')
        self.assertDictEqual(d1, d2)

    def test_endpointtemplate_xml_serialization(self):
        endpointtemplate = EndpointTemplate(id=1, name="the endpointtemplate",
                                            blank=None)
        xml_str = endpointtemplate.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<endpointtemplate \
                        name="the endpointtemplate" id="1"/>'))

    def test_endpointtemplate_json_deserialization(self):
        endpointtemplate = EndpointTemplate.from_json('{"name": \
                                    "the endpointtemplate", "id": 1}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(endpointtemplate, EndpointTemplate)
        self.assertEquals(endpointtemplate.id, 1)
        self.assertEquals(endpointtemplate.name, "the endpointtemplate")

    def test_endpointtemplate_xml_deserialization(self):
        endpointtemplate = EndpointTemplate(id=1, name="the endpointtemplate",
                                            blank=None)
        self.assertIsInstance(endpointtemplate, EndpointTemplate)

    def test_endpointtemplate_inspection(self):
        endpointtemplate = EndpointTemplate(id=1, name="the endpointtemplate",
                                            blank=None)
        self.assertFalse(endpointtemplate.inspect())

    def test_endpointtemplate_validation(self):
        endpointtemplate = EndpointTemplate(id=1, name="the endpointtemplate",
                                            blank=None)
        self.assertTrue(endpointtemplate.validate())


if __name__ == '__main__':
    unittest.main()
