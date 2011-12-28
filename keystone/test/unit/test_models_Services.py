import json
import unittest2 as unittest

from keystone.logic.types import fault
from keystone.models import Service, Services
from keystone.test import utils as testutils


class TestModelsServices(unittest.TestCase):
    '''Unit tests for keystone/models.py:Service class.'''

    def test_services(self):
        services = Services(None, None)
        self.assertEquals(str(services.__class__),
                          "<class 'keystone.models.Services'>",
                          "services should be of instance "
                          "class keystone.models.Services but instead "
                          "was '%s'" % str(services.__class__))

    def test_xml_serialization(self):
        service_list = [Service(name="keystone", type="identity"),
                        Service(name="nova", type="compute"),
                        Service(name="glance", type="image-service")]
        services = Services(service_list, {})
        xml_str = services.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                '<services xmlns="http://docs.openstack.org/identity/api/ext/\
OS-KSADM/v1.0"><service xmlns="http://docs.openstack.org/identity/api/ext/\
OS-KSADM/v1.0" type="identity" name="keystone"/><service xmlns="http://\
docs.openstack.org/identity/api/ext/OS-KSADM/v1.0" type="compute" name="nova"\
/><service xmlns="http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0" \
type="image-service" name="glance"/></services>'))

    def test_json_serialization(self):
        service_list = [Service(name="keystone", type="identity"),
                        Service(name="nova", type="compute"),
                        Service(name="glance", type="image-service")]
        services = Services(service_list, {})
        json_str = services.to_json()
        self.assertEqual(json_str,
                '{"OS-KSADM:services": [{"type": "identity", "name": \
"keystone"}, {"type": "compute", "name": "nova"}, {"type": "image-service", \
"name": "glance"}], "OS-KSADM:services_links": []}')


if __name__ == '__main__':
    unittest.main()
