import unittest2 as unittest
from keystone.test.functional import common


class TestExtensions(common.FunctionalTestCase):
    def test_extensions_json(self):
        r = self.service_request(path='/extensions.json')
        self.assertTrue('json' in r.getheader('Content-Type'))

    def test_extensions_xml(self):
        r = self.service_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))


class TestAdminExtensions(common.ApiTestCase):
    def test_extensions_json(self):
        r = self.service_request(path='/extensions.json')
        self.assertTrue('json' in r.getheader('Content-Type'))

    def test_extensions_xml(self):
        r = self.service_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))


if __name__ == '__main__':
    unittest.main()
