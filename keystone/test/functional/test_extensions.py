import unittest
from common import KeystoneTestCase


class TestExtensions(KeystoneTestCase):
    def test_extensions_json(self):
        r = self.service_request(path='/extensions.json')
        self.assertTrue('json' in r.getheader('Content-Type'))

    def test_extensions_xml(self):
        r = self.service_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))


class TestAdminExtensions(KeystoneTestCase):
    def test_extensions_json(self):
        r = self.admin_request(path='/extensions.json')
        self.assertTrue('json' in r.getheader('Content-Type'))

    def test_extensions_xml(self):
        r = self.admin_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))


if __name__ == '__main__':
    unittest.main()
