import unittest2 as unittest
from common import KeystoneTestCase


class TestExtensions(KeystoneTestCase):
    def test_extensions_json(self):
        r = self.service_request(path='/extensions.json',
            assert_status=200)
        self.assertTrue('json' in r.getheader('Content-Type'))
        content = r.json
        self.assertIsNotNone(content['extensions'])
        self.assertIsNotNone(content['extensions']['values'])
        found = False
        for value in content['extensions']['values']:
            if value['alias'] == 'RAX-KEY':
                found = True
                break
        self.assertTrue(found)

    def test_extensions_xml(self):
        r = self.service_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))
        content = r.xml
        extension = content.find("*[@alias='RAX-KEY']")
        self.assertIsNotNone(extension)


if __name__ == '__main__':
    unittest.main()
