import unittest2 as unittest
from keystone.test.functional import common


class TestExtensions(common.ApiTestCase):
    def test_extensions_json(self):
        r = self.service_request(path='/extensions.json',
            assert_status=200)
        self.assertTrue('json' in r.getheader('Content-Type'))
        content = r.json
        self.assertIsNotNone(content['extensions'])
        self.assertIsNotNone(content['extensions']['values'])
        found = False
        for value in content['extensions']['values']:
            if value['extension']['alias'] == 'RAX-KSKEY':
                found = True
                break
        self.assertTrue(found)

    def test_extensions_xml(self):
        r = self.service_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))
        content = r.xml
        extension = content.find(
            "{http://docs.openstack.org/common/api/v1.0}extension")
        self.assertEqual(extension.get("alias"), "RAX-KSKEY")


if __name__ == '__main__':
    unittest.main()
