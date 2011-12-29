import os
import unittest2 as unittest
from keystone.test.functional import common


class TestExtensions(common.FunctionalTestCase):
    use_server = True

    def test_extensions_json(self):
        r = self.service_request(path='/extensions.json')
        self.assertTrue('json' in r.getheader('Content-Type'))
        content = r.json
        self.assertIsNotNone(content['extensions'])
        self.assertIsNotNone(content['extensions']['values'])

    def test_extensions_xml(self):
        r = self.service_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))


class TestAdminExtensions(common.ApiTestCase):
    use_server = True

    def test_extensions_json(self):
        r = self.admin_request(path='/extensions.json')
        self.assertTrue('json' in r.getheader('Content-Type'))
        content = r.json
        self.assertIsNotNone(content['extensions'])
        self.assertIsNotNone(content['extensions']['values'])
        found_osksadm = False
        found_oskscatalog = False
        found_hpidm = False
        for value in content['extensions']['values']:
            if value['extension']['alias'] == 'OS-KSADM':
                found_osksadm = True
            if value['extension']['alias'] == 'OS-KSCATALOG':
                found_oskscatalog = True
            if value['extension']['alias'] == 'HP-IDM':
                found_hpidm = True
        self.assertTrue(found_osksadm, "Missing OS-KSADM extension.")
        self.assertTrue(found_oskscatalog, "Missing OS-KSCATALOG extension.")
        if not common.isSsl() and 'HP-IDM_Disabled' not in os.environ:
            self.assertTrue(found_hpidm, "Missing HP-IDM extension.")

    def test_extensions_xml(self):
        r = self.admin_request(path='/extensions.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))
        content = r.xml
        extensions = content.findall(
            "{http://docs.openstack.org/common/api/v1.0}extension")
        found_osksadm = False
        found_oskscatalog = False
        found_hpidm = False
        for extension in extensions:
            if extension.get("alias") == 'OS-KSADM':
                found_osksadm = True
            if extension.get("alias") == 'OS-KSCATALOG':
                found_oskscatalog = True
            if extension.get("alias") == 'HP-IDM':
                found_hpidm = True
        self.assertTrue(found_osksadm, "Missing OS-KSADM extension.")
        self.assertTrue(found_oskscatalog, "Missing OS-KSCATALOG extension.")
        if not common.isSsl() and 'HP-IDM_Disabled' not in os.environ:
            self.assertTrue(found_hpidm, "Missing HP-IDM extension.")


if __name__ == '__main__':
    unittest.main()
