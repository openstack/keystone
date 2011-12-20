import unittest2 as unittest
from keystone.test.functional import common


class TestStaticFiles(common.ApiTestCase):
    use_server = True

    def test_pdf_contract(self):
        if not common.isSsl():
            #TODO(ziad): Caller hangs in SSL (but works with cURL)
            r = self.service_request(path='/identitydevguide.pdf')
            self.assertTrue('pdf' in r.getheader('Content-Type'))

    def test_wadl_contract(self):
        r = self.service_request(path='/identity.wadl')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_wadl_common(self):
        r = self.service_request(path='/common.ent')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xsd_contract(self):
        r = self.service_request(path='/xsd/api.xsd')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xsd_atom_contract(self):
        r = self.service_request(path='/xsd/atom/atom.xsd')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xslt(self):
        r = self.service_request(path='/xslt/schema.xslt')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_js(self):
        r = self.service_request(path='/js/shjs/sh_java.js')
        self.assertTrue('javascript' in r.getheader('Content-Type'))

    def test_xml_sample(self):
        r = self.service_request(path='/samples/auth.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_json_sample(self):
        r = self.service_request(path='/samples/auth.json')
        self.assertTrue('json' in r.getheader('Content-Type'))

    def test_stylesheet(self):
        r = self.service_request(path='/style/shjs/sh_acid.css')
        self.assertTrue('css' in r.getheader('Content-Type'))


class TestAdminStaticFiles(common.FunctionalTestCase):
    use_server = True

    def test_pdf_contract(self):
        if not common.isSsl():
            #TODO(ziad): Caller hangs in SSL (but works with cURL)
            r = self.admin_request(path='/identityadminguide.pdf')
            self.assertTrue('pdf' in r.getheader('Content-Type'))

    def test_wadl_contract(self):
        r = self.admin_request(path='/identity-admin.wadl')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xsd_contract(self):
        r = self.admin_request(path='/xsd/api.xsd')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xsd_atom_contract(self):
        r = self.admin_request(path='/xsd/atom/atom.xsd')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xslt(self):
        r = self.admin_request(path='/xslt/schema.xslt')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_js(self):
        r = self.admin_request(path='/js/shjs/sh_java.js')
        self.assertTrue('javascript' in r.getheader('Content-Type'))

    def test_xml_sample(self):
        r = self.admin_request(path='/samples/auth.xml')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_json_sample(self):
        r = self.admin_request(path='/samples/auth.json')
        self.assertTrue('json' in r.getheader('Content-Type'))

    def test_stylesheet(self):
        r = self.admin_request(path='/style/shjs/sh_acid.css')
        self.assertTrue('css' in r.getheader('Content-Type'))


if __name__ == '__main__':
    unittest.main()
