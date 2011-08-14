import unittest
from common import KeystoneTestCase


class TestStaticFiles(KeystoneTestCase):
    def test_pdf_contract(self):
        r = self.service_request(path='/identitydevguide.pdf')
        self.assertTrue('pdf' in r.getheader('Content-Type'))

    def test_wadl_contract(self):
        r = self.service_request(path='/identity.wadl')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xsd_contract(self):
        r = self.service_request(path='/xsd/api.xsd')
        self.assertTrue('xml' in r.getheader('Content-Type'))

    def test_xsd_atom_contract(self):
        r = self.service_request(path='/xsd/atom/atom.xsd')
        self.assertTrue('xml' in r.getheader('Content-Type'))


class TestAdminStaticFiles(KeystoneTestCase):
    def test_pdf_contract(self):
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

if __name__ == '__main__':
    unittest.main()
