import unittest
from common import KeystoneTestCase


class TestStaticFiles(KeystoneTestCase):
    def test_pdf_contract(self):
        r = self.admin_request(path='/identitydevguide.pdf')
        self.assertTrue('pdf' in r.getheader('Content-Type'))

    def test_wadl_contract(self):
        r = self.admin_request(path='/identity.wadl')
        self.assertTrue('xml' in r.getheader('Content-Type'))

#    def test_xsd_contract(self):
#        self.admin_request(path='/xsd/something')

#    def test_xsd_atom_contract(self):
#        self.admin_request(path='/xsd/atom/something')


if __name__ == '__main__':
    unittest.main()
