import unittest
from common import KeystoneTestCase

class TestUrlHandling(KeystoneTestCase):
    """Tests API's global URL handling behaviors"""
    
    def test_optional_trailing_slash(self):
        """Same response returned regardless of a trailing slash in the url."""
        r1 = self.admin_request(path='/v2.0/')
        r2 = self.admin_request(path='/v2.0')
        self.assertEqual(r1.read(), r2.read())

class TestContentTypes(KeystoneTestCase):
    """Tests API's Content-Type handling"""
    
    def test_default_content_type(self):
        """Service returns JSON without being asked to"""
        r = self.admin_request(path='/v2.0')
        self.assertTrue('application/json' in r.getheader('Content-Type'))
    
    def test_xml_extension(self):
        """Service responds to .xml URL extension"""
        r = self.admin_request(path='/v2.0.xml')
        self.assertTrue('application/xml' in r.getheader('Content-Type'))
    
    def test_json_extension(self):
        """Service responds to .json URL extension"""
        r = self.admin_request(path='/v2.0.json')
        self.assertTrue('application/json' in r.getheader('Content-Type'))
    
    def test_xml_accept_header(self):
        """Service responds to xml Accept header"""
        r = self.admin_request(path='/v2.0',
            headers={'Accept': 'application/xml'})
        self.assertTrue('application/xml' in r.getheader('Content-Type'))
    
    def test_json_accept_header(self):
        """Service responds to json Accept header"""
        r = self.admin_request(path='/v2.0',
            headers={'Accept': 'application/json'})
        self.assertTrue('application/json' in r.getheader('Content-Type'))
    
    def test_xml_extension_overrides_conflicting_header(self):
        """Service returns XML when Accept header conflicts with extension"""
        r = self.admin_request(path='/v2.0.xml',
            headers={'Accept': 'application/json'})
        
        self.assertTrue('application/xml' in r.getheader('Content-Type'))
    
    def test_json_extension_overrides_conflicting_header(self):
        """Service returns JSON when Accept header conflicts with extension"""
        r = self.admin_request(path='/v2.0.json',
            headers={'Accept': 'application/xml'})
        
        self.assertTrue('application/json' in r.getheader('Content-Type'))

if __name__ == '__main__':
    unittest.main()
