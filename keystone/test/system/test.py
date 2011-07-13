import unittest
import urllib2

class RestfulTestCase(unittest.TestCase):
    def setUp(self):
        self.opener = urllib2.build_opener(urllib2.HTTPHandler)
    
    def tearDown(self):
        self.opener = None
    
    def request(self, method='GET', path='/', headers={}, data=None):
        # Build URL
        url = ''.join(['http://127.0.0.1', path])
        
        # Build request
        request = urllib2.Request(url, data=data)
        request.get_method = lambda: method
        
        # Build headers
        for header, value in headers:
            request.add_header(header, value)
        
        return self.opener.open(request)

class ServiceRestfulTestCase(RestfulTestCase):
    def request(self, path='/', data=None, headers={}, method='GET'):
        # Build URL
        path = ''.join([':5000', path])
        
        # Build request
        return super(AdminRestfulTestCase, self).request(
            method=method,
            path=path,
            headers={},
            data=data)

class AdminRestfulTestCase(RestfulTestCase):
    def request(self, path='/', data=None, headers={}, method='GET'):
        # Build URL
        path = ''.join([':5001', path])
        
        # Build request
        return super(AdminRestfulTestCase, self).request(
            method=method,
            path=path,
            headers={},
            data=data)
    
class TestContentTypes(AdminRestfulTestCase):
    def setUp(self):
        super(TestContentTypes, self).setUp()
    
    def tearDown(self):
        super(TestContentTypes, self).tearDown()
    
    def test_simple(self):
        r = self.request(path='/v2.0/')
        self.assertEqual(r.status, 200)

if __name__ == '__main__':
    unittest.main()
