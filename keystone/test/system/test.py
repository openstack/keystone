import unittest
import httplib

class RestfulTestCase(unittest.TestCase):
    """Performs generic HTTP request testing"""
    
    def setUp(self):
        """Sets default connection settings"""
        self.host = '127.0.0.1'
        self.port = 80
    
    def request(self, method='GET', path='/', headers={}, body=None,
            expect_exception=False):
        """Perform request and fetch httplib.HTTPResponse from the server"""
        
        # Initialize a connection
        connection = httplib.HTTPConnection(self.host, self.port, timeout=3)
        
        # Perform the request
        connection.request(method, path, body, headers)
        
        # Retrieve the response so can go ahead and close the connection
        response = connection.getresponse()
        
        # Close the connection
        connection.close()
        
        # Automatically assert HTTP status code
        if not expect_exception:
            self.assertSuccessfulResponse(response.status)
        else:
            self.assertExceptionalResponse(response.status)
        
        # This contains the response headers, body, etc
        return response
    
    def assertSuccessfulResponse(self, status_code):
        """Asserts that a status code lies in the 2xx range"""
        self.assertTrue(status_code >= 200 and status_code <= 299)

    def assertExceptionalResponse(self, status_code):
        """Asserts that a status code lies outside the 2xx range"""
        self.assertTrue(status_code < 200 or status_code > 299)

class ServiceTestCase(RestfulTestCase):
    """Perform generic HTTP request testing against Service API"""
    
    def setUp(self):
        """Sets custom connection settings"""
        super(ServiceTestCase, self).setUp()
        
        # Override parent's connection settings
        self.port = 5000 # The port the service API is expected to run on
        
class AdminTestCase(RestfulTestCase):
    """Perform generic HTTP request testing against Service API"""
    
    def setUp(self):
        """Sets custom connection settings"""
        super(AdminTestCase, self).setUp()
        
        # Override parent's connection settings
        self.port = 5001 # The port the admin API is expected to run on
    
class TestContentTypes(AdminTestCase):
    def test_simple(self):
        self.request(path='/v2.0/')

if __name__ == '__main__':
    unittest.main()
