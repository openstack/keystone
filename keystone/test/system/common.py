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
        """Perform request and fetch httplib.HTTPResponse from the server
        
        Dynamically includes 'json' and 'xml' attributes based on the detected
        response type, and fails the current test case if unsuccessful.
        
        response.json: standard python dictionary
        response.xml: xml.etree.ElementTree
        """
        
        # Initialize a connection
        connection = httplib.HTTPConnection(self.host, self.port, timeout=3)
        
        # Perform the request
        connection.request(method, path, body, headers)
        
        # Retrieve the response so can go ahead and close the connection
        response = connection.getresponse()
        response.body = response.read()
        
        # Close the connection
        connection.close()
        
        # Automatically assert HTTP status code
        if not expect_exception:
            self.assertSuccessfulResponse(response.status)
        else:
            self.assertExceptionalResponse(response.status)
        
        # Attempt to parse JSON and XML automatically, if detected
        response = self._parseResponseBody(response)
        
        # This contains the response headers, body, parsed json/xml, etc
        return response

    def assertSuccessfulResponse(self, status_code):
        """Asserts that a status code lies in the 2xx range"""
        self.assertTrue(status_code >= 200 and status_code <= 299)

    def assertExceptionalResponse(self, status_code):
        """Asserts that a status code lies outside the 2xx range"""
        self.assertTrue(status_code < 200 or status_code > 299)
    
    def _parseResponseBody(self, response):
        """Detects response body type, and attempts to decode it"""
        if 'application/json' in response.getheader('Content-Type'):
            response.json = self._parseJson(response.body)
        elif 'application/xml' in response.getheader('Content-Type'):
            response.xml = self._parseXml(response.body)
        return response
    
    def _parseXml(self, xml_str):
        """Returns an ElementTree of the given XML string"""
        try:
            import xml.etree.ElementTree
            return xml.etree.ElementTree.fromstring(xml_str)
        except Exception as e:
            self.fail(e)
    
    def _parseJson(self, json_str):
        """Returns a dict of the given JSON string"""
        try:
            import json
            return json.loads(json_str)
        except Exception as e:
            self.fail(e)

class ServiceTestCase(RestfulTestCase):
    """Perform generic HTTP request testing against Service API"""
    
    def setUp(self):
        """Sets custom connection settings"""
        super(ServiceTestCase, self).setUp()
        
        # Override parent's connection settings
        self.port = 5000 # The port the service API is expected to run on
        
class AdminTestCase(RestfulTestCase):
    """Perform generic HTTP request testing against Admin API"""
    
    def setUp(self):
        """Sets custom connection settings"""
        super(AdminTestCase, self).setUp()
        
        # Override parent's connection settings
        self.port = 5001 # The port the admin API is expected to run on
