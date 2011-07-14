import unittest
import httplib

class RestfulTestCase(unittest.TestCase):
    """Performs generic HTTP request testing"""

    def request(self, host='127.0.0.1', port=80, method='GET', path='/',
            headers={}, body=None, expect_exception=False,):
        """Perform request and fetch httplib.HTTPResponse from the server
        
        Dynamically includes 'json' and 'xml' attributes based on the detected
        response type, and fails the current test case if unsuccessful.
        
        response.json: standard python dictionary
        response.xml: xml.etree.ElementTree
        """
        
        # Initialize a connection
        connection = httplib.HTTPConnection(host, port, timeout=3)
        
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
        
        # Contains the response headers, body, parsed json/xml, etc
        return response

    def assertSuccessfulResponse(self, status_code):
        """Asserts that a status code lies inside the 2xx range"""
        self.assertTrue(status_code >= 200 and status_code <= 299)

    def assertExceptionalResponse(self, status_code):
        """Asserts that a status code lies outside the 2xx range"""
        self.assertFalse(status_code >= 200 and status_code <= 299)
    
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

class KeystoneTestCase(RestfulTestCase):
    """Perform generic HTTP request against Keystone APIs"""
    service_token = None
    admin_token = None
    
    def service_request(self, port=5000, headers={}, **kwargs):
        """Returns a request to the service API"""
        
        if self.service_token:
            headers['X-Auth-Token'] = self.service_token
        
        return self.request(port=port, headers=headers, **kwargs)
    
    def admin_request(self, port=5001, headers={}, **kwargs):
        """Returns a request to the admin API"""
        
        if self.admin_token:
            headers['X-Auth-Token'] = self.admin_token
        
        return self.request(port=port, headers=headers, **kwargs)
