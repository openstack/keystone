import uuid
import unittest2 as unittest
import httplib
import json
import xml.etree.ElementTree


class HttpTestCase(unittest.TestCase):
    """Performs generic HTTP request testing"""

    def request(self, host='127.0.0.1', port=80, method='GET', path='/',
            headers=None, body=None, assert_status=None):
        """Perform request and fetch httplib.HTTPResponse from the server"""

        # Initialize headers dictionary
        headers = {} if not headers else headers

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
        if assert_status:
            self.assertResponseStatus(response, assert_status)
        else:
            self.assertResponseSuccessful(response)

        # Contains the response headers, body, etc
        return response

    def assertResponseSuccessful(self, response):
        """Asserts that a status code lies inside the 2xx range"""
        self.assertTrue(response.status >= 200 and response.status <= 299,
            'Status code %d is outside of the expected range (2xx)\n\n%s' %
            (response.status, response.body))

    def assertResponseStatus(self, response, assert_status):
        """Asserts a specific status code on the response"""
        self.assertEqual(response.status, assert_status,
            'Status code %s is not %s, as expected)\n\n%s' %
            (response.status, assert_status, response.body))


class RestfulTestCase(HttpTestCase):
    """Performs restful HTTP request testing"""

    def restful_request(self, headers=None, as_json=None, as_xml=None,
        **kwargs):
        """Encodes and decodes (JSON & XML) HTTP requests and responses.

        Dynamically encodes json or xml as request body if one is provided.

        WARNING: Existing Content-Type header will be overwritten.
        WARNING: If both as_json and as_xml are provided, as_xml is ignored.
        WARNING: If either as_json or as_xml AND a body is provided, the body
            is ignored.

        Dynamically returns 'as_json' or 'as_xml' attribute based on the
        detected response type, and fails the current test case if
        unsuccessful.

        response.as_json: standard python dictionary
        response.as_xml: as_xml.etree.ElementTree
        """

        # Initialize headers dictionary
        headers = {} if not headers else headers

        # Attempt to encode JSON and XML automatically, if requested
        if as_json:
            body = RestfulTestCase._encode_json(as_json)
            headers['Content-Type'] = 'application/json'
        elif as_xml:
            body = as_xml
            headers['Content-Type'] = 'application/xml'
        else:
            body = kwargs.get('body')

        # Perform the HTTP request/response
        response = self.request(headers=headers, body=body, **kwargs)

        # Attempt to parse JSON and XML automatically, if detected
        response = self._decode_response_body(response)

        # Contains the decoded response as_json/as_xml, etc
        return response

    @staticmethod
    def _encode_json(data):
        """Returns a JSON-encoded string of the given python dictionary"""
        return json.dumps(data)

    def _decode_response_body(self, response):
        """Detects response body type, and attempts to decode it"""
        if 'application/json' in response.getheader('Content-Type'):
            response.json = self._decode_json(response.body)
        elif 'application/xml' in response.getheader('Content-Type'):
            response.xml = self._decode_xml(response.body)
        return response

    @staticmethod
    def _decode_json(json_str):
        """Returns a dict of the given JSON string"""
        return json.loads(json_str)

    @staticmethod
    def _decode_xml(xml_str):
        """Returns an ElementTree of the given XML string"""
        return xml.etree.ElementTree.fromstring(xml_str)


class KeystoneTestCase(RestfulTestCase):
    """Perform generic HTTP request against Keystone APIs"""
    service_token = None

    admin_token = None
    admin_credentials = {
        'passwordCredentials': {
            'username': 'admin',
            'password': 'secrete',
        }
    }

    def setUp(self):
        """Prepare keystone for system tests"""
        # Authenticate as admin user to establish admin_token
        r = self.admin_request(method='POST', path='/tokens',
            as_json=self.admin_credentials)
        self.admin_token = r.json['auth']['token']['id']

    def service_request(self, version='2.0', path='', port=5000, headers=None,
            **kwargs):
        """Returns a request to the service API"""

        # Initialize headers dictionary
        headers = {} if not headers else headers

        path = KeystoneTestCase._version_path(version, path)

        if self.service_token:
            headers['X-Auth-Token'] = self.service_token

        return self.restful_request(port=port, path=path, headers=headers,
            **kwargs)

    def admin_request(self, version='2.0', path='', port=5001, headers=None,
            **kwargs):
        """Returns a request to the admin API"""

        # Initialize headers dictionary
        headers = {} if not headers else headers

        path = KeystoneTestCase._version_path(version, path)

        if self.admin_token:
            headers['X-Auth-Token'] = self.admin_token

        return self.restful_request(port=port, path=path, headers=headers,
            **kwargs)

    @staticmethod
    def _version_path(version, path):
        """Prepend the given path with the API version.

        An empty version results in no version being prepended."""
        if version:
            return '/v' + str(version) + str(path)
        else:
            return str(path)

    @staticmethod
    def _uuid():
        """Generate and return a unique identifier"""
        return str(uuid.uuid4())
