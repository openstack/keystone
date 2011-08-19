import unittest2 as unittest
import os
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', '..', 'keystone')))

from keystone import utils
import keystone.logic.types.auth as auth
import keystone.logic.types.fault as fault

from StringIO import StringIO
from datetime import date
from lxml import etree
from webob import Request


class TestServer(unittest.TestCase):
    '''Unit tests for server.py.'''

    request = None
    auth_data = None

    def setUp(self):
        environ = {'wsgi.url_scheme': 'http'}
        self.request = Request(environ)
        self.auth_data = auth.ValidateData(auth.Token(date.today(), "2231312"),
            auth.User("username", "12345"))

    #def tearDown(self):

    def test_is_xml_response(self):
        self.assertFalse(utils.is_xml_response(self.request))
        self.request.headers["Accept"] = "application/xml"
        self.request.content_type = "application/json"
        self.assertTrue(utils.is_xml_response(self.request))

    def test_send_result_xml(self):
        self.request.headers["Accept"] = "application/xml"
        response = utils.send_result(200, self.request, self.auth_data)

        self.assertTrue(response.headers['content-type'] ==
            "application/xml; charset=UTF-8")
        xml = etree.fromstring(response.unicode_body)

        user = xml.find("{http://docs.openstack.org/identity/api/v2.0}user")
        token = xml.find("{http://docs.openstack.org/identity/api/v2.0}token")

        self.assertTrue(user.get("username"), "username")
        self.assertTrue(user.get("tenantId"), '12345')
        self.assertTrue(token.get("id"), '2231312')
        self.assertTrue(token.get("expires"), date.today())

    def test_send_result_json(self):
        self.request.headers["Accept"] = "application/json"
        response = utils.send_result(200, self.request, self.auth_data)
        self.assertTrue(response.headers['content-type'] ==
            "application/json; charset=UTF-8")
        dict = json.loads(response.unicode_body)
        self.assertTrue(dict['auth']['user']['username'], 'username')
        self.assertTrue(dict['auth']['user']['tenantId'], '12345')
        self.assertTrue(dict['auth']['token']['id'], '2231312')
        self.assertTrue(dict['auth']['token']['expires'], date.today())

    def test_get_auth_token(self):
        self.request.headers["X-Auth-Token"] = "Test token"
        self.assertTrue(utils.get_auth_token(self.request), "Test Token")

    def test_get_normalized_request_content_exception(self):
        self.assertRaises(fault.IdentityFault,
            utils.get_normalized_request_content, None, self.request)

    def test_get_normalized_request_content_xml(self):
        self.request.environ["CONTENT_TYPE"] = "application/xml"
        auth.PasswordCredentials("username", "password", "1")
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secret" username="disabled" \
                />'
        str = StringIO()
        str.write(body)
        self.request.environ["wsgi.input"] = str
        self.request.environ["CONTENT_LENGTH"] = str.len
        #TODO: I THINK THIS belongs in a test for auth.py.


if __name__ == '__main__':
    unittest.main()
