import unittest2 as unittest
from StringIO import StringIO
import datetime
import webob
from lxml import etree
import json

from keystone import utils
from keystone.logic.types import auth
import keystone.logic.types.fault as fault


class TestServer(unittest.TestCase):
    '''Unit tests for server.py.'''

    request = None
    auth_data = None

    def setUp(self):
        environ = {'wsgi.url_scheme': 'http'}
        self.request = webob.Request(environ)
        self.auth_data = auth.ValidateData(auth.Token(datetime.date.today(),
            "2231312"), auth.User("id", "username", "12345", "aTenant"))

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

        self.assertTrue(user.get("name"), "username")
        self.assertTrue(user.get("id"), "id")
        self.assertTrue(user.get("tenantId"), '12345')
        self.assertTrue(token.get("id"), '2231312')
        self.assertTrue(token.get("expires"), datetime.date.today())

    def test_send_result_json(self):
        self.request.headers["Accept"] = "application/json"
        response = utils.send_result(200, self.request, self.auth_data)
        self.assertTrue(response.headers['content-type'] ==
            "application/json; charset=UTF-8")
        dict = json.loads(response.unicode_body)
        self.assertTrue(dict['access']['user']['id'], 'id')
        self.assertTrue(dict['access']['user']['name'], 'username')
        self.assertTrue(dict['access']['user']['tenantId'], '12345')
        self.assertTrue(dict['access']['token']['id'], '2231312')
        self.assertTrue(dict['access']['token']['expires'],
            datetime.date.today())

    def test_get_auth_token(self):
        self.request.headers["X-Auth-Token"] = "Test token"
        self.assertTrue(utils.get_auth_token(self.request), "Test Token")

    def test_get_normalized_request_content_exception(self):
        self.assertRaises(fault.IdentityFault,
            utils.get_normalized_request_content, None, self.request)

    def test_get_normalized_request_content_xml(self):
        self.request.environ["CONTENT_TYPE"] = "application/xml"
        auth.AuthWithPasswordCredentials("username", "password", "1")
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <auth xmlns="http://docs.openstack.org/identity/api/v2.0">\
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secret" username="disabled" \
                /></auth>'
        str = StringIO()
        str.write(body)
        self.request.environ["wsgi.input"] = str
        self.request.environ["CONTENT_LENGTH"] = str.len
        #TODO: I THINK THIS belongs in a test for auth.py.


if __name__ == '__main__':
    unittest.main()
