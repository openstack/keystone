import os
import sys
# Need to access identity module
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest
from webtest import TestApp
import httplib2
import json
from lxml import etree
import unittest
from webtest import TestApp
from test_common import *


class authentication_test(unittest.TestCase):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()

    def tearDown(self):
        delete_token(self.token, self.auth_token)

    def test_a_authorize(self):
        resp, content = get_token('joeuser', 'secrete')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_a_authorize_xml(self):
        resp, content = get_token_xml('joeuser', 'secrete')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_authorize_user_disabled(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = {"passwordCredentials": {"username": "disabled",
                                        "password": "secrete"}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})
        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_a_authorize_user_disabled_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="secrete" username="disabled" \
                />'
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_authorize_user_wrong(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = {"passwordCredentials": {"username-w": "disabled",
                                        "password": "secrete"}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})
        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_a_authorize_user_wrong_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="secrete" username-w="disabled" \
                />'
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

def run():
    unittest.main()
    
if __name__ == '__main__':
    unittest.main()
