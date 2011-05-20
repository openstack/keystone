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

import test_common  as utils


class authentication_test(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_tenant()
        self.token = utils.get_token('joeuser', 'secrete', 'token')
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()

    def tearDown(self):
        utils.delete_token(self.token, self.auth_token)

    def test_a_authorize(self):
        resp, content = utils.get_token('joeuser', 'secrete', '')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_authorize_xml(self):
        resp, content = utils.get_token_xml('joeuser', 'secrete', '',
                                             self.tenant)
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_authorize_user_disabled(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = {"passwordCredentials": {"username": "disabled",
                                        "password": "secrete"}}
        resp, content = header.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})
        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_authorize_user_disabled_xml(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secrete" username="disabled" \
                />'
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_authorize_user_wrong(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = {"passwordCredentials": {"username-w": "disabled",
                                        "password": "secrete"}}
        resp, content = header.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})
        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_authorize_user_wrong_xml(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secrete" username-w="disabled" \
                />'
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

if __name__ == '__main__':
    unittest.main()
