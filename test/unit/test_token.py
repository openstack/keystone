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


class validate_token(unittest.TestCase):

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

    def test_validate_token_true(self):
        h = httplib2.Http(".cache")

        url = '%stoken/%s?belongsTo=%s' % (URL, self.token, self.tenant)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_validate_token_true_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, self.token, self.tenant)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_validate_token_expired(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, self.exp_auth_token,
                                           self.tenant)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_validate_token_expired_xml(self):
        h = httplib2.Http(".cache")

        url = '%stoken/%s?belongsTo=%s' % (URL, self.exp_auth_token,
                                           self.tenant)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_validate_token_invalid(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, 'NonExistingToken',
                                           self.tenant)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_validate_token_invalid_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, 'NonExistingToken',
                                           self.tenant)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

def run():
    unittest.main()
    
if __name__ == '__main__':
    unittest.main()
