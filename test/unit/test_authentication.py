# Need to access identity module
import httplib2
import json
from lxml import etree
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest
from webtest import TestApp

import test_common  as utils


class AuthenticationTest(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_tenant()
        self.token = utils.get_token('joeuser', 'secrete', self.tenant,
                                     'token')
        #self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        #self.exp_auth_token = utils.get_exp_auth_token()
        #self.disabled_token = utils.get_disabled_token()

    def tearDown(self):
        utils.delete_token(self.token, self.auth_token)

    def test_a_authorize(self):
        resp, content = utils.get_token('joeuser', 'secrete', self.tenant)
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_authorize_xml(self):
        resp, content = utils.get_token_xml('joeuser', 'secrete',
                                             self.tenant)
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_authorize_user_disabled(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = {"passwordCredentials": {"username": self.userdisabled,
                                        "password": "secrete",
                                        "tenantId" : self.tenant}}
        resp, content = header.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})

        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_authorize_user_disabled_xml(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="secrete" username="%s" \
                tenantId="%s"/>' % (self.userdisabled, self.tenant)
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})

        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_authorize_user_wrong(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = {"passwordCredentials": {"username-w": "disabled",
                                        "password": "secrete",
                                        "tenantId" : self.tenant}}
        resp, content = header.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})
        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_authorize_user_wrong_xml(self):
        header = httplib2.Http(".cache")
        url = '%stoken' % utils.URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/1idm/api/v1.0" \
                password="secrete" username-w="disabled" \
                tenantId="%s"/>' % self.tenant
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

class MultiToken(unittest.TestCase):
    def setUp(self):
        self.auth_token = utils.get_auth_token()
        self.userdisabled = utils.get_userdisabled()
        resp1, content1 = utils.create_tenant('test_tenant1', self.auth_token)
        #create tenant2
        resp2, content2 = utils.create_tenant('test_tenant2', self.auth_token)
        #create user1 with tenant1
        resp3, content3 = utils.create_user('test_tenant1', 'test_user1',
                                      self.auth_token)
        resp3, content3 = utils.create_user('test_tenant1', 'test_user2',
                                      self.auth_token)
        #add user1 to tenant2
        resp4, content4 = utils.add_user_json('test_tenant2', 'test_user1',
                                      self.auth_token)
        #self.exp_auth_token = utils.get_exp_auth_token()
        #self.disabled_token = utils.get_disabled_token()

    def tearDown(self):
        utils.delete_user('test_tenant1', 'test_user1', self.auth_token)
        utils.delete_user('test_tenant1', 'test_user2', self.auth_token)
        utils.delete_user('test_tenant2', 'test_user1', self.auth_token)
        utils.delete_tenant('test_tenant1', self.auth_token)
        utils.delete_tenant('test_tenant2', self.auth_token)

    def test_multi_token(self):
        #get token for user1 with tenant1
        token1 = utils.get_token('test_user1', 'secrete', 'test_tenant1', 'token')
        #get token for user 1 with tenant2
        token2 = utils.get_token('test_user1', 'secrete', 'test_tenant2', 'token')
        #test result :: both token should be different
        self.assertNotEqual(token1, None)
        self.assertNotEqual(token2, None)
        self.assertNotEqual(token1, token2)

        resp = utils.delete_token(token1, self.auth_token)
        resp = utils.delete_token(token2, self.auth_token)

    def test_unassigned_user(self):
        resp, content = utils.get_token('test_user2', 'secrete', 'test_tenant2')

        self.assertEqual(403, int(resp['status']))

if __name__ == '__main__':
    unittest.main()
