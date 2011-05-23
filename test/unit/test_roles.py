# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import httplib2
import json
from lxml import etree
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest

import test_common as utils
from test_common import URL

class RolesTest(unittest.TestCase):
    def setUp(self):
        self.tenant = utils.get_tenant()
        self.password = utils.get_password()
        self.email = utils.get_email()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.missing_token = utils.get_none_token()
        self.invalid_token = utils.get_non_existing_token()
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.add_user_json(self.tenant, self.user, self.auth_token)
        self.token = utils.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        utils.delete_user(self.tenant, self.user, self.auth_token)
        utils.delete_tenant(self.tenant, self.auth_token)
        
class CreateRoleTest(RolesTest):
    def test_a_role_create_json(self):
        resp, content = utils.create_role('test_role1',
                                           str(self.auth_token))
        self.role = 'test_role1'
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)

    def test_a_role_create_xml(self):
        resp, content = utils.create_role_xml('test_role2',
                                           str(self.auth_token))
        self.role = 'test_role1'
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))
        
    def test_role_create_again(self):
        resp_new, content = utils.create_role_xml('test_role2',
                                           str(self.auth_token))
        if int(resp_new['status']) == 500:
            self.fail('IDM fault')
        elif int(resp_new['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp_new['status']))

    def test_role_create_again_xml(self):
        resp_new, content = utils.create_role_xml('test_role2',
                                           str(self.auth_token))
        if int(resp_new['status']) == 500:
            self.fail('IDM fault')
        elif int(resp_new['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp_new['status']))        
        
class GetRolesTest(RolesTest):
    def test_get_roles(self):
        header = httplib2.Http(".cache")
        url = '%sroles' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_roles_xml(self):
        header = httplib2.Http(".cache")
        url = '%sroles' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_roles_exp_token(self):
        header = httplib2.Http(".cache")
        url = '%sroles' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                        "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_roles_exp_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        
class GetRoleTest(RolesTest):

    def test_get_role(self):
        self.role = 'test_role1'
        header = httplib2.Http(".cache")
        url = '%sroles/%s' % (utils.URL, self.role)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_role_xml(self):
        self.role = 'test_role1'
        header = httplib2.Http(".cache")
        url = '%sroles/%s' % (utils.URL, self.role)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_role_bad(self):
        header = httplib2.Http(".cache")
        url = '%sroles/%s' % (utils.URL, 'tenant_bad')
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_role_bad_xml(self):
        header = httplib2.Http(".cache")
        resp, content = utils.create_tenant(self.tenant, str(self.auth_token))
        url = '%sroles/%s' % (utils.URL, 'role_bad')
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))
        
if __name__ == '__main__':
    unittest.main()
