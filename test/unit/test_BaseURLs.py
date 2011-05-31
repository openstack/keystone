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

class BaseURLsTest(unittest.TestCase):
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
        utils.create_user(self.tenant, self.user, self.auth_token)
        self.token = utils.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        utils.delete_user(self.tenant, self.user, self.auth_token)
        utils.delete_tenant(self.tenant, self.auth_token)
        utils.delete_all_baseurls_ref(self.tenant, self.auth_token)

class GetBaseURLsTest(BaseURLsTest):
    def test_get_baseURLs(self):
        header = httplib2.Http(".cache")
        url = '%sbaseURLs' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        
        #verify content
        obj = json.loads(content)
        if not "baseURLs" in obj:
            raise self.fail("Expecting BaseURLs")

    def test_get_baseURLs_xml(self):
        header = httplib2.Http(".cache")
        url = '%sbaseURLs' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        
        #verify content
        dom = etree.Element("root")
        dom.append(etree.fromstring(content))
        baseURLs = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
            "baseURLs")
        if baseURLs == None:
            self.fail("Expecting BaseURLs")

class GetBaseURLTest(BaseURLsTest):
    def test_get_baseURL(self):
        header = httplib2.Http(".cache")
        url = '%sbaseURLs/%s' % (utils.URL, '1')
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        
        #verify content
        obj = json.loads(content)
        if not "baseURL" in obj:
            raise self.fail("Expecting BaseURL")

    def test_get_baseURL_xml(self):
        header = httplib2.Http(".cache")
        url = '%sbaseURLs/%s' % (utils.URL,'1')
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        
        #verify content
        dom = etree.Element("root")
        dom.append(etree.fromstring(content))
        baseURL = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
            "baseURL")
        if baseURL == None:
            self.fail("Expecting BaseURL")

            
class BaseURLRefsTest(BaseURLsTest):
    def test_baseurls_ref_create_json(self):
        header = httplib2.Http(".cache")
        resp, content = utils.create_baseurls_ref(self.tenant,"1",
            str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)

    
    def test_baseurls_ref_create_xml(self):
        header = httplib2.Http(".cache")
        
        resp, content = utils.create_baseurls_ref_xml(self.tenant,"1",
            str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)
        url = '%stenants/%s/baseURLRefs/%s' % (URL, self.tenant, '1')
        resp, content = header.request(url, "DELETE", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": str(self.auth_token)})
        resp_val = int(resp['status'])
        self.assertEqual(204, resp_val)
        
    
    def test_get_baseurls_ref_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/baseURLRefs' % (URL, self.tenant)
        #test for Content-Type = application/xml
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": str(self.auth_token),
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        
        
    def test_get_baseurls_ref_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/baseURLRefs' % (URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": str(self.auth_token),
                                         "ACCEPT": "application/json"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        obj = json.loads(content)
        if not "baseURLRefs" in obj:
            raise self.fail("Expecting BaseURLRefs")
        
    def test_delete_baseurlref(self):
        header = httplib2.Http(".cache")
        resp, content = utils.create_baseurls_ref(self.tenant,"1",
            str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)
        obj = json.loads(content)
        if not "baseURLRef" in obj:
            raise fault.BadRequestFault("Expecting baseURLRef")
        base_url_ref = obj["baseURLRef"]
        if not "id" in base_url_ref:
                base_url_ref_id = None
        else:
            base_url_ref_id = base_url_ref["id"]
        if base_url_ref_id is None:
            raise fault.BadRequestFault("Expecting baseURLRefID")
        url = '%stenants/%s/baseURLRefs/%s' % (URL, self.tenant, base_url_ref_id)
        resp, content = header.request(url, "DELETE", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": str(self.auth_token)})
        resp_val = int(resp['status'])
        self.assertEqual(204, resp_val)

    #TODO
    #To add failure cases using disabled token,expired token and invalid token.
if __name__ == '__main__':
    unittest.main()