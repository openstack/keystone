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
import os
import sys
app_path = os.path.abspath(os.path.join(os.path.abspath(__file__),
    '..', '..', '..', '..', '..', '..', 'keystone'))
sys.path.append(app_path)
import unittest2 as unittest
import test_common as utils
import json
import keystone.logic.types.fault as fault
from lxml import etree


class ValidateToken(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_tenant()
        self.user = 'joeuser'
        self.token = utils.get_token('joeuser', 'secrete', self.tenant,
                                    'token')
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        _resp, content = utils.create_role_ref(self.user, 'Admin', self.tenant,
            str(self.auth_token))
        obj = json.loads(content)
        if not "roleRef" in obj:
            raise fault.BadRequestFault("Expecting RoleRef")
        roleRef = obj["roleRef"]
        if not "id" in roleRef:
            self.role_ref_id = None
        else:
            self.role_ref_id = roleRef["id"]

    def tearDown(self):
        _resp, _content = utils.delete_role_ref(self.user, self.role_ref_id,
            self.auth_token)
        utils.delete_token(self.token, self.auth_token)

    def test_validate_token_true(self):
        header = httplib2.Http(".cache")

        url = '%stokens/%s?belongsTo=%s' % (utils.URL_V2, self.token,
            self.tenant)
        resp, content = header.request(url, "GET", body='', headers={
            "Content-Type": "application/json",
            "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))
        #verify content
        obj = json.loads(content)
        if not "auth" in obj:
            raise self.fail("Expecting Auth")
        role_refs = obj["auth"]["user"]["roleRefs"]
        role_ref = role_refs[0]
        role_ref_id = role_ref["id"]
        self.assertEqual(self.role_ref_id, role_ref_id)

    def test_validate_token_true_using_service_token(self):
        header = httplib2.Http(".cache")

        url = '%stokens/%s?belongsTo=%s' % (utils.URL_V2, self.token,
            self.tenant)
        resp, content = header.request(url, "GET", body='', headers={
            "Content-Type": "application/json",
            "X-Auth-Token": utils.get_service_token()})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))
        #verify content
        obj = json.loads(content)
        if not "auth" in obj:
            raise self.fail("Expecting Auth")
        role_refs = obj["auth"]["user"]["roleRefs"]
        role_ref = role_refs[0]
        role_ref_id = role_ref["id"]
        self.assertEqual(self.role_ref_id, role_ref_id)

    def test_validate_token_true_xml(self):
        header = httplib2.Http(".cache")
        url = '%stokens/%s?belongsTo=%s' % (
            utils.URL_V2, self.token, self.tenant)
        resp, content = header.request(url, "GET", body='', headers={
            "Content-Type": "application/xml",
            "X-Auth-Token": self.auth_token,
            "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))
        #verify content
        dom = etree.Element("root")
        dom.append(etree.fromstring(content))
        auth = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
            "auth")
        if auth == None:
            self.fail("Expecting Auth")

        user = auth.find("{http://docs.openstack.org/identity/api/v2.0}" \
            "user")
        if user == None:
            self.fail("Expecting User")
        roleRefs = user.find("{http://docs.openstack.org/identity/api/v2.0}" \
               "roleRefs")
        if roleRefs == None:
            self.fail("Expecting Role Refs")
        roleRef = roleRefs.find(
            "{http://docs.openstack.org/identity/api/v2.0}roleRef")
        if roleRef == None:
            self.fail("Expecting Role Refs")
        self.assertEqual(str(self.role_ref_id), roleRef.get("id"))

    def test_validate_token_expired(self):
        header = httplib2.Http(".cache")
        url = '%stokens/%s?belongsTo=%s' % (utils.URL_V2, self.exp_auth_token,
                                           self.tenant)
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_validate_token_expired_xml(self):
        header = httplib2.Http(".cache")

        url = '%stokens/%s?belongsTo=%s' % (utils.URL_V2, self.exp_auth_token,
                                           self.tenant)
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_validate_token_invalid(self):
        header = httplib2.Http(".cache")
        url = '%stokens/%s?belongsTo=%s' % (utils.URL_V2, 'NonExistingToken',
                                           self.tenant)
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_validate_token_invalid_xml(self):
        header = httplib2.Http(".cache")
        url = '%stokens/%s?belongsTo=%s' % (utils.URL_V2, 'NonExistingToken',
                                           self.tenant)
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

if __name__ == '__main__':
    unittest.main()
