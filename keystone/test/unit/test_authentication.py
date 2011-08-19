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
import unittest2 as unittest
import test_common as utils

from keystone.logic.types import fault


class AuthenticationTest(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_tenant()
        self.token = utils.get_token(
            'joeuser', 'secrete', self.tenant, 'token')
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        utils.delete_all_endpoint(self.tenant, self.auth_token)
        utils.create_endpoint(self.tenant, "1", str(self.auth_token))
        utils.create_endpoint(self.tenant, "2", str(self.auth_token))
        utils.create_endpoint(self.tenant, "3", str(self.auth_token))
        utils.create_endpoint(self.tenant, "4", str(self.auth_token))

    def tearDown(self):
        utils.delete_all_endpoint(self.tenant, self.auth_token)
        utils.delete_token(self.token, self.auth_token)

    def test_a_authorize(self):
        resp, content = utils.get_token('joeuser', 'secrete', self.tenant)
        self.assertEqual(200, int(resp['status']))
        obj = content
        if not "auth" in obj:
            raise fault.BadRequestFault("Expecting Auth")
        auth = obj["auth"]
        if not "serviceCatalog" in auth:
            raise fault.BadRequestFault("Expecting Service Catalog")

        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_authorize_xml(self):
        resp, content = utils.get_token_xml('joeuser', 'secrete',
                                             self.tenant)
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))
        #verify content
        dom = etree.Element("root")
        dom.append(etree.fromstring(content))
        auth = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
            "auth")
        if auth == None:
            self.fail("Expecting Auth")
        service_catalog = auth.find(
            "{http://docs.openstack.org/identity/api/v2.0}" \
                "serviceCatalog")
        if service_catalog == None:
            self.fail("Expecting Service Catalog")

    def test_a_authorize_legacy(self):
        resp, _content = utils.get_token_legacy('joeuser', 'secrete')
        self.assertEqual(204, int(resp['status']))
        self.assertTrue(resp['x-auth-token'])
        self.assertTrue(resp['x-server-management-url'])
        self.assertTrue(resp['x-storage-url'])
        self.assertTrue(resp['x-glance'])
        #Assert Existence of global endpoint
        self.assertTrue(resp['x-identity'])

    def test_a_authorize_user_disabled(self):
        header = httplib2.Http(".cache")
        url = '%stokens' % utils.URL_V2
        body = {"passwordCredentials": {"username": self.userdisabled,
                                        "password": "secrete",
                                        "tenantId": self.tenant}}
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
        url = '%stokens' % utils.URL_V2
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secrete" username="%s" \
                tenantId="%s"/>' % (self.userdisabled, self.tenant)
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
        url = '%stokens' % utils.URL_V2
        body = {"passwordCredentials": {"username-w": "disabled",
                                        "password": "secrete",
                                        "tenantId": self.tenant}}
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
        url = '%stokens' % utils.URL_V2
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/identity/api/v2.0" \
                password="secrete" username-w="disabled" \
                tenantId="%s"/>' % self.tenant
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


class MultiToken(unittest.TestCase):

    def setUp(self):
        self.auth_token = utils.get_auth_token()
        self.userdisabled = utils.get_userdisabled()
        utils.create_tenant('test_tenant1', self.auth_token)
        utils.create_tenant('test_tenant2', self.auth_token)
        utils.create_user('test_tenant1', 'test_user1', self.auth_token)
        utils.create_user('test_tenant1', 'test_user2', self.auth_token)
        utils.add_user_json(self.auth_token)

    def tearDown(self):
        utils.delete_user('test_user1', self.auth_token)
        utils.delete_user('test_user2', self.auth_token)
        utils.delete_user('test_user1', self.auth_token)
        utils.delete_tenant('test_tenant1', self.auth_token)
        utils.delete_tenant('test_tenant2', self.auth_token)

    def test_unassigned_user(self):
        resp, _content = utils.get_token(
            'test_user2', 'secrete', 'test_tenant')

        self.assertEqual(401, int(resp['status']))


if __name__ == '__main__':
    unittest.main()
