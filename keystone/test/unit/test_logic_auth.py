# Copyright (c) 2011 OpenStack, LLC.
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

import json
import datetime
from lxml import etree
import unittest2 as unittest

import base
from keystone.logic.types import auth as logic_auth
from keystone import models
from keystone.test import utils as test_utils


class LogicTypesAuthTestCase(base.ServiceAPITest):
    """
    Base class to test keystone/logic/types/auth.py
    """
    def __init__(self, *args, **kwargs):
        super(LogicTypesAuthTestCase, self).__init__(*args, **kwargs)

        self.user = models.User(id='u1', name='john', username='john')
        self.role = models.Role(id=1, name='Admin')
        self.user.rolegrants = models.Roles([self.role], links=None)
        self.token = models.Token(id='abc123T', user_id=self.user.id,
                                  expires=datetime.date(2000, 1, 31))
        self.tenant = models.Tenant(id='ten8', name='The Tenant')
        self.token.tenant = self.tenant
        self.base_urls = [models.EndpointTemplate(
                    id="1",
                    internal_url="http://127.0.0.1/v1/%tenant_id%",
                    public_url="http://internet.com/v1/%tenant_id%",
                    admin_url="http://private.net/v1/",
                    version_id="v1",
                    version_url="http://127.0.0.1/v1/",
                    version_info="http://127.0.0.1/",
                    region="RegionOne",
                    service_id="0"
                ),
                models.EndpointTemplate(
                    id="2",
                    internal_url="http://127.0.0.1/v1/%tenant_id%",
                    public_url="http://internet.com/v1/%tenant_id%",
                    service_id="0"
                )]
        self.url_types = ["internal", "public", "admin"]

    def test_AuthData_json_serialization(self):
        auth = logic_auth.AuthData(self.token, self.user)
        data = json.loads(auth.to_json())
        expected = {
            'access': {
                'token': {
                    'expires': '2000-01-31',
                    'tenants': [{
                        'id': 'ten8',
                        'name': 'The Tenant'
                    }],
                    'id': 'abc123T',
                    'tenant': {
                        'id': 'ten8',
                        'name': 'The Tenant'
                    }
                },
                'user': {
                    'id': 'u1',
                    'roles': [{
                        'name': 'Admin',
                        'id': '1'
                    }],
                    'name': 'john'
                }
            }
        }
        self.assertDictEqual(data, expected)

    def test_AuthData_xml_serialization(self):
        auth = logic_auth.AuthData(self.token, self.user)
        xml_str = auth.to_xml()
        expected = ('<access xmlns='
                '"http://docs.openstack.org/identity/api/v2.0"><token expires='
                '"2000-01-31" id="abc123T"><tenant name="The Tenant" '
                'id="ten8"/></token><user name="john" id="u1"><roles '
                'xmlns="http://docs.openstack.org/identity/api/v2.0"><role '
                'xmlns="http://docs.openstack.org/identity/api/v2.0" id="1" '
                'name="Admin"/></roles></user></access>')
        self.assertTrue(test_utils.XMLTools.xmlEqual(xml_str, expected))

    def test_AuthData_json_catalog(self):
        auth = logic_auth.AuthData(self.token, self.user, self.base_urls)
        data = json.loads(auth.to_json())
        self.assertIn("access", data)
        self.assertIn("serviceCatalog", data['access'])
        catalog = data['access']['serviceCatalog']
        self.assertTrue(len(catalog) > 0)
        endpoints = catalog[0]['endpoints']
        self.assertTrue(len(endpoints) > 1)
        endpoint = endpoints[0]
        self.assertIn("publicURL", endpoint)
        self.assertIn("versionId", endpoint)
        self.assertIn("tenantId", endpoint)

        endpoint = endpoints[1]
        self.assertNotIn("versionId", endpoint)

    def test_AuthData_xml_catalog(self):
        auth = logic_auth.AuthData(self.token, self.user, self.base_urls)
        xml_str = auth.to_xml()
        dom = etree.fromstring(xml_str)
        xmlns = "http://docs.openstack.org/identity/api/v2.0"
        catalog = dom.find("{%s}serviceCatalog" % xmlns)
        service = catalog.find("{%s}service" % xmlns)
        endpoint = service.find("{%s}endpoint" % xmlns)
        self.assertIsNotNone("publicURL", endpoint.attrib)
        self.assertIn("versionId", endpoint.attrib)
        self.assertIn("tenantId", endpoint.attrib)


if __name__ == '__main__':
    unittest.main()
