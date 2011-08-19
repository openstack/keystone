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
                                '..', '..', '..', '..', '..', 'keystone')))
import unittest2 as unittest

import test_common as utils
from test_common import URL_V2

from keystone.logic.types import fault


class ServicesTest(unittest.TestCase):
    def setUp(self):
        self.auth_token = utils.get_auth_token()
        self.service_token = utils.get_service_token()
        self.missing_token = utils.get_none_token()
        self.invalid_token = utils.get_non_existing_token()
        self.disabled_token = utils.get_disabled_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.user = utils.get_user()
        self.tenant = utils.get_tenant()
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.create_user(self.tenant, self.user, self.auth_token)
        self.sample_service = 'sampleservice'
        self.test_service = 'test_service'
        self.token = utils.get_token(self.user, 'secrete', self.tenant,
                                     'token')
        utils.create_service(self.sample_service, str(self.auth_token))

    def tearDown(self):
        utils.delete_user(self.user, self.auth_token)
        utils.delete_tenant(self.tenant, self.auth_token)
        utils.delete_service(self.sample_service, str(self.auth_token))


class GetServicesTest(ServicesTest):
        def test_get_services_using_keystone_admin_token_json(self):
            resp, content = utils.get_services(self.auth_token)
            self.assertEqual(200, int(resp['status']))
            #verify content
            obj = json.loads(content)
            if not "services" in obj:
                raise self.fail("Expecting Services")
            services = obj["services"]["values"]
            if len(services) < 1:
                self.fail("Services not of required length.")
            is_service_found = None
            for service in services:
                if service["id"] in [self.sample_service]:
                    is_service_found = True
            if not is_service_found:
                raise self.fail("Service not found")

        def test_get_services_using_keystone_admin_token_xml(self):
            resp, content = utils.get_services_xml(self.auth_token)
            self.assertEqual(200, int(resp['status']))
            # verify content
            # Validate Returned Content
            dom = etree.Element("root")
            dom.append(etree.fromstring(content))
            services = dom.find(
                "{http://docs.openstack.org/identity/api/v2.0}" \
                "services")
            if services == None:
                self.fail("Expecting Services")
            services = services.findall(
                "{http://docs.openstack.org/identity/api/v2.0}" \
                "service")
            if len(services) < 1:
                self.fail("Not the expected Service count")
            for service in services:
                if service.get("id") in [self.sample_service]:
                    is_service_found = True
            if not is_service_found:
                raise self.fail("Service not found")

        def test_get_services_using_service_admin_token(self):
            resp, content = utils.get_services(self.service_token)
            self.assertEqual(200, int(resp['status']))
            #verify content
            obj = json.loads(content)
            if not "services" in obj:
                raise self.fail("Expecting Services")
            services = obj["services"]["values"]
            if len(services) < 1:
                self.fail("Services not of required length.")
            is_service_found = None
            for service in services:
                if service["id"] in [self.sample_service]:
                    is_service_found = True
            if not is_service_found:
                raise self.fail("Service not found")

        def test_get_services_using_service_admin_token_xml(self):
            resp, content = utils.get_services_xml(self.service_token)
            self.assertEqual(200, int(resp['status']))
            # Verify content
            # Validate Returned Content
            dom = etree.Element("root")
            dom.append(etree.fromstring(content))
            services = dom.find(
                "{http://docs.openstack.org/identity/api/v2.0}" \
                "services")
            if services == None:
                self.fail("Expecting Services")
            services = services.findall(
                "{http://docs.openstack.org/identity/api/v2.0}" \
                "service")
            if len(services) < 1:
                self.fail("Not the expected Service count")
            for service in services:
                if service.get("id") in [self.sample_service]:
                    is_service_found = True
            if not is_service_found:
                raise self.fail("Service not found")

        def test_get_services_using_invalid_tokens(self):
            resp, content = utils.get_services(self.disabled_token)
            self.assertEqual(403, int(resp['status']))
            resp, content = utils.get_services(self.missing_token)
            self.assertEqual(401, int(resp['status']))
            resp, content = utils.get_services(self.exp_auth_token)
            self.assertEqual(403, int(resp['status']))
            resp, content = utils.get_services(self.invalid_token)
            self.assertEqual(404, int(resp['status']))


class GetServiceTest(ServicesTest):
    def test_service_get_json(self):
        resp, _content = utils.get_service(
            self.sample_service, str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(200, resp_val)

    def test_service_get_xml(self):
        resp, _content = utils.get_service_xml(
            self.sample_service, str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(200, resp_val)

    def test_service_get_using_expired_token(self):
        resp, _content = utils.get_service(
            self.sample_service, str(self.exp_auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(403, resp_val)

    def test_service_get_using_disabled_token(self):
        resp, _content = utils.get_service(
            self.sample_service, str(self.disabled_token))
        resp_val = int(resp['status'])
        self.assertEqual(403, resp_val)

    def test_service_get_json_using_missing_token(self):
        resp, _content = utils.get_service(
            self.sample_service, str(self.missing_token))
        resp_val = int(resp['status'])
        self.assertEqual(401, resp_val)

    def test_service_get_json_using_invalid_token(self):
        resp, _content = utils.get_service(
            self.sample_service, str(self.invalid_token))
        resp_val = int(resp['status'])
        self.assertEqual(404, resp_val)

    def test_get_service_using_invalid_tokens(self):
        resp, content = utils.get_service(
            self.sample_service, self.disabled_token)
        self.assertEqual(403, int(resp['status']))
        resp, content = utils.get_service(
            self.sample_service, self.missing_token)
        self.assertEqual(401, int(resp['status']))
        resp, content = utils.get_service(
            self.sample_service, self.exp_auth_token)
        self.assertEqual(403, int(resp['status']))
        resp, content = utils.get_service(
            self.sample_service, self.invalid_token)
        self.assertEqual(404, int(resp['status']))

    def test_get_service_using_invalid_tokens(self):
        resp, content = utils.get_service(
            self.sample_service, self.disabled_token)
        self.assertEqual(403, int(resp['status']))

        resp, content = utils.get_service(
            self.sample_service, self.missing_token)
        self.assertEqual(401, int(resp['status']))

        resp, content = utils.get_service(
            self.sample_service, self.exp_auth_token)
        self.assertEqual(403, int(resp['status']))

        resp, content = utils.get_service(
            self.sample_service, self.invalid_token)
        self.assertEqual(404, int(resp['status']))


class CreateServiceTest(ServicesTest):
    def test_service_create_json(self):
        resp, _content = utils.create_service(
            self.test_service, str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)
        utils.delete_service(self.test_service, self.auth_token)

    def test_service_create_xml(self):
        resp, _content = utils.create_service_xml(
            self.test_service, str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)

    def test_service_create_duplicate_json(self):
        resp, _content = utils.create_service(
            self.test_service, str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)
        resp, _content = utils.create_service(
            self.test_service, str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(409, resp_val)
        utils.delete_service(self.test_service, self.auth_token)

    def test_service_create_using_expired_token(self):
        resp, _content = utils.create_service(
            self.test_service, str(self.exp_auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(403, resp_val)

    def test_service_create_using_disabled_token(self):
        resp, _content = utils.create_service(
            self.test_service, str(self.disabled_token))
        resp_val = int(resp['status'])
        self.assertEqual(403, resp_val)

    def test_service_create_json_using_missing_token(self):
        resp, _content = utils.create_service(
            self.test_service, str(self.missing_token))
        resp_val = int(resp['status'])
        self.assertEqual(401, resp_val)

    def test_service_create_json_using_invalid_token(self):
        resp, _content = utils.create_service(
            self.test_service, str(self.invalid_token))
        resp_val = int(resp['status'])
        self.assertEqual(404, resp_val)


class DeleteServiceTest(ServicesTest):
    def test_service_delete(self):
        resp, _content = utils.delete_service(
            self.test_service, self.auth_token)
        resp_val = int(resp['status'])
        self.assertEqual(204, resp_val)

    def test_service_which_has_dependencies_delete(self):
        resp, _content = utils.create_service(
            self.test_service, str(self.auth_token))
        resp, _content = utils.create_role_mapped_to_service(
            self.test_service + ":test_role",
            self.auth_token, self.test_service)
        self.assertEqual(201, int(resp['status']))
        resp, _content = utils.create_role_ref(
            self.user, self.test_service +
            ":test_role", self.tenant, self.auth_token)
        self.assertEqual(201, int(resp['status']))
        resp, _content = utils.create_endpoint_template(\
            'DFW', self.test_service, 'public_url',\
            'admin_url', 'internal_url', True, False, self.auth_token)
        self.assertEqual(201, int(resp['status']))

        #verify content
        obj = json.loads(_content)
        if not "endpointTemplate" in obj:
            raise fault.BadRequestFault("Expecting endpointTemplate")
        endpoint_template = obj["endpointTemplate"]
        if not "id" in endpoint_template:
            endpoint_template_id = None
        else:
            endpoint_template_id = endpoint_template["id"]
        resp, _content = utils.create_endpoint_xml(self.tenant,
            endpoint_template_id,
            str(self.auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(201, resp_val)

        resp, _content = utils.delete_service(
            self.test_service, self.auth_token)
        resp_val = int(resp['status'])
        self.assertEqual(204, resp_val)

    def test_service_delete_json_using_expired_token(self):
        resp, _content = utils.delete_service(
            self.test_service, str(self.exp_auth_token))
        resp_val = int(resp['status'])
        self.assertEqual(403, resp_val)

    def test_service_delete_json_using_disabled_token(self):
        resp, _content = utils.delete_service(
            self.test_service, str(self.disabled_token))
        resp_val = int(resp['status'])
        self.assertEqual(403, resp_val)

    def test_service_delete_json_using_missing_token(self):
        resp, _content = utils.delete_service(
            self.test_service, str(self.missing_token))
        resp_val = int(resp['status'])
        self.assertEqual(401, resp_val)

    def test_service_delete_json_using_invalid_token(self):
        resp, _content = utils.delete_service(
            self.test_service, str(self.invalid_token))
        resp_val = int(resp['status'])
        self.assertEqual(404, resp_val)

    def test_service_delete_json_using_disabled_token(self):
        resp, _content = utils.delete_service(
            self.test_service, str(self.disabled_token))
        resp_val = int(resp['status'])
        self.assertEqual(403, resp_val)

if __name__ == '__main__':
    unittest.main()
