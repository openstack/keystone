# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid

import six

from keystone.tests import rest


BASE_URL = 'http://127.0.0.1:35357/v2'
SERVICE_FIXTURE = object()


class V2CatalogTestCase(rest.RestfulTestCase):
    def setUp(self):
        super(V2CatalogTestCase, self).setUp()
        self.service_id = uuid.uuid4().hex
        self.service = self.new_service_ref()
        self.service['id'] = self.service_id
        self.catalog_api.create_service(
            self.service_id,
            self.service.copy())

        # TODO(termie): add an admin user to the fixtures and use that user
        # override the fixtures, for now
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_admin['id'])

    def new_ref(self):
        """Populates a ref with attributes common to all API entities."""
        return {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'enabled': True}

    def new_service_ref(self):
        ref = self.new_ref()
        ref['type'] = uuid.uuid4().hex
        return ref

    def _get_token_id(self, r):
        """Applicable only to JSON."""
        return r.result['access']['token']['id']

    def _endpoint_create(self, expected_status=200, service_id=SERVICE_FIXTURE,
                         publicurl='http://localhost:8080',
                         internalurl='http://localhost:8080',
                         adminurl='http://localhost:8080'):
        if service_id is SERVICE_FIXTURE:
            service_id = self.service_id
        # FIXME(dolph): expected status should actually be 201 Created
        path = '/v2.0/endpoints'
        body = {
            'endpoint': {
                'adminurl': adminurl,
                'service_id': service_id,
                'region': 'RegionOne',
                'internalurl': internalurl,
                'publicurl': publicurl
            }
        }

        r = self.admin_request(method='POST', token=self.get_scoped_token(),
                               path=path, expected_status=expected_status,
                               body=body)
        return body, r

    def test_endpoint_create(self):
        req_body, response = self._endpoint_create()
        self.assertTrue('endpoint' in response.result)
        self.assertTrue('id' in response.result['endpoint'])
        for field, value in six.iteritems(req_body['endpoint']):
            self.assertEqual(response.result['endpoint'][field], value)

    def test_endpoint_create_with_null_adminurl(self):
        req_body, response = self._endpoint_create(adminurl=None)
        self.assertEqual(req_body['endpoint']['adminurl'], None)
        self.assertNotIn('adminurl', response.result['endpoint'])

    def test_endpoint_create_with_empty_adminurl(self):
        req_body, response = self._endpoint_create(adminurl='')
        self.assertEqual(req_body['endpoint']['adminurl'], '')
        self.assertNotIn("adminurl", response.result['endpoint'])

    def test_endpoint_create_with_null_internalurl(self):
        req_body, response = self._endpoint_create(internalurl=None)
        self.assertEqual(req_body['endpoint']['internalurl'], None)
        self.assertNotIn('internalurl', response.result['endpoint'])

    def test_endpoint_create_with_empty_internalurl(self):
        req_body, response = self._endpoint_create(internalurl='')
        self.assertEqual(req_body['endpoint']['internalurl'], '')
        self.assertNotIn("internalurl", response.result['endpoint'])

    def test_endpoint_create_with_null_publicurl(self):
        self._endpoint_create(expected_status=400, publicurl=None)

    def test_endpoint_create_with_empty_publicurl(self):
        self._endpoint_create(expected_status=400, publicurl='')

    def test_endpoint_create_with_null_service_id(self):
        self._endpoint_create(expected_status=400, service_id=None)

    def test_endpoint_create_with_empty_service_id(self):
        self._endpoint_create(expected_status=400, service_id='')
