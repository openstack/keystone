# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

    def assertValidErrorResponse(self, response):
        self.assertEqual(response.status_code, 400)

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
                'region': 'regionOne',
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
        for field, value in req_body['endpoint'].iteritems():
            self.assertEqual(response.result['endpoint'][field], value)

    def test_endpoint_create_with_null_adminurl(self):
        self._endpoint_create(adminurl=None)

    def test_endpoint_create_with_null_internalurl(self):
        self._endpoint_create(internalurl=None)

    def test_endpoint_create_with_null_publicurl(self):
        self._endpoint_create(expected_status=400, publicurl=None)
