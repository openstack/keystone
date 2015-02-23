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

from keystone import catalog
from keystone.tests import unit as tests
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import rest


BASE_URL = 'http://127.0.0.1:35357/v2'
SERVICE_FIXTURE = object()


class V2CatalogTestCase(rest.RestfulTestCase):
    def setUp(self):
        super(V2CatalogTestCase, self).setUp()
        self.useFixture(database.Database())

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

    def config_overrides(self):
        super(V2CatalogTestCase, self).config_overrides()
        self.config_fixture.config(
            group='catalog',
            driver='keystone.catalog.backends.sql.Catalog')

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
        self.assertIn('endpoint', response.result)
        self.assertIn('id', response.result['endpoint'])
        for field, value in six.iteritems(req_body['endpoint']):
            self.assertEqual(response.result['endpoint'][field], value)

    def test_endpoint_create_with_null_adminurl(self):
        req_body, response = self._endpoint_create(adminurl=None)
        self.assertIsNone(req_body['endpoint']['adminurl'])
        self.assertNotIn('adminurl', response.result['endpoint'])

    def test_endpoint_create_with_empty_adminurl(self):
        req_body, response = self._endpoint_create(adminurl='')
        self.assertEqual('', req_body['endpoint']['adminurl'])
        self.assertNotIn("adminurl", response.result['endpoint'])

    def test_endpoint_create_with_null_internalurl(self):
        req_body, response = self._endpoint_create(internalurl=None)
        self.assertIsNone(req_body['endpoint']['internalurl'])
        self.assertNotIn('internalurl', response.result['endpoint'])

    def test_endpoint_create_with_empty_internalurl(self):
        req_body, response = self._endpoint_create(internalurl='')
        self.assertEqual('', req_body['endpoint']['internalurl'])
        self.assertNotIn("internalurl", response.result['endpoint'])

    def test_endpoint_create_with_null_publicurl(self):
        self._endpoint_create(expected_status=400, publicurl=None)

    def test_endpoint_create_with_empty_publicurl(self):
        self._endpoint_create(expected_status=400, publicurl='')

    def test_endpoint_create_with_null_service_id(self):
        self._endpoint_create(expected_status=400, service_id=None)

    def test_endpoint_create_with_empty_service_id(self):
        self._endpoint_create(expected_status=400, service_id='')


class TestV2CatalogAPISQL(tests.TestCase):

    def setUp(self):
        super(TestV2CatalogAPISQL, self).setUp()
        self.useFixture(database.Database())
        self.catalog_api = catalog.Manager()

        self.service_id = uuid.uuid4().hex
        service = {'id': self.service_id, 'name': uuid.uuid4().hex}
        self.catalog_api.create_service(self.service_id, service)

        endpoint = self.new_endpoint_ref(service_id=self.service_id)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

    def config_overrides(self):
        super(TestV2CatalogAPISQL, self).config_overrides()
        self.config_fixture.config(
            group='catalog',
            driver='keystone.catalog.backends.sql.Catalog')

    def new_endpoint_ref(self, service_id):
        return {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'interface': uuid.uuid4().hex[:8],
            'service_id': service_id,
            'url': uuid.uuid4().hex,
            'region': uuid.uuid4().hex,
        }

    def test_get_catalog_ignores_endpoints_with_invalid_urls(self):
        user_id = uuid.uuid4().hex
        tenant_id = uuid.uuid4().hex

        # the only endpoint in the catalog is the one created in setUp
        catalog = self.catalog_api.get_catalog(user_id, tenant_id)
        self.assertEqual(1, len(catalog))
        # it's also the only endpoint in the backend
        self.assertEqual(1, len(self.catalog_api.list_endpoints()))

        # create a new, invalid endpoint - malformed type declaration
        endpoint = self.new_endpoint_ref(self.service_id)
        endpoint['url'] = 'http://keystone/%(tenant_id)'
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # create a new, invalid endpoint - nonexistent key
        endpoint = self.new_endpoint_ref(self.service_id)
        endpoint['url'] = 'http://keystone/%(you_wont_find_me)s'
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # verify that the invalid endpoints don't appear in the catalog
        catalog = self.catalog_api.get_catalog(user_id, tenant_id)
        self.assertEqual(1, len(catalog))
        # all three endpoints appear in the backend
        self.assertEqual(3, len(self.catalog_api.list_endpoints()))

    def test_get_catalog_always_returns_service_name(self):
        user_id = uuid.uuid4().hex
        tenant_id = uuid.uuid4().hex

        # create a service, with a name
        named_svc = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(named_svc['id'], named_svc)
        endpoint = self.new_endpoint_ref(service_id=named_svc['id'])
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # create a service, with no name
        unnamed_svc = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex
        }
        self.catalog_api.create_service(unnamed_svc['id'], unnamed_svc)
        endpoint = self.new_endpoint_ref(service_id=unnamed_svc['id'])
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        region = None
        catalog = self.catalog_api.get_catalog(user_id, tenant_id)

        self.assertEqual(named_svc['name'],
                         catalog[region][named_svc['type']]['name'])
        self.assertEqual('', catalog[region][unnamed_svc['type']]['name'])
