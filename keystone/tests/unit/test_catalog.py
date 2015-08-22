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

from six.moves import http_client

from keystone import catalog
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import rest


BASE_URL = 'http://127.0.0.1:35357/v2'
SERVICE_FIXTURE = object()


class V2CatalogTestCase(rest.RestfulTestCase):
    def setUp(self):
        super(V2CatalogTestCase, self).setUp()
        self.useFixture(database.Database())

        self.service_id = uuid.uuid4().hex
        self.service = unit.new_service_ref()
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
        self.config_fixture.config(group='catalog', driver='sql')

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

    def _region_create(self):
        region_id = uuid.uuid4().hex
        self.catalog_api.create_region({'id': region_id})
        return region_id

    def _service_create(self):
        service_id = uuid.uuid4().hex
        service = unit.new_service_ref()
        service['id'] = service_id
        self.catalog_api.create_service(service_id, service)
        return service_id

    def test_endpoint_create(self):
        req_body, response = self._endpoint_create()
        self.assertIn('endpoint', response.result)
        self.assertIn('id', response.result['endpoint'])
        for field, value in req_body['endpoint'].items():
            self.assertEqual(response.result['endpoint'][field], value)

    def test_pure_v3_endpoint_with_publicurl_visible_from_v2(self):
        """Test pure v3 endpoint can be fetched via v2 API.

        For those who are using v2 APIs, endpoints created by v3 API should
        also be visible as there are no differences about the endpoints
        except the format or the internal implementation.
        And because public url is required for v2 API, so only the v3 endpoints
        of the service which has the public interface endpoint will be
        converted into v2 endpoints.
        """
        region_id = self._region_create()
        service_id = self._service_create()
        # create a v3 endpoint with three interfaces
        body = {
            'endpoint': unit.new_endpoint_ref(service_id,
                                              default_region_id=region_id)
        }
        for interface in catalog.controllers.INTERFACES:
            body['endpoint']['interface'] = interface
            self.admin_request(method='POST',
                               token=self.get_scoped_token(),
                               path='/v3/endpoints',
                               expected_status=http_client.CREATED,
                               body=body)

        r = self.admin_request(token=self.get_scoped_token(),
                               path='/v2.0/endpoints')
        # v3 endpoints having public url can be fetched via v2.0 API
        self.assertEqual(1, len(r.result['endpoints']))
        v2_endpoint = r.result['endpoints'][0]
        self.assertEqual(service_id, v2_endpoint['service_id'])
        # check urls just in case.
        # This is not the focus of this test, so no different urls are used.
        self.assertEqual(body['endpoint']['url'], v2_endpoint['publicurl'])
        self.assertEqual(body['endpoint']['url'], v2_endpoint['adminurl'])
        self.assertEqual(body['endpoint']['url'], v2_endpoint['internalurl'])
        self.assertNotIn('name', v2_endpoint)

        v3_endpoint = self.catalog_api.get_endpoint(v2_endpoint['id'])
        # it's the v3 public endpoint's id as the generated v2 endpoint
        self.assertEqual('public', v3_endpoint['interface'])
        self.assertEqual(service_id, v3_endpoint['service_id'])

    def test_pure_v3_endpoint_without_publicurl_invisible_from_v2(self):
        """Test pure v3 endpoint without public url can't be fetched via v2 API.

        V2 API will return endpoints created by v3 API, but because public url
        is required for v2 API, so v3 endpoints without public url will be
        ignored.
        """
        region_id = self._region_create()
        service_id = self._service_create()
        # create a v3 endpoint without public interface
        body = {
            'endpoint': unit.new_endpoint_ref(service_id,
                                              default_region_id=region_id)
        }
        for interface in catalog.controllers.INTERFACES:
            if interface == 'public':
                continue
            body['endpoint']['interface'] = interface
            self.admin_request(method='POST',
                               token=self.get_scoped_token(),
                               path='/v3/endpoints',
                               expected_status=http_client.CREATED,
                               body=body)

        r = self.admin_request(token=self.get_scoped_token(),
                               path='/v2.0/endpoints')
        # v3 endpoints without public url won't be fetched via v2.0 API
        self.assertEqual(0, len(r.result['endpoints']))

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
        self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                              publicurl=None)

    def test_endpoint_create_with_empty_publicurl(self):
        self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                              publicurl='')

    def test_endpoint_create_with_null_service_id(self):
        self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                              service_id=None)

    def test_endpoint_create_with_empty_service_id(self):
        self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                              service_id='')

    def test_endpoint_create_with_valid_url(self):
        """Create endpoint with valid URL should be tested, too."""
        # list one valid url is enough, no need to list too much
        valid_url = 'http://127.0.0.1:8774/v1.1/$(tenant_id)s'

        # baseline tests that all valid URLs works
        self._endpoint_create(expected_status=200,
                              publicurl=valid_url,
                              internalurl=valid_url,
                              adminurl=valid_url)

    def test_endpoint_create_with_invalid_url(self):
        """Test the invalid cases: substitutions is not exactly right."""
        invalid_urls = [
            # using a substitution that is not whitelisted - KeyError
            'http://127.0.0.1:8774/v1.1/$(nonexistent)s',

            # invalid formatting - ValueError
            'http://127.0.0.1:8774/v1.1/$(tenant_id)',
            'http://127.0.0.1:8774/v1.1/$(tenant_id)t',
            'http://127.0.0.1:8774/v1.1/$(tenant_id',

            # invalid type specifier - TypeError
            # admin_url is a string not an int
            'http://127.0.0.1:8774/v1.1/$(admin_url)d',
        ]

        # list one valid url is enough, no need to list too much
        valid_url = 'http://127.0.0.1:8774/v1.1/$(tenant_id)s'

        # Case one: publicurl, internalurl and adminurl are
        # all invalid
        for invalid_url in invalid_urls:
            self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                                  publicurl=invalid_url,
                                  internalurl=invalid_url,
                                  adminurl=invalid_url)

        # Case two: publicurl, internalurl are invalid
        # and adminurl is valid
        for invalid_url in invalid_urls:
            self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                                  publicurl=invalid_url,
                                  internalurl=invalid_url,
                                  adminurl=valid_url)

        # Case three: publicurl, adminurl are invalid
        # and internalurl is valid
        for invalid_url in invalid_urls:
            self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                                  publicurl=invalid_url,
                                  internalurl=valid_url,
                                  adminurl=invalid_url)

        # Case four: internalurl, adminurl are invalid
        # and publicurl is valid
        for invalid_url in invalid_urls:
            self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                                  publicurl=valid_url,
                                  internalurl=invalid_url,
                                  adminurl=invalid_url)

        # Case five: publicurl is invalid, internalurl
        # and adminurl are valid
        for invalid_url in invalid_urls:
            self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                                  publicurl=invalid_url,
                                  internalurl=valid_url,
                                  adminurl=valid_url)

        # Case six: internalurl is invalid, publicurl
        # and adminurl are valid
        for invalid_url in invalid_urls:
            self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                                  publicurl=valid_url,
                                  internalurl=invalid_url,
                                  adminurl=valid_url)

        # Case seven: adminurl is invalid, publicurl
        # and internalurl are valid
        for invalid_url in invalid_urls:
            self._endpoint_create(expected_status=http_client.BAD_REQUEST,
                                  publicurl=valid_url,
                                  internalurl=valid_url,
                                  adminurl=invalid_url)


class TestV2CatalogAPISQL(unit.TestCase):

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
        self.config_fixture.config(group='catalog', driver='sql')

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
