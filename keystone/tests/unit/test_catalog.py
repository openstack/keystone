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

        self.service = unit.new_service_ref()
        self.service_id = self.service['id']
        self.catalog_api.create_service(self.service_id, self.service)

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

    def _endpoint_create(self, expected_status=http_client.OK,
                         service_id=SERVICE_FIXTURE,
                         publicurl='http://localhost:8080',
                         internalurl='http://localhost:8080',
                         adminurl='http://localhost:8080',
                         region='RegionOne'):
        if service_id is SERVICE_FIXTURE:
            service_id = self.service_id

        path = '/v2.0/endpoints'
        body = {
            'endpoint': {
                'adminurl': adminurl,
                'service_id': service_id,
                'internalurl': internalurl,
                'publicurl': publicurl
            }
        }
        if region is not None:
            body['endpoint']['region'] = region

        r = self.admin_request(method='POST', token=self.get_scoped_token(),
                               path=path, expected_status=expected_status,
                               body=body)
        return body, r

    def _region_create(self):
        region = unit.new_region_ref()
        region_id = region['id']
        self.catalog_api.create_region(region)
        return region_id

    def test_endpoint_create(self):
        req_body, response = self._endpoint_create()
        self.assertIn('endpoint', response.result)
        self.assertIn('id', response.result['endpoint'])
        for field, value in req_body['endpoint'].items():
            self.assertEqual(value, response.result['endpoint'][field])

    def test_endpoint_create_without_region(self):
        req_body, response = self._endpoint_create(region=None)
        self.assertIn('endpoint', response.result)
        self.assertIn('id', response.result['endpoint'])
        self.assertNotIn('region', response.result['endpoint'])
        for field, value in req_body['endpoint'].items():
            self.assertEqual(value, response.result['endpoint'][field])

    def test_pure_v3_endpoint_with_publicurl_visible_from_v2(self):
        """Test pure v3 endpoint can be fetched via v2.0 API.

        For those who are using v2.0 APIs, endpoints created by v3 API should
        also be visible as there are no differences about the endpoints
        except the format or the internal implementation. Since publicURL is
        required for v2.0 API, so only v3 endpoints of the service which have
        the public interface endpoint will be converted into v2.0 endpoints.
        """
        region_id = self._region_create()

        # create v3 endpoints with three interfaces
        body = {
            'endpoint': unit.new_endpoint_ref(self.service_id,
                                              region_id=region_id)
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
        # Endpoints of the service which have a public interface endpoint
        # will be returned via v2.0 API
        self.assertEqual(1, len(r.result['endpoints']))
        v2_endpoint = r.result['endpoints'][0]
        self.assertEqual(self.service_id, v2_endpoint['service_id'])
        # This is not the focus of this test, so no different urls are used.
        self.assertEqual(body['endpoint']['url'], v2_endpoint['publicurl'])
        self.assertEqual(body['endpoint']['url'], v2_endpoint['adminurl'])
        self.assertEqual(body['endpoint']['url'], v2_endpoint['internalurl'])
        self.assertNotIn('name', v2_endpoint)

        v3_endpoint = self.catalog_api.get_endpoint(v2_endpoint['id'])
        # Checks the v3 public endpoint's id is the generated v2.0 endpoint
        self.assertEqual('public', v3_endpoint['interface'])
        self.assertEqual(self.service_id, v3_endpoint['service_id'])

    def test_pure_v3_endpoint_without_publicurl_invisible_from_v2(self):
        """Test that the v2.0 API can't fetch v3 endpoints without publicURLs.

        v2.0 API will return endpoints created by v3 API, but publicURL is
        required for the service in the v2.0 API, therefore v3 endpoints of
        a service which don't have publicURL will be ignored.
        """
        region_id = self._region_create()

        # create a v3 endpoint without public interface
        body = {
            'endpoint': unit.new_endpoint_ref(self.service_id,
                                              region_id=region_id)
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
        # v3 endpoints of a service which don't have publicURL can't be
        # fetched via v2.0 API
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
        self._endpoint_create(expected_status=http_client.OK,
                              publicurl=valid_url,
                              internalurl=valid_url,
                              adminurl=valid_url)

    def test_endpoint_create_with_invalid_url(self):
        """Test the invalid cases: substitutions is not exactly right."""
        invalid_urls = [
            # using a substitution that is not whitelisted - KeyError
            'http://127.0.0.1:8774/v1.1/$(nonexistent)s',

            # invalid formatting - ValueError
            'http://127.0.0.1:8774/v1.1/$(project_id)',
            'http://127.0.0.1:8774/v1.1/$(project_id)t',
            'http://127.0.0.1:8774/v1.1/$(project_id',

            # invalid type specifier - TypeError
            # admin_url is a string not an int
            'http://127.0.0.1:8774/v1.1/$(admin_url)d',
        ]

        # list one valid url is enough, no need to list too much
        valid_url = 'http://127.0.0.1:8774/v1.1/$(project_id)s'

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

        service = unit.new_service_ref()
        self.service_id = service['id']
        self.catalog_api.create_service(self.service_id, service)

        self.create_endpoint(service_id=self.service_id)

    def create_endpoint(self, service_id, **kwargs):
        endpoint = unit.new_endpoint_ref(service_id=service_id,
                                         region_id=None,
                                         **kwargs)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)
        return endpoint

    def config_overrides(self):
        super(TestV2CatalogAPISQL, self).config_overrides()
        self.config_fixture.config(group='catalog', driver='sql')

    def test_get_catalog_ignores_endpoints_with_invalid_urls(self):
        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex

        # the only endpoint in the catalog is the one created in setUp
        catalog = self.catalog_api.get_catalog(user_id, project_id)
        self.assertEqual(1, len(catalog))
        # it's also the only endpoint in the backend
        self.assertEqual(1, len(self.catalog_api.list_endpoints()))

        # create a new, invalid endpoint - malformed type declaration
        self.create_endpoint(self.service_id,
                             url='http://keystone/%(project_id)')

        # create a new, invalid endpoint - nonexistent key
        self.create_endpoint(self.service_id,
                             url='http://keystone/%(you_wont_find_me)s')

        # verify that the invalid endpoints don't appear in the catalog
        catalog = self.catalog_api.get_catalog(user_id, project_id)
        self.assertEqual(1, len(catalog))
        # all three endpoints appear in the backend
        self.assertEqual(3, len(self.catalog_api.list_endpoints()))

    def test_get_catalog_always_returns_service_name(self):
        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex

        # new_service_ref() returns a ref with a `name`.
        named_svc = unit.new_service_ref()
        self.catalog_api.create_service(named_svc['id'], named_svc)
        self.create_endpoint(service_id=named_svc['id'])

        # This time manually delete the generated `name`.
        unnamed_svc = unit.new_service_ref()
        del unnamed_svc['name']
        self.catalog_api.create_service(unnamed_svc['id'], unnamed_svc)
        self.create_endpoint(service_id=unnamed_svc['id'])

        region = None
        catalog = self.catalog_api.get_catalog(user_id, project_id)

        self.assertEqual(named_svc['name'],
                         catalog[region][named_svc['type']]['name'])

        # verify a name is not generated when the service is passed to the API
        self.assertEqual('', catalog[region][unnamed_svc['type']]['name'])
