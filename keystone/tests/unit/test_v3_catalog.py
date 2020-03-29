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

import copy
import uuid

import http.client
from testtools import matchers

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import test_v3

PROVIDERS = provider_api.ProviderAPIs


class CatalogTestCase(test_v3.RestfulTestCase):
    """Test service & endpoint CRUD."""

    # region crud tests

    def test_create_region_with_id(self):
        """Call ``PUT /regions/{region_id}`` w/o an ID in the request body."""
        ref = unit.new_region_ref()
        region_id = ref.pop('id')
        r = self.put(
            '/regions/%s' % region_id,
            body={'region': ref},
            expected_status=http.client.CREATED)
        self.assertValidRegionResponse(r, ref)
        # Double-check that the region ID was kept as-is and not
        # populated with a UUID, as is the case with POST /v3/regions
        self.assertEqual(region_id, r.json['region']['id'])

    def test_create_region_with_matching_ids(self):
        """Call ``PUT /regions/{region_id}`` with an ID in the request body."""
        ref = unit.new_region_ref()
        region_id = ref['id']
        r = self.put(
            '/regions/%s' % region_id,
            body={'region': ref},
            expected_status=http.client.CREATED)
        self.assertValidRegionResponse(r, ref)
        # Double-check that the region ID was kept as-is and not
        # populated with a UUID, as is the case with POST /v3/regions
        self.assertEqual(region_id, r.json['region']['id'])

    def test_create_region_with_duplicate_id(self):
        """Call ``PUT /regions/{region_id}``."""
        ref = unit.new_region_ref()
        region_id = ref['id']
        self.put(
            '/regions/%s' % region_id,
            body={'region': ref}, expected_status=http.client.CREATED)
        # Create region again with duplicate id
        self.put(
            '/regions/%s' % region_id,
            body={'region': ref}, expected_status=http.client.CONFLICT)

    def test_create_region(self):
        """Call ``POST /regions`` with an ID in the request body."""
        # the ref will have an ID defined on it
        ref = unit.new_region_ref()
        r = self.post(
            '/regions',
            body={'region': ref})
        self.assertValidRegionResponse(r, ref)

        # we should be able to get the region, having defined the ID ourselves
        r = self.get(
            '/regions/%(region_id)s' % {
                'region_id': ref['id']})
        self.assertValidRegionResponse(r, ref)

    def test_create_region_with_empty_id(self):
        """Call ``POST /regions`` with an empty ID in the request body."""
        ref = unit.new_region_ref(id='')

        r = self.post('/regions', body={'region': ref})
        self.assertValidRegionResponse(r, ref)
        self.assertNotEmpty(r.result['region'].get('id'))

    def test_create_region_without_id(self):
        """Call ``POST /regions`` without an ID in the request body."""
        ref = unit.new_region_ref()

        # instead of defining the ID ourselves...
        del ref['id']

        # let the service define the ID
        r = self.post('/regions', body={'region': ref})
        self.assertValidRegionResponse(r, ref)

    def test_create_region_without_description(self):
        """Call ``POST /regions`` without description in the request body."""
        ref = unit.new_region_ref(description=None)

        del ref['description']

        r = self.post('/regions', body={'region': ref})
        # Create the description in the reference to compare to since the
        # response should now have a description, even though we didn't send
        # it with the original reference.
        ref['description'] = ''
        self.assertValidRegionResponse(r, ref)

    def test_create_regions_with_same_description_string(self):
        """Call ``POST /regions`` with duplicate descriptions."""
        # NOTE(lbragstad): Make sure we can create two regions that have the
        # same description.
        region_desc = 'Some Region Description'

        ref1 = unit.new_region_ref(description=region_desc)
        ref2 = unit.new_region_ref(description=region_desc)

        resp1 = self.post('/regions', body={'region': ref1})
        self.assertValidRegionResponse(resp1, ref1)

        resp2 = self.post('/regions', body={'region': ref2})
        self.assertValidRegionResponse(resp2, ref2)

    def test_create_regions_without_descriptions(self):
        """Call ``POST /regions`` with no description."""
        # NOTE(lbragstad): Make sure we can create two regions that have
        # no description in the request body. The description should be
        # populated by Catalog Manager.
        ref1 = unit.new_region_ref()
        ref2 = unit.new_region_ref()

        del ref1['description']
        ref2['description'] = None

        resp1 = self.post('/regions', body={'region': ref1})

        resp2 = self.post('/regions', body={'region': ref2})
        # Create the descriptions in the references to compare to since the
        # responses should now have descriptions, even though we didn't send
        # a description with the original references.
        ref1['description'] = ''
        ref2['description'] = ''
        self.assertValidRegionResponse(resp1, ref1)
        self.assertValidRegionResponse(resp2, ref2)

    def test_create_region_with_conflicting_ids(self):
        """Call ``PUT /regions/{region_id}`` with conflicting region IDs."""
        # the region ref is created with an ID
        ref = unit.new_region_ref()

        # but instead of using that ID, make up a new, conflicting one
        self.put(
            '/regions/%s' % uuid.uuid4().hex,
            body={'region': ref},
            expected_status=http.client.BAD_REQUEST)

    def test_list_head_regions(self):
        """Call ``GET & HEAD /regions``."""
        resource_url = '/regions'
        r = self.get(resource_url)
        self.assertValidRegionListResponse(r, ref=self.region)
        self.head(resource_url, expected_status=http.client.OK)

    def _create_region_with_parent_id(self, parent_id=None):
        ref = unit.new_region_ref(parent_region_id=parent_id)
        return self.post(
            '/regions',
            body={'region': ref})

    def test_list_regions_filtered_by_parent_region_id(self):
        """Call ``GET /regions?parent_region_id={parent_region_id}``."""
        new_region = self._create_region_with_parent_id()
        parent_id = new_region.result['region']['id']

        new_region = self._create_region_with_parent_id(parent_id)
        new_region = self._create_region_with_parent_id(parent_id)

        r = self.get('/regions?parent_region_id=%s' % parent_id)

        for region in r.result['regions']:
            self.assertEqual(parent_id, region['parent_region_id'])

    def test_get_head_region(self):
        """Call ``GET & HEAD /regions/{region_id}``."""
        resource_url = '/regions/%(region_id)s' % {
            'region_id': self.region_id}
        r = self.get(resource_url)
        self.assertValidRegionResponse(r, self.region)
        self.head(resource_url, expected_status=http.client.OK)

    def test_update_region(self):
        """Call ``PATCH /regions/{region_id}``."""
        region = unit.new_region_ref()
        del region['id']
        r = self.patch('/regions/%(region_id)s' % {
            'region_id': self.region_id},
            body={'region': region})
        self.assertValidRegionResponse(r, region)

    def test_update_region_without_description_keeps_original(self):
        """Call ``PATCH /regions/{region_id}``."""
        region_ref = unit.new_region_ref()

        resp = self.post('/regions', body={'region': region_ref})

        region_updates = {
            # update with something that's not the description
            'parent_region_id': self.region_id,
        }
        resp = self.patch('/regions/%s' % region_ref['id'],
                          body={'region': region_updates})

        # NOTE(dstanek): Keystone should keep the original description.
        self.assertEqual(region_ref['description'],
                         resp.result['region']['description'])

    def test_update_region_with_null_description(self):
        """Call ``PATCH /regions/{region_id}``."""
        region = unit.new_region_ref(description=None)
        del region['id']
        r = self.patch('/regions/%(region_id)s' % {
            'region_id': self.region_id},
            body={'region': region})

        # NOTE(dstanek): Keystone should turn the provided None value into
        # an empty string before storing in the backend.
        region['description'] = ''
        self.assertValidRegionResponse(r, region)

    def test_delete_region(self):
        """Call ``DELETE /regions/{region_id}``."""
        ref = unit.new_region_ref()
        r = self.post(
            '/regions',
            body={'region': ref})
        self.assertValidRegionResponse(r, ref)

        self.delete('/regions/%(region_id)s' % {
            'region_id': ref['id']})

    # service crud tests

    def test_create_service(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref()
        r = self.post(
            '/services',
            body={'service': ref})
        self.assertValidServiceResponse(r, ref)

    def test_create_service_no_name(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref()
        del ref['name']
        r = self.post(
            '/services',
            body={'service': ref})
        ref['name'] = ''
        self.assertValidServiceResponse(r, ref)

    def test_create_service_no_enabled(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref()
        del ref['enabled']
        r = self.post(
            '/services',
            body={'service': ref})
        ref['enabled'] = True
        self.assertValidServiceResponse(r, ref)
        self.assertIs(True, r.result['service']['enabled'])

    def test_create_service_enabled_false(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref(enabled=False)
        r = self.post(
            '/services',
            body={'service': ref})
        self.assertValidServiceResponse(r, ref)
        self.assertIs(False, r.result['service']['enabled'])

    def test_create_service_enabled_true(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref(enabled=True)
        r = self.post(
            '/services',
            body={'service': ref})
        self.assertValidServiceResponse(r, ref)
        self.assertIs(True, r.result['service']['enabled'])

    def test_create_service_enabled_str_true(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref(enabled='True')
        self.post('/services', body={'service': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_service_enabled_str_false(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref(enabled='False')
        self.post('/services', body={'service': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_service_enabled_str_random(self):
        """Call ``POST /services``."""
        ref = unit.new_service_ref(enabled='puppies')
        self.post('/services', body={'service': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_list_head_services(self):
        """Call ``GET & HEAD /services``."""
        resource_url = '/services'
        r = self.get(resource_url)
        self.assertValidServiceListResponse(r, ref=self.service)
        self.head(resource_url, expected_status=http.client.OK)

    def _create_random_service(self):
        ref = unit.new_service_ref()
        response = self.post(
            '/services',
            body={'service': ref})
        return response.json['service']

    def test_filter_list_services_by_type(self):
        """Call ``GET /services?type=<some type>``."""
        target_ref = self._create_random_service()

        # create unrelated services
        self._create_random_service()
        self._create_random_service()

        response = self.get('/services?type=' + target_ref['type'])
        self.assertValidServiceListResponse(response, ref=target_ref)

        filtered_service_list = response.json['services']
        self.assertEqual(1, len(filtered_service_list))

        filtered_service = filtered_service_list[0]
        self.assertEqual(target_ref['type'], filtered_service['type'])

    def test_filter_list_services_by_name(self):
        """Call ``GET /services?name=<some name>``."""
        # create unrelated services
        self._create_random_service()
        self._create_random_service()

        # create the desired service
        target_ref = self._create_random_service()

        response = self.get('/services?name=' + target_ref['name'])
        self.assertValidServiceListResponse(response, ref=target_ref)

        filtered_service_list = response.json['services']
        self.assertEqual(1, len(filtered_service_list))

        filtered_service = filtered_service_list[0]
        self.assertEqual(target_ref['name'], filtered_service['name'])

    def test_filter_list_services_by_name_with_list_limit(self):
        """Call ``GET /services?name=<some name>``."""
        self.config_fixture.config(list_limit=1)

        self.test_filter_list_services_by_name()

    def test_get_head_service(self):
        """Call ``GET & HEAD /services/{service_id}``."""
        resource_url = '/services/%(service_id)s' % {
            'service_id': self.service_id}
        r = self.get(resource_url)
        self.assertValidServiceResponse(r, self.service)
        self.head(resource_url, expected_status=http.client.OK)

    def test_update_service(self):
        """Call ``PATCH /services/{service_id}``."""
        service = unit.new_service_ref()
        del service['id']
        r = self.patch('/services/%(service_id)s' % {
            'service_id': self.service_id},
            body={'service': service})
        self.assertValidServiceResponse(r, service)

    def test_delete_service(self):
        """Call ``DELETE /services/{service_id}``."""
        self.delete('/services/%(service_id)s' % {
            'service_id': self.service_id})

    # endpoint crud tests

    def test_list_head_endpoints(self):
        """Call ``GET & HEAD /endpoints``."""
        resource_url = '/endpoints'
        r = self.get(resource_url)
        self.assertValidEndpointListResponse(r, ref=self.endpoint)
        self.head(resource_url, expected_status=http.client.OK)

    def _create_random_endpoint(self, interface='public',
                                parent_region_id=None):
        region = self._create_region_with_parent_id(
            parent_id=parent_region_id)
        service = self._create_random_service()
        ref = unit.new_endpoint_ref(
            service_id=service['id'],
            interface=interface,
            region_id=region.result['region']['id'])

        response = self.post(
            '/endpoints',
            body={'endpoint': ref})
        return response.json['endpoint']

    def test_list_endpoints_filtered_by_interface(self):
        """Call ``GET /endpoints?interface={interface}``."""
        ref = self._create_random_endpoint(interface='internal')

        response = self.get('/endpoints?interface=%s' % ref['interface'])
        self.assertValidEndpointListResponse(response, ref=ref)

        for endpoint in response.json['endpoints']:
            self.assertEqual(ref['interface'], endpoint['interface'])

    def test_list_endpoints_filtered_by_service_id(self):
        """Call ``GET /endpoints?service_id={service_id}``."""
        ref = self._create_random_endpoint()

        response = self.get('/endpoints?service_id=%s' % ref['service_id'])
        self.assertValidEndpointListResponse(response, ref=ref)

        for endpoint in response.json['endpoints']:
            self.assertEqual(ref['service_id'], endpoint['service_id'])

    def test_list_endpoints_filtered_by_region_id(self):
        """Call ``GET /endpoints?region_id={region_id}``."""
        ref = self._create_random_endpoint()

        response = self.get('/endpoints?region_id=%s' % ref['region_id'])
        self.assertValidEndpointListResponse(response, ref=ref)

        for endpoint in response.json['endpoints']:
            self.assertEqual(ref['region_id'], endpoint['region_id'])

    def test_list_endpoints_filtered_by_parent_region_id(self):
        """Call ``GET /endpoints?region_id={region_id}``.

        Ensure passing the parent_region_id as filter returns an
        empty list.

        """
        parent_region = self._create_region_with_parent_id()
        parent_region_id = parent_region.result['region']['id']
        self._create_random_endpoint(parent_region_id=parent_region_id)

        response = self.get('/endpoints?region_id=%s' % parent_region_id)
        self.assertEqual(0, len(response.json['endpoints']))

    def test_list_endpoints_with_multiple_filters(self):
        """Call ``GET /endpoints?interface={interface}...``.

        Ensure passing different combinations of interface, region_id and
        service_id as filters will return the correct result.

        """
        # interface and region_id specified
        ref = self._create_random_endpoint(interface='internal')
        response = self.get('/endpoints?interface=%s&region_id=%s' %
                            (ref['interface'], ref['region_id']))
        self.assertValidEndpointListResponse(response, ref=ref)

        for endpoint in response.json['endpoints']:
            self.assertEqual(ref['interface'], endpoint['interface'])
            self.assertEqual(ref['region_id'], endpoint['region_id'])

        # interface and service_id specified
        ref = self._create_random_endpoint(interface='internal')
        response = self.get('/endpoints?interface=%s&service_id=%s' %
                            (ref['interface'], ref['service_id']))
        self.assertValidEndpointListResponse(response, ref=ref)

        for endpoint in response.json['endpoints']:
            self.assertEqual(ref['interface'], endpoint['interface'])
            self.assertEqual(ref['service_id'], endpoint['service_id'])

        # region_id and service_id specified
        ref = self._create_random_endpoint(interface='internal')
        response = self.get('/endpoints?region_id=%s&service_id=%s' %
                            (ref['region_id'], ref['service_id']))
        self.assertValidEndpointListResponse(response, ref=ref)

        for endpoint in response.json['endpoints']:
            self.assertEqual(ref['region_id'], endpoint['region_id'])
            self.assertEqual(ref['service_id'], endpoint['service_id'])

        # interface, region_id and service_id specified
        ref = self._create_random_endpoint(interface='internal')
        response = self.get(('/endpoints?interface=%s&region_id=%s'
                             '&service_id=%s') %
                            (ref['interface'], ref['region_id'],
                             ref['service_id']))
        self.assertValidEndpointListResponse(response, ref=ref)

        for endpoint in response.json['endpoints']:
            self.assertEqual(ref['interface'], endpoint['interface'])
            self.assertEqual(ref['region_id'], endpoint['region_id'])
            self.assertEqual(ref['service_id'], endpoint['service_id'])

    def test_list_endpoints_with_random_filter_values(self):
        """Call ``GET /endpoints?interface={interface}...``.

        Ensure passing random values for: interface, region_id and
        service_id will return an empty list.

        """
        self._create_random_endpoint(interface='internal')

        response = self.get('/endpoints?interface=%s' % uuid.uuid4().hex)
        self.assertEqual(0, len(response.json['endpoints']))

        response = self.get('/endpoints?region_id=%s' % uuid.uuid4().hex)
        self.assertEqual(0, len(response.json['endpoints']))

        response = self.get('/endpoints?service_id=%s' % uuid.uuid4().hex)
        self.assertEqual(0, len(response.json['endpoints']))

    def test_create_endpoint_no_enabled(self):
        """Call ``POST /endpoints``."""
        ref = unit.new_endpoint_ref(service_id=self.service_id,
                                    interface='public',
                                    region_id=self.region_id)
        r = self.post('/endpoints', body={'endpoint': ref})
        ref['enabled'] = True
        self.assertValidEndpointResponse(r, ref)

    def test_create_endpoint_enabled_true(self):
        """Call ``POST /endpoints`` with enabled: true."""
        ref = unit.new_endpoint_ref(service_id=self.service_id,
                                    interface='public',
                                    region_id=self.region_id,
                                    enabled=True)
        r = self.post('/endpoints', body={'endpoint': ref})
        self.assertValidEndpointResponse(r, ref)

    def test_create_endpoint_enabled_false(self):
        """Call ``POST /endpoints`` with enabled: false."""
        ref = unit.new_endpoint_ref(service_id=self.service_id,
                                    interface='public',
                                    region_id=self.region_id,
                                    enabled=False)
        r = self.post('/endpoints', body={'endpoint': ref})
        self.assertValidEndpointResponse(r, ref)

    def test_create_endpoint_enabled_str_true(self):
        """Call ``POST /endpoints`` with enabled: 'True'."""
        ref = unit.new_endpoint_ref(service_id=self.service_id,
                                    interface='public',
                                    region_id=self.region_id,
                                    enabled='True')
        self.post('/endpoints', body={'endpoint': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_endpoint_enabled_str_false(self):
        """Call ``POST /endpoints`` with enabled: 'False'."""
        ref = unit.new_endpoint_ref(service_id=self.service_id,
                                    interface='public',
                                    region_id=self.region_id,
                                    enabled='False')
        self.post('/endpoints', body={'endpoint': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_endpoint_enabled_str_random(self):
        """Call ``POST /endpoints`` with enabled: 'puppies'."""
        ref = unit.new_endpoint_ref(service_id=self.service_id,
                                    interface='public',
                                    region_id=self.region_id,
                                    enabled='puppies')
        self.post('/endpoints', body={'endpoint': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_endpoint_with_invalid_region_id(self):
        """Call ``POST /endpoints``."""
        ref = unit.new_endpoint_ref(service_id=self.service_id)
        self.post('/endpoints', body={'endpoint': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_endpoint_with_region(self):
        """EndpointV3 creates the region before creating the endpoint.

        This occurs when endpoint is provided with 'region' and no 'region_id'.
        """
        ref = unit.new_endpoint_ref_with_region(service_id=self.service_id,
                                                region=uuid.uuid4().hex)
        self.post('/endpoints', body={'endpoint': ref})
        # Make sure the region is created
        self.get('/regions/%(region_id)s' % {'region_id': ref["region"]})

    def test_create_endpoint_with_no_region(self):
        """EndpointV3 allows to creates the endpoint without region."""
        ref = unit.new_endpoint_ref(service_id=self.service_id, region_id=None)
        del ref['region_id']  # cannot just be None, it needs to not exist
        self.post('/endpoints', body={'endpoint': ref})

    def test_create_endpoint_with_empty_url(self):
        """Call ``POST /endpoints``."""
        ref = unit.new_endpoint_ref(service_id=self.service_id, url='')
        self.post('/endpoints', body={'endpoint': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_get_head_endpoint(self):
        """Call ``GET & HEAD /endpoints/{endpoint_id}``."""
        resource_url = '/endpoints/%(endpoint_id)s' % {
            'endpoint_id': self.endpoint_id}
        r = self.get(resource_url)
        self.assertValidEndpointResponse(r, self.endpoint)
        self.head(resource_url, expected_status=http.client.OK)

    def test_update_endpoint(self):
        """Call ``PATCH /endpoints/{endpoint_id}``."""
        ref = unit.new_endpoint_ref(service_id=self.service_id,
                                    interface='public',
                                    region_id=self.region_id)
        del ref['id']
        r = self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': ref})
        ref['enabled'] = True
        self.assertValidEndpointResponse(r, ref)

    def test_update_endpoint_enabled_true(self):
        """Call ``PATCH /endpoints/{endpoint_id}`` with enabled: True."""
        r = self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': {'enabled': True}})
        self.assertValidEndpointResponse(r, self.endpoint)

    def test_update_endpoint_enabled_false(self):
        """Call ``PATCH /endpoints/{endpoint_id}`` with enabled: False."""
        r = self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': {'enabled': False}})
        exp_endpoint = copy.copy(self.endpoint)
        exp_endpoint['enabled'] = False
        self.assertValidEndpointResponse(r, exp_endpoint)

    def test_update_endpoint_enabled_str_true(self):
        """Call ``PATCH /endpoints/{endpoint_id}`` with enabled: 'True'."""
        self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': {'enabled': 'True'}},
            expected_status=http.client.BAD_REQUEST)

    def test_update_endpoint_enabled_str_false(self):
        """Call ``PATCH /endpoints/{endpoint_id}`` with enabled: 'False'."""
        self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': {'enabled': 'False'}},
            expected_status=http.client.BAD_REQUEST)

    def test_update_endpoint_enabled_str_random(self):
        """Call ``PATCH /endpoints/{endpoint_id}`` with enabled: 'kitties'."""
        self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': {'enabled': 'kitties'}},
            expected_status=http.client.BAD_REQUEST)

    def test_delete_endpoint(self):
        """Call ``DELETE /endpoints/{endpoint_id}``."""
        self.delete(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id})

    def test_deleting_endpoint_with_space_in_url(self):
        # add a space to all urls (intentional "i d" to test bug)
        url_with_space = "http://127.0.0.1:8774 /v1.1/\\$(tenant_i d)s"

        # create a v3 endpoint ref
        ref = unit.new_endpoint_ref(service_id=self.service['id'],
                                    region_id=None,
                                    publicurl=url_with_space,
                                    internalurl=url_with_space,
                                    adminurl=url_with_space,
                                    url=url_with_space)

        # add the endpoint to the database
        PROVIDERS.catalog_api.create_endpoint(ref['id'], ref)

        # delete the endpoint
        self.delete('/endpoints/%s' % ref['id'])

        # make sure it's deleted (GET should return Not Found)
        self.get('/endpoints/%s' % ref['id'],
                 expected_status=http.client.NOT_FOUND)

    def test_endpoint_create_with_valid_url(self):
        """Create endpoint with valid url should be tested,too."""
        # list one valid url is enough, no need to list too much
        valid_url = 'http://127.0.0.1:8774/v1.1/$(project_id)s'

        ref = unit.new_endpoint_ref(self.service_id,
                                    interface='public',
                                    region_id=self.region_id,
                                    url=valid_url)
        self.post('/endpoints', body={'endpoint': ref})

    def test_endpoint_create_with_valid_url_project_id(self):
        """Create endpoint with valid url should be tested,too."""
        valid_url = 'http://127.0.0.1:8774/v1.1/$(project_id)s'

        ref = unit.new_endpoint_ref(self.service_id,
                                    interface='public',
                                    region_id=self.region_id,
                                    url=valid_url)
        self.post('/endpoints', body={'endpoint': ref})

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

        ref = unit.new_endpoint_ref(self.service_id)

        for invalid_url in invalid_urls:
            ref['url'] = invalid_url
            self.post('/endpoints',
                      body={'endpoint': ref},
                      expected_status=http.client.BAD_REQUEST)


class TestMultiRegion(test_v3.RestfulTestCase):

    def test_catalog_with_multi_region_reports_all_endpoints(self):

        # Create two separate regions
        first_region = self.post(
            '/regions',
            body={'region': unit.new_region_ref()}
        ).json_body['region']

        second_region = self.post(
            '/regions',
            body={'region': unit.new_region_ref()}
        ).json_body['region']

        # Create two services with the same type but separate name.
        first_service = self.post(
            '/services',
            body={'service': unit.new_service_ref(type='foobar')}
        ).json_body['service']

        second_service = self.post(
            '/services',
            body={'service': unit.new_service_ref(type='foobar')}
        ).json_body['service']

        # Create an endpoint for each service
        first_endpoint = self.post(
            '/endpoints',
            body={
                'endpoint': unit.new_endpoint_ref(
                    first_service['id'],
                    interface='public',
                    region_id=first_region['id']
                )
            }
        ).json_body['endpoint']

        second_endpoint = self.post(
            '/endpoints',
            body={
                'endpoint': unit.new_endpoint_ref(
                    second_service['id'],
                    interface='public',
                    region_id=second_region['id']
                )
            }
        ).json_body['endpoint']

        # Assert the endpoints and services from each region are in the
        # catalog.
        found_first_endpoint = False
        found_second_endpoint = False
        catalog = self.get('/auth/catalog/').json_body['catalog']
        for service in catalog:
            if service['id'] == first_service['id']:
                endpoint = service['endpoints'][0]
                self.assertEqual(endpoint['id'], first_endpoint['id'])
                self.assertEqual(endpoint['region_id'], first_region['id'])
                found_first_endpoint = True
            elif service['id'] == second_service['id']:
                endpoint = service['endpoints'][0]
                self.assertEqual(endpoint['id'], second_endpoint['id'])
                self.assertEqual(endpoint['region_id'], second_region['id'])
                found_second_endpoint = True

        self.assertTrue(found_first_endpoint)
        self.assertTrue(found_second_endpoint)


class TestCatalogAPISQL(unit.TestCase):
    """Test for the catalog Manager against the SQL backend."""

    def setUp(self):
        super(TestCatalogAPISQL, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

        service = unit.new_service_ref()
        self.service_id = service['id']
        PROVIDERS.catalog_api.create_service(self.service_id, service)

        self.create_endpoint(service_id=self.service_id)

        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)

    def create_endpoint(self, service_id, **kwargs):
        endpoint = unit.new_endpoint_ref(service_id=service_id,
                                         region_id=None, **kwargs)

        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)
        return endpoint

    def config_overrides(self):
        super(TestCatalogAPISQL, self).config_overrides()
        self.config_fixture.config(group='catalog', driver='sql')

    def test_get_catalog_ignores_endpoints_with_invalid_urls(self):
        user_id = uuid.uuid4().hex

        # create a project since the project should exist if we want to
        # filter the catalog by the project or replace the url with a
        # valid project id.
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)

        # the only endpoint in the catalog is the one created in setUp
        catalog = PROVIDERS.catalog_api.get_v3_catalog(user_id, project['id'])
        self.assertEqual(1, len(catalog[0]['endpoints']))
        # it's also the only endpoint in the backend
        self.assertEqual(1, len(PROVIDERS.catalog_api.list_endpoints()))

        # create a new, invalid endpoint - malformed type declaration
        self.create_endpoint(self.service_id,
                             url='http://keystone/%(project_id)')

        # create a new, invalid endpoint - nonexistent key
        self.create_endpoint(self.service_id,
                             url='http://keystone/%(you_wont_find_me)s')

        # verify that the invalid endpoints don't appear in the catalog
        catalog = PROVIDERS.catalog_api.get_v3_catalog(user_id, project['id'])
        self.assertEqual(1, len(catalog[0]['endpoints']))
        # all three appear in the backend
        self.assertEqual(3, len(PROVIDERS.catalog_api.list_endpoints()))

        # create another valid endpoint - project_id will be replaced
        self.create_endpoint(self.service_id,
                             url='http://keystone/%(project_id)s')

        # there are two valid endpoints, positive check
        catalog = PROVIDERS.catalog_api.get_v3_catalog(user_id, project['id'])
        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(2))

        # If the URL has no 'project_id' to substitute, we will skip the
        # endpoint which contains this kind of URL, negative check.
        project_id = None
        catalog = PROVIDERS.catalog_api.get_v3_catalog(user_id, project_id)
        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(1))

    def test_get_catalog_always_returns_service_name(self):
        user_id = uuid.uuid4().hex
        # create a project since the project should exist if we want to
        # filter the catalog by the project or replace the url with a
        # valid project id.
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)

        # create a service, with a name
        named_svc = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(named_svc['id'], named_svc)
        self.create_endpoint(service_id=named_svc['id'])

        # create a service, with no name
        unnamed_svc = unit.new_service_ref(name=None)
        del unnamed_svc['name']
        PROVIDERS.catalog_api.create_service(unnamed_svc['id'], unnamed_svc)
        self.create_endpoint(service_id=unnamed_svc['id'])

        catalog = PROVIDERS.catalog_api.get_v3_catalog(user_id, project['id'])

        named_endpoint = [ep for ep in catalog
                          if ep['type'] == named_svc['type']][0]
        self.assertEqual(named_svc['name'], named_endpoint['name'])

        unnamed_endpoint = [ep for ep in catalog
                            if ep['type'] == unnamed_svc['type']][0]
        self.assertEqual('', unnamed_endpoint['name'])


# TODO(dstanek): this needs refactoring with the test above, but we are in a
# crunch so that will happen in a future patch.
class TestCatalogAPISQLRegions(unit.TestCase):
    """Test for the catalog Manager against the SQL backend."""

    def setUp(self):
        super(TestCatalogAPISQLRegions, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)

    def config_overrides(self):
        super(TestCatalogAPISQLRegions, self).config_overrides()
        self.config_fixture.config(group='catalog', driver='sql')

    def test_get_catalog_returns_proper_endpoints_with_no_region(self):
        service = unit.new_service_ref()
        service_id = service['id']
        PROVIDERS.catalog_api.create_service(service_id, service)

        endpoint = unit.new_endpoint_ref(service_id=service_id,
                                         region_id=None)
        del endpoint['region_id']
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # create a project since the project should exist if we want to
        # filter the catalog by the project or replace the url with a
        # valid project id.
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)
        user_id = uuid.uuid4().hex
        catalog = PROVIDERS.catalog_api.get_v3_catalog(user_id, project['id'])
        self.assertValidCatalogEndpoint(
            catalog[0]['endpoints'][0], ref=endpoint)

    def test_get_catalog_returns_proper_endpoints_with_region(self):
        service = unit.new_service_ref()
        service_id = service['id']
        PROVIDERS.catalog_api.create_service(service_id, service)

        endpoint = unit.new_endpoint_ref(service_id=service_id)
        region = unit.new_region_ref(id=endpoint['region_id'])
        PROVIDERS.catalog_api.create_region(region)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)

        endpoint = PROVIDERS.catalog_api.get_endpoint(endpoint['id'])
        user_id = uuid.uuid4().hex
        # create a project since the project should exist if we want to
        # filter the catalog by the project or replace the url with a
        # valid project id.
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)

        catalog = PROVIDERS.catalog_api.get_v3_catalog(user_id, project['id'])
        self.assertValidCatalogEndpoint(
            catalog[0]['endpoints'][0], ref=endpoint)

    def assertValidCatalogEndpoint(self, entity, ref=None):
        keys = ['description', 'id', 'interface', 'name', 'region_id', 'url']
        for k in keys:
            self.assertEqual(ref.get(k), entity[k], k)
        self.assertEqual(entity['region_id'], entity['region'])


class TestCatalogAPITemplatedProject(test_v3.RestfulTestCase):
    """Templated Catalog doesn't support full API.

    Eg. No region/endpoint creation.

    """

    def config_overrides(self):
        super(TestCatalogAPITemplatedProject, self).config_overrides()
        self.config_fixture.config(group='catalog', driver='templated')

    def load_fixtures(self, fixtures):
        self.load_sample_data(create_region_and_endpoints=False)

    def test_project_delete(self):
        """Deleting a project should not result in an 500 ISE.

        Deleting a project will create a notification, which the EndpointFilter
        functionality will use to clean up any project->endpoint and
        project->endpoint_group relationships. The templated catalog does not
        support such relationships, but the act of attempting to delete them
        should not cause a NotImplemented exception to be exposed to an API
        caller.

        Deleting an endpoint has a similar notification and clean up
        mechanism, but since we do not allow deletion of endpoints with the
        templated catalog, there is no testing to do for that action.
        """
        self.delete(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id})
