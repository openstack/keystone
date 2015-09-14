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

from six.moves import http_client
from testtools import matchers

from keystone import catalog
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import test_v3


class CatalogTestCase(test_v3.RestfulTestCase):
    """Test service & endpoint CRUD."""

    # region crud tests

    def test_create_region_with_id(self):
        """Call ``PUT /regions/{region_id}`` w/o an ID in the request body."""
        ref = self.new_region_ref()
        region_id = ref.pop('id')
        r = self.put(
            '/regions/%s' % region_id,
            body={'region': ref},
            expected_status=201)
        self.assertValidRegionResponse(r, ref)
        # Double-check that the region ID was kept as-is and not
        # populated with a UUID, as is the case with POST /v3/regions
        self.assertEqual(region_id, r.json['region']['id'])

    def test_create_region_with_matching_ids(self):
        """Call ``PUT /regions/{region_id}`` with an ID in the request body."""
        ref = self.new_region_ref()
        region_id = ref['id']
        r = self.put(
            '/regions/%s' % region_id,
            body={'region': ref},
            expected_status=201)
        self.assertValidRegionResponse(r, ref)
        # Double-check that the region ID was kept as-is and not
        # populated with a UUID, as is the case with POST /v3/regions
        self.assertEqual(region_id, r.json['region']['id'])

    def test_create_region_with_duplicate_id(self):
        """Call ``PUT /regions/{region_id}``."""
        ref = dict(description="my region")
        self.put(
            '/regions/myregion',
            body={'region': ref}, expected_status=201)
        # Create region again with duplicate id
        self.put(
            '/regions/myregion',
            body={'region': ref}, expected_status=409)

    def test_create_region(self):
        """Call ``POST /regions`` with an ID in the request body."""
        # the ref will have an ID defined on it
        ref = self.new_region_ref()
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
        ref = self.new_region_ref()
        ref['id'] = ''

        r = self.post(
            '/regions',
            body={'region': ref}, expected_status=201)
        self.assertValidRegionResponse(r, ref)
        self.assertNotEmpty(r.result['region'].get('id'))

    def test_create_region_without_id(self):
        """Call ``POST /regions`` without an ID in the request body."""
        ref = self.new_region_ref()

        # instead of defining the ID ourselves...
        del ref['id']

        # let the service define the ID
        r = self.post(
            '/regions',
            body={'region': ref},
            expected_status=201)
        self.assertValidRegionResponse(r, ref)

    def test_create_region_without_description(self):
        """Call ``POST /regions`` without description in the request body."""
        ref = self.new_region_ref()

        del ref['description']

        r = self.post(
            '/regions',
            body={'region': ref},
            expected_status=201)
        # Create the description in the reference to compare to since the
        # response should now have a description, even though we didn't send
        # it with the original reference.
        ref['description'] = ''
        self.assertValidRegionResponse(r, ref)

    def test_create_regions_with_same_description_string(self):
        """Call ``POST /regions`` with same description in the request bodies.
        """
        # NOTE(lbragstad): Make sure we can create two regions that have the
        # same description.
        ref1 = self.new_region_ref()
        ref2 = self.new_region_ref()

        region_desc = 'Some Region Description'

        ref1['description'] = region_desc
        ref2['description'] = region_desc

        resp1 = self.post(
            '/regions',
            body={'region': ref1},
            expected_status=201)
        self.assertValidRegionResponse(resp1, ref1)

        resp2 = self.post(
            '/regions',
            body={'region': ref2},
            expected_status=201)
        self.assertValidRegionResponse(resp2, ref2)

    def test_create_regions_without_descriptions(self):
        """Call ``POST /regions`` with no description in the request bodies.
        """
        # NOTE(lbragstad): Make sure we can create two regions that have
        # no description in the request body. The description should be
        # populated by Catalog Manager.
        ref1 = self.new_region_ref()
        ref2 = self.new_region_ref()

        del ref1['description']
        ref2['description'] = None

        resp1 = self.post(
            '/regions',
            body={'region': ref1},
            expected_status=201)

        resp2 = self.post(
            '/regions',
            body={'region': ref2},
            expected_status=201)
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
        ref = self.new_region_ref()

        # but instead of using that ID, make up a new, conflicting one
        self.put(
            '/regions/%s' % uuid.uuid4().hex,
            body={'region': ref},
            expected_status=http_client.BAD_REQUEST)

    def test_list_regions(self):
        """Call ``GET /regions``."""
        r = self.get('/regions')
        self.assertValidRegionListResponse(r, ref=self.region)

    def _create_region_with_parent_id(self, parent_id=None):
        ref = self.new_region_ref()
        ref['parent_region_id'] = parent_id
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

    def test_get_region(self):
        """Call ``GET /regions/{region_id}``."""
        r = self.get('/regions/%(region_id)s' % {
            'region_id': self.region_id})
        self.assertValidRegionResponse(r, self.region)

    def test_update_region(self):
        """Call ``PATCH /regions/{region_id}``."""
        region = self.new_region_ref()
        del region['id']
        r = self.patch('/regions/%(region_id)s' % {
            'region_id': self.region_id},
            body={'region': region})
        self.assertValidRegionResponse(r, region)

    def test_update_region_without_description_keeps_original(self):
        """Call ``PATCH /regions/{region_id}``."""
        region_ref = self.new_region_ref()

        resp = self.post('/regions', body={'region': region_ref},
                         expected_status=201)

        region_updates = {
            # update with something that's not the description
            'parent_region_id': self.region_id,
        }
        resp = self.patch('/regions/%s' % region_ref['id'],
                          body={'region': region_updates},
                          expected_status=200)

        # NOTE(dstanek): Keystone should keep the original description.
        self.assertEqual(region_ref['description'],
                         resp.result['region']['description'])

    def test_update_region_with_null_description(self):
        """Call ``PATCH /regions/{region_id}``."""
        region = self.new_region_ref()
        del region['id']
        region['description'] = None
        r = self.patch('/regions/%(region_id)s' % {
            'region_id': self.region_id},
            body={'region': region})

        # NOTE(dstanek): Keystone should turn the provided None value into
        # an empty string before storing in the backend.
        region['description'] = ''
        self.assertValidRegionResponse(r, region)

    def test_delete_region(self):
        """Call ``DELETE /regions/{region_id}``."""

        ref = self.new_region_ref()
        r = self.post(
            '/regions',
            body={'region': ref})
        self.assertValidRegionResponse(r, ref)

        self.delete('/regions/%(region_id)s' % {
            'region_id': ref['id']})

    # service crud tests

    def test_create_service(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        r = self.post(
            '/services',
            body={'service': ref})
        self.assertValidServiceResponse(r, ref)

    def test_create_service_no_name(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        del ref['name']
        r = self.post(
            '/services',
            body={'service': ref})
        ref['name'] = ''
        self.assertValidServiceResponse(r, ref)

    def test_create_service_no_enabled(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        del ref['enabled']
        r = self.post(
            '/services',
            body={'service': ref})
        ref['enabled'] = True
        self.assertValidServiceResponse(r, ref)
        self.assertIs(True, r.result['service']['enabled'])

    def test_create_service_enabled_false(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        ref['enabled'] = False
        r = self.post(
            '/services',
            body={'service': ref})
        self.assertValidServiceResponse(r, ref)
        self.assertIs(False, r.result['service']['enabled'])

    def test_create_service_enabled_true(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        ref['enabled'] = True
        r = self.post(
            '/services',
            body={'service': ref})
        self.assertValidServiceResponse(r, ref)
        self.assertIs(True, r.result['service']['enabled'])

    def test_create_service_enabled_str_true(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        ref['enabled'] = 'True'
        self.post('/services', body={'service': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_create_service_enabled_str_false(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        ref['enabled'] = 'False'
        self.post('/services', body={'service': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_create_service_enabled_str_random(self):
        """Call ``POST /services``."""
        ref = self.new_service_ref()
        ref['enabled'] = 'puppies'
        self.post('/services', body={'service': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_list_services(self):
        """Call ``GET /services``."""
        r = self.get('/services')
        self.assertValidServiceListResponse(r, ref=self.service)

    def _create_random_service(self):
        ref = self.new_service_ref()
        ref['enabled'] = True
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
        target_ref = self._create_random_service()

        # create unrelated services
        self._create_random_service()
        self._create_random_service()

        response = self.get('/services?name=' + target_ref['name'])
        self.assertValidServiceListResponse(response, ref=target_ref)

        filtered_service_list = response.json['services']
        self.assertEqual(1, len(filtered_service_list))

        filtered_service = filtered_service_list[0]
        self.assertEqual(target_ref['name'], filtered_service['name'])

    def test_get_service(self):
        """Call ``GET /services/{service_id}``."""
        r = self.get('/services/%(service_id)s' % {
            'service_id': self.service_id})
        self.assertValidServiceResponse(r, self.service)

    def test_update_service(self):
        """Call ``PATCH /services/{service_id}``."""
        service = self.new_service_ref()
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

    def test_list_endpoints(self):
        """Call ``GET /endpoints``."""
        r = self.get('/endpoints')
        self.assertValidEndpointListResponse(r, ref=self.endpoint)

    def _create_random_endpoint(self, interface='public',
                                parent_region_id=None):
        region = self._create_region_with_parent_id(
            parent_id=parent_region_id)
        service = self._create_random_service()
        ref = self.new_endpoint_ref(
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
        ref = self.new_endpoint_ref(service_id=self.service_id)
        r = self.post(
            '/endpoints',
            body={'endpoint': ref})
        ref['enabled'] = True
        self.assertValidEndpointResponse(r, ref)

    def test_create_endpoint_enabled_true(self):
        """Call ``POST /endpoints`` with enabled: true."""
        ref = self.new_endpoint_ref(service_id=self.service_id,
                                    enabled=True)
        r = self.post(
            '/endpoints',
            body={'endpoint': ref})
        self.assertValidEndpointResponse(r, ref)

    def test_create_endpoint_enabled_false(self):
        """Call ``POST /endpoints`` with enabled: false."""
        ref = self.new_endpoint_ref(service_id=self.service_id,
                                    enabled=False)
        r = self.post(
            '/endpoints',
            body={'endpoint': ref})
        self.assertValidEndpointResponse(r, ref)

    def test_create_endpoint_enabled_str_true(self):
        """Call ``POST /endpoints`` with enabled: 'True'."""
        ref = self.new_endpoint_ref(service_id=self.service_id,
                                    enabled='True')
        self.post(
            '/endpoints',
            body={'endpoint': ref},
            expected_status=http_client.BAD_REQUEST)

    def test_create_endpoint_enabled_str_false(self):
        """Call ``POST /endpoints`` with enabled: 'False'."""
        ref = self.new_endpoint_ref(service_id=self.service_id,
                                    enabled='False')
        self.post(
            '/endpoints',
            body={'endpoint': ref},
            expected_status=http_client.BAD_REQUEST)

    def test_create_endpoint_enabled_str_random(self):
        """Call ``POST /endpoints`` with enabled: 'puppies'."""
        ref = self.new_endpoint_ref(service_id=self.service_id,
                                    enabled='puppies')
        self.post(
            '/endpoints',
            body={'endpoint': ref},
            expected_status=http_client.BAD_REQUEST)

    def test_create_endpoint_with_invalid_region_id(self):
        """Call ``POST /endpoints``."""
        ref = self.new_endpoint_ref(service_id=self.service_id)
        ref["region_id"] = uuid.uuid4().hex
        self.post('/endpoints', body={'endpoint': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_create_endpoint_with_region(self):
        """EndpointV3 creates the region before creating the endpoint, if
        endpoint is provided with 'region' and no 'region_id'
        """
        ref = self.new_endpoint_ref(service_id=self.service_id)
        ref["region"] = uuid.uuid4().hex
        ref.pop('region_id')
        self.post('/endpoints', body={'endpoint': ref}, expected_status=201)
        # Make sure the region is created
        self.get('/regions/%(region_id)s' % {
            'region_id': ref["region"]})

    def test_create_endpoint_with_no_region(self):
        """EndpointV3 allows to creates the endpoint without region."""
        ref = self.new_endpoint_ref(service_id=self.service_id)
        ref.pop('region_id')
        self.post('/endpoints', body={'endpoint': ref}, expected_status=201)

    def test_create_endpoint_with_empty_url(self):
        """Call ``POST /endpoints``."""
        ref = self.new_endpoint_ref(service_id=self.service_id)
        ref["url"] = ''
        self.post('/endpoints', body={'endpoint': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_get_endpoint(self):
        """Call ``GET /endpoints/{endpoint_id}``."""
        r = self.get(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id})
        self.assertValidEndpointResponse(r, self.endpoint)

    def test_update_endpoint(self):
        """Call ``PATCH /endpoints/{endpoint_id}``."""
        ref = self.new_endpoint_ref(service_id=self.service_id)
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
            expected_status=http_client.BAD_REQUEST)

    def test_update_endpoint_enabled_str_false(self):
        """Call ``PATCH /endpoints/{endpoint_id}`` with enabled: 'False'."""
        self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': {'enabled': 'False'}},
            expected_status=http_client.BAD_REQUEST)

    def test_update_endpoint_enabled_str_random(self):
        """Call ``PATCH /endpoints/{endpoint_id}`` with enabled: 'kitties'."""
        self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': {'enabled': 'kitties'}},
            expected_status=http_client.BAD_REQUEST)

    def test_delete_endpoint(self):
        """Call ``DELETE /endpoints/{endpoint_id}``."""
        self.delete(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id})

    def test_create_endpoint_on_v2(self):
        # clear the v3 endpoint so we only have endpoints created on v2
        self.delete(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id})

        # create a v3 endpoint ref, and then tweak it back to a v2-style ref
        ref = self.new_endpoint_ref(service_id=self.service['id'])
        del ref['id']
        del ref['interface']
        ref['publicurl'] = ref.pop('url')
        ref['internalurl'] = None
        ref['region'] = ref['region_id']
        del ref['region_id']
        # don't set adminurl to ensure it's absence is handled like internalurl

        # create the endpoint on v2 (using a v3 token)
        r = self.admin_request(
            method='POST',
            path='/v2.0/endpoints',
            token=self.get_scoped_token(),
            body={'endpoint': ref})
        endpoint_v2 = r.result['endpoint']

        # test the endpoint on v3
        r = self.get('/endpoints')
        endpoints = self.assertValidEndpointListResponse(r)
        self.assertEqual(1, len(endpoints))
        endpoint_v3 = endpoints.pop()

        # these attributes are identical between both APIs
        self.assertEqual(ref['region'], endpoint_v3['region_id'])
        self.assertEqual(ref['service_id'], endpoint_v3['service_id'])
        self.assertEqual(ref['description'], endpoint_v3['description'])

        # a v2 endpoint is not quite the same concept as a v3 endpoint, so they
        # receive different identifiers
        self.assertNotEqual(endpoint_v2['id'], endpoint_v3['id'])

        # v2 has a publicurl; v3 has a url + interface type
        self.assertEqual(ref['publicurl'], endpoint_v3['url'])
        self.assertEqual('public', endpoint_v3['interface'])

        # tests for bug 1152632 -- these attributes were being returned by v3
        self.assertNotIn('publicurl', endpoint_v3)
        self.assertNotIn('adminurl', endpoint_v3)
        self.assertNotIn('internalurl', endpoint_v3)

        # test for bug 1152635 -- this attribute was being returned by v3
        self.assertNotIn('legacy_endpoint_id', endpoint_v3)

        self.assertEqual(endpoint_v2['region'], endpoint_v3['region_id'])

    def test_deleting_endpoint_with_space_in_url(self):
        # create a v3 endpoint ref
        ref = self.new_endpoint_ref(service_id=self.service['id'])

        # add a space to all urls (intentional "i d" to test bug)
        url_with_space = "http://127.0.0.1:8774 /v1.1/\$(tenant_i d)s"
        ref['publicurl'] = url_with_space
        ref['internalurl'] = url_with_space
        ref['adminurl'] = url_with_space
        ref['url'] = url_with_space

        # add the endpoint to the database
        self.catalog_api.create_endpoint(ref['id'], ref)

        # delete the endpoint
        self.delete('/endpoints/%s' % ref['id'])

        # make sure it's deleted (GET should return 404)
        self.get('/endpoints/%s' % ref['id'],
                 expected_status=http_client.NOT_FOUND)

    def test_endpoint_create_with_valid_url(self):
        """Create endpoint with valid url should be tested,too."""
        # list one valid url is enough, no need to list too much
        valid_url = 'http://127.0.0.1:8774/v1.1/$(tenant_id)s'

        ref = self.new_endpoint_ref(self.service_id)
        ref['url'] = valid_url
        self.post('/endpoints',
                  body={'endpoint': ref},
                  expected_status=201)

    def test_endpoint_create_with_invalid_url(self):
        """Test the invalid cases: substitutions is not exactly right.
        """
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

        ref = self.new_endpoint_ref(self.service_id)

        for invalid_url in invalid_urls:
            ref['url'] = invalid_url
            self.post('/endpoints',
                      body={'endpoint': ref},
                      expected_status=http_client.BAD_REQUEST)


class TestCatalogAPISQL(unit.TestCase):
    """Tests for the catalog Manager against the SQL backend.

    """

    def setUp(self):
        super(TestCatalogAPISQL, self).setUp()
        self.useFixture(database.Database())
        self.catalog_api = catalog.Manager()

        self.service_id = uuid.uuid4().hex
        service = {'id': self.service_id, 'name': uuid.uuid4().hex}
        self.catalog_api.create_service(self.service_id, service)

        endpoint = self.new_endpoint_ref(service_id=self.service_id)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

    def config_overrides(self):
        super(TestCatalogAPISQL, self).config_overrides()
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
        catalog = self.catalog_api.get_v3_catalog(user_id, tenant_id)
        self.assertEqual(1, len(catalog[0]['endpoints']))
        # it's also the only endpoint in the backend
        self.assertEqual(1, len(self.catalog_api.list_endpoints()))

        # create a new, invalid endpoint - malformed type declaration
        ref = self.new_endpoint_ref(self.service_id)
        ref['url'] = 'http://keystone/%(tenant_id)'
        self.catalog_api.create_endpoint(ref['id'], ref)

        # create a new, invalid endpoint - nonexistent key
        ref = self.new_endpoint_ref(self.service_id)
        ref['url'] = 'http://keystone/%(you_wont_find_me)s'
        self.catalog_api.create_endpoint(ref['id'], ref)

        # verify that the invalid endpoints don't appear in the catalog
        catalog = self.catalog_api.get_v3_catalog(user_id, tenant_id)
        self.assertEqual(1, len(catalog[0]['endpoints']))
        # all three appear in the backend
        self.assertEqual(3, len(self.catalog_api.list_endpoints()))

        # create another valid endpoint - tenant_id will be replaced
        ref = self.new_endpoint_ref(self.service_id)
        ref['url'] = 'http://keystone/%(tenant_id)s'
        self.catalog_api.create_endpoint(ref['id'], ref)

        # there are two valid endpoints, positive check
        catalog = self.catalog_api.get_v3_catalog(user_id, tenant_id)
        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(2))

        # If the URL has no 'tenant_id' to substitute, we will skip the
        # endpoint which contains this kind of URL, negative check.
        catalog = self.catalog_api.get_v3_catalog(user_id, tenant_id=None)
        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(1))

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

        catalog = self.catalog_api.get_v3_catalog(user_id, tenant_id)

        named_endpoint = [ep for ep in catalog
                          if ep['type'] == named_svc['type']][0]
        self.assertEqual(named_svc['name'], named_endpoint['name'])

        unnamed_endpoint = [ep for ep in catalog
                            if ep['type'] == unnamed_svc['type']][0]
        self.assertEqual('', unnamed_endpoint['name'])


# TODO(dstanek): this needs refactoring with the test above, but we are in a
# crunch so that will happen in a future patch.
class TestCatalogAPISQLRegions(unit.TestCase):
    """Tests for the catalog Manager against the SQL backend.

    """

    def setUp(self):
        super(TestCatalogAPISQLRegions, self).setUp()
        self.useFixture(database.Database())
        self.catalog_api = catalog.Manager()

    def config_overrides(self):
        super(TestCatalogAPISQLRegions, self).config_overrides()
        self.config_fixture.config(group='catalog', driver='sql')

    def new_endpoint_ref(self, service_id):
        return {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'interface': uuid.uuid4().hex[:8],
            'service_id': service_id,
            'url': uuid.uuid4().hex,
            'region_id': uuid.uuid4().hex,
        }

    def test_get_catalog_returns_proper_endpoints_with_no_region(self):
        service_id = uuid.uuid4().hex
        service = {'id': service_id, 'name': uuid.uuid4().hex}
        self.catalog_api.create_service(service_id, service)

        endpoint = self.new_endpoint_ref(service_id=service_id)
        del endpoint['region_id']
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        user_id = uuid.uuid4().hex
        tenant_id = uuid.uuid4().hex

        catalog = self.catalog_api.get_v3_catalog(user_id, tenant_id)
        self.assertValidCatalogEndpoint(
            catalog[0]['endpoints'][0], ref=endpoint)

    def test_get_catalog_returns_proper_endpoints_with_region(self):
        service_id = uuid.uuid4().hex
        service = {'id': service_id, 'name': uuid.uuid4().hex}
        self.catalog_api.create_service(service_id, service)

        endpoint = self.new_endpoint_ref(service_id=service_id)
        self.catalog_api.create_region({'id': endpoint['region_id']})
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        endpoint = self.catalog_api.get_endpoint(endpoint['id'])
        user_id = uuid.uuid4().hex
        tenant_id = uuid.uuid4().hex

        catalog = self.catalog_api.get_v3_catalog(user_id, tenant_id)
        self.assertValidCatalogEndpoint(
            catalog[0]['endpoints'][0], ref=endpoint)

    def assertValidCatalogEndpoint(self, entity, ref=None):
        keys = ['description', 'id', 'interface', 'name', 'region_id', 'url']
        for k in keys:
            self.assertEqual(ref.get(k), entity[k], k)
        self.assertEqual(entity['region_id'], entity['region'])
