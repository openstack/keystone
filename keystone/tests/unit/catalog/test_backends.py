# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy
from unittest import mock
import uuid

from testtools import matchers

from keystone.catalog.backends import base
from keystone.common import driver_hints
from keystone.common import provider_api
from keystone import exception
from keystone.tests import unit

PROVIDERS = provider_api.ProviderAPIs


class CatalogTests(object):

    _legacy_endpoint_id_in_endpoint = True
    _enabled_default_to_true_when_creating_endpoint = False

    def test_region_crud(self):
        # create
        region_id = 'default'
        new_region = unit.new_region_ref(id=region_id)
        res = PROVIDERS.catalog_api.create_region(new_region)

        # Ensure that we don't need to have a
        # parent_region_id in the original supplied
        # ref dict, but that it will be returned from
        # the endpoint, with None value.
        expected_region = new_region.copy()
        expected_region['parent_region_id'] = None
        self.assertDictEqual(expected_region, res)

        # Test adding another region with the one above
        # as its parent. We will check below whether deleting
        # the parent successfully deletes any child regions.
        parent_region_id = region_id
        new_region = unit.new_region_ref(parent_region_id=parent_region_id)
        region_id = new_region['id']
        res = PROVIDERS.catalog_api.create_region(new_region)
        self.assertDictEqual(new_region, res)

        # list
        regions = PROVIDERS.catalog_api.list_regions()
        self.assertThat(regions, matchers.HasLength(2))
        region_ids = [x['id'] for x in regions]
        self.assertIn(parent_region_id, region_ids)
        self.assertIn(region_id, region_ids)

        # update
        region_desc_update = {'description': uuid.uuid4().hex}
        res = PROVIDERS.catalog_api.update_region(
            region_id, region_desc_update
        )
        expected_region = new_region.copy()
        expected_region['description'] = region_desc_update['description']
        self.assertDictEqual(expected_region, res)

        # delete
        PROVIDERS.catalog_api.delete_region(parent_region_id)
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.delete_region,
                          parent_region_id)
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          parent_region_id)
        # Ensure the child is also gone...
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          region_id)

    def _create_region_with_parent_id(self, parent_id=None):
        new_region = unit.new_region_ref(parent_region_id=parent_id)
        PROVIDERS.catalog_api.create_region(new_region)
        return new_region

    def test_list_regions_filtered_by_parent_region_id(self):
        new_region = self._create_region_with_parent_id()
        parent_id = new_region['id']
        new_region = self._create_region_with_parent_id(parent_id)
        new_region = self._create_region_with_parent_id(parent_id)

        # filter by parent_region_id
        hints = driver_hints.Hints()
        hints.add_filter('parent_region_id', parent_id)
        regions = PROVIDERS.catalog_api.list_regions(hints)
        for region in regions:
            self.assertEqual(parent_id, region['parent_region_id'])

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_region_crud(self):
        new_region = unit.new_region_ref()
        region_id = new_region['id']
        PROVIDERS.catalog_api.create_region(new_region.copy())
        updated_region = copy.deepcopy(new_region)
        updated_region['description'] = uuid.uuid4().hex
        # cache the result
        PROVIDERS.catalog_api.get_region(region_id)
        # update the region bypassing catalog_api
        PROVIDERS.catalog_api.driver.update_region(region_id, updated_region)
        self.assertLessEqual(
            new_region.items(),
            PROVIDERS.catalog_api.get_region(region_id).items()
        )
        PROVIDERS.catalog_api.get_region.invalidate(
            PROVIDERS.catalog_api, region_id
        )
        self.assertLessEqual(
            updated_region.items(),
            PROVIDERS.catalog_api.get_region(region_id).items()
        )
        # delete the region
        PROVIDERS.catalog_api.driver.delete_region(region_id)
        # still get the old region
        self.assertLessEqual(
            updated_region.items(),
            PROVIDERS.catalog_api.get_region(region_id).items()
        )
        PROVIDERS.catalog_api.get_region.invalidate(
            PROVIDERS.catalog_api, region_id
        )
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region, region_id)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_region(self):
        new_region = unit.new_region_ref()
        region_id = new_region['id']
        PROVIDERS.catalog_api.create_region(new_region)

        # cache the region
        PROVIDERS.catalog_api.get_region(region_id)

        # update the region via catalog_api
        new_description = {'description': uuid.uuid4().hex}
        PROVIDERS.catalog_api.update_region(region_id, new_description)

        # assert that we can get the new region
        current_region = PROVIDERS.catalog_api.get_region(region_id)
        self.assertEqual(new_description['description'],
                         current_region['description'])

    def test_update_region_extras(self):
        new_region = unit.new_region_ref()
        region_id = new_region['id']
        PROVIDERS.catalog_api.create_region(new_region)

        email = 'keystone@openstack.org'
        new_ref = {'description': uuid.uuid4().hex,
                   'email': email}
        PROVIDERS.catalog_api.update_region(region_id, new_ref)

        current_region = PROVIDERS.catalog_api.get_region(region_id)
        self.assertEqual(email,
                         current_region['email'])

    def test_create_region_with_duplicate_id(self):
        new_region = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(new_region)
        # Create region again with duplicate id
        self.assertRaises(exception.Conflict,
                          PROVIDERS.catalog_api.create_region,
                          new_region)

    def test_get_region_returns_not_found(self):
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          uuid.uuid4().hex)

    def test_delete_region_returns_not_found(self):
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.delete_region,
                          uuid.uuid4().hex)

    def test_create_region_invalid_parent_region_returns_not_found(self):
        new_region = unit.new_region_ref(parent_region_id=uuid.uuid4().hex)
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.create_region,
                          new_region)

    def test_avoid_creating_circular_references_in_regions_update(self):
        region_one = self._create_region_with_parent_id()

        # self circle: region_one->region_one
        self.assertRaises(exception.CircularRegionHierarchyError,
                          PROVIDERS.catalog_api.update_region,
                          region_one['id'],
                          {'parent_region_id': region_one['id']})

        # region_one->region_two->region_one
        region_two = self._create_region_with_parent_id(region_one['id'])
        self.assertRaises(exception.CircularRegionHierarchyError,
                          PROVIDERS.catalog_api.update_region,
                          region_one['id'],
                          {'parent_region_id': region_two['id']})

        # region_one region_two->region_three->region_four->region_two
        region_three = self._create_region_with_parent_id(region_two['id'])
        region_four = self._create_region_with_parent_id(region_three['id'])
        self.assertRaises(exception.CircularRegionHierarchyError,
                          PROVIDERS.catalog_api.update_region,
                          region_two['id'],
                          {'parent_region_id': region_four['id']})

    @mock.patch.object(base.CatalogDriverBase,
                       "_ensure_no_circle_in_hierarchical_regions")
    def test_circular_regions_can_be_deleted(self, mock_ensure_on_circle):
        # turn off the enforcement so that cycles can be created for the test
        mock_ensure_on_circle.return_value = None

        region_one = self._create_region_with_parent_id()

        # self circle: region_one->region_one
        PROVIDERS.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_one['id']})
        PROVIDERS.catalog_api.delete_region(region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          region_one['id'])

        # region_one->region_two->region_one
        region_one = self._create_region_with_parent_id()
        region_two = self._create_region_with_parent_id(region_one['id'])
        PROVIDERS.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_two['id']})
        PROVIDERS.catalog_api.delete_region(region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          region_two['id'])

        # region_one->region_two->region_three->region_one
        region_one = self._create_region_with_parent_id()
        region_two = self._create_region_with_parent_id(region_one['id'])
        region_three = self._create_region_with_parent_id(region_two['id'])
        PROVIDERS.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_three['id']})
        PROVIDERS.catalog_api.delete_region(region_two['id'])
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          region_two['id'])
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.get_region,
                          region_three['id'])

    def test_service_crud(self):
        # create
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        res = PROVIDERS.catalog_api.create_service(service_id, new_service)
        self.assertDictEqual(new_service, res)

        # list
        services = PROVIDERS.catalog_api.list_services()
        self.assertIn(service_id, [x['id'] for x in services])

        # update
        service_name_update = {'name': uuid.uuid4().hex}
        res = PROVIDERS.catalog_api.update_service(
            service_id, service_name_update
        )
        expected_service = new_service.copy()
        expected_service['name'] = service_name_update['name']
        self.assertDictEqual(expected_service, res)

        # delete
        PROVIDERS.catalog_api.delete_service(service_id)
        self.assertRaises(exception.ServiceNotFound,
                          PROVIDERS.catalog_api.delete_service,
                          service_id)
        self.assertRaises(exception.ServiceNotFound,
                          PROVIDERS.catalog_api.get_service,
                          service_id)

    def _create_random_service(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        return PROVIDERS.catalog_api.create_service(service_id, new_service)

    def test_service_filtering(self):
        target_service = self._create_random_service()
        unrelated_service1 = self._create_random_service()
        unrelated_service2 = self._create_random_service()

        # filter by type
        hint_for_type = driver_hints.Hints()
        hint_for_type.add_filter(name="type", value=target_service['type'])
        services = PROVIDERS.catalog_api.list_services(hint_for_type)

        self.assertEqual(1, len(services))
        filtered_service = services[0]
        self.assertEqual(target_service['type'], filtered_service['type'])
        self.assertEqual(target_service['id'], filtered_service['id'])

        # filter should have been removed, since it was already used by the
        # backend
        self.assertEqual(0, len(hint_for_type.filters))

        # the backend shouldn't filter by name, since this is handled by the
        # front end
        hint_for_name = driver_hints.Hints()
        hint_for_name.add_filter(name="name", value=target_service['name'])
        services = PROVIDERS.catalog_api.list_services(hint_for_name)

        self.assertEqual(3, len(services))

        # filter should still be there, since it wasn't used by the backend
        self.assertEqual(1, len(hint_for_name.filters))

        PROVIDERS.catalog_api.delete_service(target_service['id'])
        PROVIDERS.catalog_api.delete_service(unrelated_service1['id'])
        PROVIDERS.catalog_api.delete_service(unrelated_service2['id'])

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_service_crud(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        res = PROVIDERS.catalog_api.create_service(service_id, new_service)
        self.assertDictEqual(new_service, res)
        PROVIDERS.catalog_api.get_service(service_id)
        updated_service = copy.deepcopy(new_service)
        updated_service['description'] = uuid.uuid4().hex
        # update bypassing catalog api
        PROVIDERS.catalog_api.driver.update_service(
            service_id, updated_service
        )
        self.assertLessEqual(
            new_service.items(),
            PROVIDERS.catalog_api.get_service(service_id).items()
        )
        PROVIDERS.catalog_api.get_service.invalidate(
            PROVIDERS.catalog_api, service_id
        )
        self.assertLessEqual(
            updated_service.items(),
            PROVIDERS.catalog_api.get_service(service_id).items()
        )

        # delete bypassing catalog api
        PROVIDERS.catalog_api.driver.delete_service(service_id)
        self.assertLessEqual(
            updated_service.items(),
            PROVIDERS.catalog_api.get_service(service_id).items()
        )
        PROVIDERS.catalog_api.get_service.invalidate(
            PROVIDERS.catalog_api, service_id
        )
        self.assertRaises(exception.ServiceNotFound,
                          PROVIDERS.catalog_api.delete_service,
                          service_id)
        self.assertRaises(exception.ServiceNotFound,
                          PROVIDERS.catalog_api.get_service,
                          service_id)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_service(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        PROVIDERS.catalog_api.create_service(service_id, new_service)

        # cache the service
        PROVIDERS.catalog_api.get_service(service_id)

        # update the service via catalog api
        new_type = {'type': uuid.uuid4().hex}
        PROVIDERS.catalog_api.update_service(service_id, new_type)

        # assert that we can get the new service
        current_service = PROVIDERS.catalog_api.get_service(service_id)
        self.assertEqual(new_type['type'], current_service['type'])

    def test_delete_service_with_endpoint(self):
        # create a service
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # deleting the service should also delete the endpoint
        PROVIDERS.catalog_api.delete_service(service['id'])
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.delete_endpoint,
                          endpoint['id'])

    def test_cache_layer_delete_service_with_endpoint(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)
        # cache the result
        PROVIDERS.catalog_api.get_service(service['id'])
        PROVIDERS.catalog_api.get_endpoint(endpoint['id'])
        # delete the service bypassing catalog api
        PROVIDERS.catalog_api.driver.delete_service(service['id'])
        self.assertLessEqual(
            endpoint.items(),
            PROVIDERS.catalog_api.get_endpoint(endpoint['id']).items())
        self.assertLessEqual(
            service.items(),
            PROVIDERS.catalog_api.get_service(service['id']).items())
        PROVIDERS.catalog_api.get_endpoint.invalidate(
            PROVIDERS.catalog_api, endpoint['id']
        )
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.delete_endpoint,
                          endpoint['id'])
        # multiple endpoints associated with a service
        second_endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                                region_id=None)
        PROVIDERS.catalog_api.create_service(service['id'], service)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)
        PROVIDERS.catalog_api.create_endpoint(
            second_endpoint['id'], second_endpoint
        )
        PROVIDERS.catalog_api.delete_service(service['id'])
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.delete_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.get_endpoint,
                          second_endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.delete_endpoint,
                          second_endpoint['id'])

    def test_get_service_returns_not_found(self):
        self.assertRaises(exception.ServiceNotFound,
                          PROVIDERS.catalog_api.get_service,
                          uuid.uuid4().hex)

    def test_delete_service_returns_not_found(self):
        self.assertRaises(exception.ServiceNotFound,
                          PROVIDERS.catalog_api.delete_service,
                          uuid.uuid4().hex)

    def test_create_endpoint_nonexistent_service(self):
        endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex,
                                         region_id=None)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_service(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_create_endpoint_nonexistent_region(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(service_id=service['id'])
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_region(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_get_endpoint_returns_not_found(self):
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.get_endpoint,
                          uuid.uuid4().hex)

    def test_delete_endpoint_returns_not_found(self):
        self.assertRaises(exception.EndpointNotFound,
                          PROVIDERS.catalog_api.delete_endpoint,
                          uuid.uuid4().hex)

    def test_create_endpoint(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

    def test_update_endpoint(self):
        dummy_service_ref, endpoint_ref, dummy_disabled_endpoint_ref = (
            self._create_endpoints())
        res = PROVIDERS.catalog_api.update_endpoint(
            endpoint_ref['id'], {'interface': 'private'}
        )
        expected_endpoint = endpoint_ref.copy()
        expected_endpoint['enabled'] = True
        expected_endpoint['interface'] = 'private'
        if self._legacy_endpoint_id_in_endpoint:
            expected_endpoint['legacy_endpoint_id'] = None
        if self._enabled_default_to_true_when_creating_endpoint:
            expected_endpoint['enabled'] = True
        self.assertDictEqual(expected_endpoint, res)

    def _create_endpoints(self):
        # Creates a service and 2 endpoints for the service in the same region.
        # The 'public' interface is enabled and the 'internal' interface is
        # disabled.

        def create_endpoint(service_id, region, **kwargs):
            ref = unit.new_endpoint_ref(
                service_id=service_id,
                region_id=region,
                url='http://localhost/%s' % uuid.uuid4().hex,
                **kwargs)

            PROVIDERS.catalog_api.create_endpoint(ref['id'], ref)
            return ref

        # Create a service for use with the endpoints.
        service_ref = unit.new_service_ref()
        service_id = service_ref['id']
        PROVIDERS.catalog_api.create_service(service_id, service_ref)

        region = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(region)

        # Create endpoints
        enabled_endpoint_ref = create_endpoint(service_id, region['id'])
        disabled_endpoint_ref = create_endpoint(
            service_id, region['id'], enabled=False, interface='internal')

        return service_ref, enabled_endpoint_ref, disabled_endpoint_ref

    def test_list_endpoints(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        expected_ids = set([uuid.uuid4().hex for _ in range(3)])
        for endpoint_id in expected_ids:
            endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                             id=endpoint_id,
                                             region_id=None)
            PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)

        endpoints = PROVIDERS.catalog_api.list_endpoints()
        self.assertEqual(expected_ids, set(e['id'] for e in endpoints))

    def test_get_v3_catalog_endpoint_disabled(self):
        """Get back only enabled endpoints when get the v3 catalog."""
        enabled_endpoint_ref = self._create_endpoints()[1]

        user_id = uuid.uuid4().hex
        # Use the project created by the default fixture since the project
        # should exist if we want to filter the catalog by the project or
        # replace the url with a valid project id.
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id, self.project_bar['id']
        )

        endpoint_ids = [x['id'] for x in catalog[0]['endpoints']]
        self.assertEqual([enabled_endpoint_ref['id']], endpoint_ids)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_endpoint(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # cache the endpoint
        PROVIDERS.catalog_api.get_endpoint(endpoint['id'])

        # update the endpoint via catalog api
        new_url = {'url': uuid.uuid4().hex}
        PROVIDERS.catalog_api.update_endpoint(endpoint['id'], new_url)

        # assert that we can get the new endpoint
        current_endpoint = PROVIDERS.catalog_api.get_endpoint(endpoint['id'])
        self.assertEqual(new_url['url'], current_endpoint['url'])
