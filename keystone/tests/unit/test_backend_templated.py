# Copyright 2012 OpenStack Foundation
#
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

import uuid

import mock
from six.moves import zip

from keystone.catalog.backends import base as catalog_base
from keystone.tests import unit
from keystone.tests.unit.catalog import test_backends as catalog_tests
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database


BROKEN_WRITE_FUNCTIONALITY_MSG = ("Templated backend doesn't correctly "
                                  "implement write operations")


class TestTemplatedCatalog(unit.TestCase, catalog_tests.CatalogTests):

    DEFAULT_FIXTURE = {
        'RegionOne': {
            'compute': {
                'adminURL': 'http://localhost:8774/v1.1/bar',
                'publicURL': 'http://localhost:8774/v1.1/bar',
                'internalURL': 'http://localhost:8774/v1.1/bar',
                'name': "'Compute Service'",
                'id': '2'
            },
            'identity': {
                'adminURL': 'http://localhost:35357/v2.0',
                'publicURL': 'http://localhost:5000/v2.0',
                'internalURL': 'http://localhost:35357/v2.0',
                'name': "'Identity Service'",
                'id': '1'
            }
        }
    }

    def setUp(self):
        super(TestTemplatedCatalog, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        self.load_fixtures(default_fixtures)

    def config_overrides(self):
        super(TestTemplatedCatalog, self).config_overrides()
        self.config_fixture.config(
            group='catalog',
            driver='templated',
            template_file=unit.dirs.tests('default_catalog.templates'))

    def test_get_catalog(self):
        catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
        self.assertDictEqual(self.DEFAULT_FIXTURE, catalog_ref)

    # NOTE(lbragstad): This test is skipped because the catalog is being
    # modified within the test and not through the API.
    @unit.skip_if_cache_is_enabled('catalog')
    def test_catalog_ignored_malformed_urls(self):
        # both endpoints are in the catalog
        catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
        self.assertEqual(2, len(catalog_ref['RegionOne']))

        region = self.catalog_api.driver.templates['RegionOne']
        region['compute']['adminURL'] = 'http://localhost:8774/v1.1/$(tenant)s'

        # the malformed one has been removed
        catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
        self.assertEqual(1, len(catalog_ref['RegionOne']))

    def test_get_catalog_endpoint_disabled(self):
        self.skip_test_overrides(
            "Templated backend doesn't have disabled endpoints")

    def test_get_v3_catalog_endpoint_disabled(self):
        self.skip_test_overrides(
            "Templated backend doesn't have disabled endpoints")

    def assert_catalogs_equal(self, expected, observed):
        sort_key = lambda d: d['id']
        for e, o in zip(sorted(expected, key=sort_key),
                        sorted(observed, key=sort_key)):
            expected_endpoints = e.pop('endpoints')
            observed_endpoints = o.pop('endpoints')
            self.assertDictEqual(e, o)
            self.assertItemsEqual(expected_endpoints, observed_endpoints)

    def test_get_v3_catalog(self):
        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        catalog_ref = self.catalog_api.get_v3_catalog(user_id, project_id)
        exp_catalog = [
            {'endpoints': [
                {'interface': 'admin',
                 'region': 'RegionOne',
                 'url': 'http://localhost:8774/v1.1/%s' % project_id},
                {'interface': 'public',
                 'region': 'RegionOne',
                 'url': 'http://localhost:8774/v1.1/%s' % project_id},
                {'interface': 'internal',
                 'region': 'RegionOne',
                 'url': 'http://localhost:8774/v1.1/%s' % project_id}],
             'type': 'compute',
             'name': "'Compute Service'",
             'id': '2'},
            {'endpoints': [
                {'interface': 'admin',
                 'region': 'RegionOne',
                 'url': 'http://localhost:35357/v2.0'},
                {'interface': 'public',
                 'region': 'RegionOne',
                 'url': 'http://localhost:5000/v2.0'},
                {'interface': 'internal',
                 'region': 'RegionOne',
                 'url': 'http://localhost:35357/v2.0'}],
             'type': 'identity',
             'name': "'Identity Service'",
             'id': '1'}]
        self.assert_catalogs_equal(exp_catalog, catalog_ref)

    def test_get_catalog_ignores_endpoints_with_invalid_urls(self):
        user_id = uuid.uuid4().hex
        project_id = None
        # If the URL has no 'project_id' to substitute, we will skip the
        # endpoint which contains this kind of URL.
        catalog_ref = self.catalog_api.get_v3_catalog(user_id, project_id)
        exp_catalog = [
            {'endpoints': [],
             'type': 'compute',
             'name': "'Compute Service'",
             'id': '2'},
            {'endpoints': [
                {'interface': 'admin',
                 'region': 'RegionOne',
                 'url': 'http://localhost:35357/v2.0'},
                {'interface': 'public',
                 'region': 'RegionOne',
                 'url': 'http://localhost:5000/v2.0'},
                {'interface': 'internal',
                 'region': 'RegionOne',
                 'url': 'http://localhost:35357/v2.0'}],
             'type': 'identity',
             'name': "'Identity Service'",
             'id': '1'}]
        self.assert_catalogs_equal(exp_catalog, catalog_ref)

    def test_list_regions_filtered_by_parent_region_id(self):
        self.skip_test_overrides('Templated backend does not support hints')

    def test_service_filtering(self):
        self.skip_test_overrides("Templated backend doesn't support filtering")

    def test_list_services_with_hints(self):
        hints = {}
        services = self.catalog_api.list_services(hints=hints)
        exp_services = [
            {'type': 'compute',
             'description': '',
             'enabled': True,
             'name': "'Compute Service'",
             'id': 'compute'},
            {'type': 'identity',
             'description': '',
             'enabled': True,
             'name': "'Identity Service'",
             'id': 'identity'}]
        self.assertItemsEqual(exp_services, services)

    # NOTE(dstanek): the following methods have been overridden
    # from unit.catalog.test_backends.CatalogTests.

    def test_region_crud(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_region_crud(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_region(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_create_region_with_duplicate_id(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_delete_region_returns_not_found(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_create_region_invalid_parent_region_returns_not_found(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_avoid_creating_circular_references_in_regions_update(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    @mock.patch.object(catalog_base.CatalogDriverBase,
                       "_ensure_no_circle_in_hierarchical_regions")
    def test_circular_regions_can_be_deleted(self, mock_ensure_on_circle):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_service_crud(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_service_crud(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_service(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_delete_service_with_endpoint(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_cache_layer_delete_service_with_endpoint(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_delete_service_returns_not_found(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_update_endpoint_nonexistent_service(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_create_endpoint_nonexistent_region(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_update_endpoint_nonexistent_region(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_get_endpoint_returns_not_found(self):
        self.skip_test_overrides(
            "Templated backend doesn't use IDs for endpoints.")

    def test_delete_endpoint_returns_not_found(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_create_endpoint(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_update_endpoint(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_list_endpoints(self):
        expected_urls = set(['http://localhost:$(public_port)s/v2.0',
                             'http://localhost:$(admin_port)s/v2.0',
                             'http://localhost:8774/v1.1/$(tenant_id)s'])
        endpoints = self.catalog_api.list_endpoints()
        self.assertEqual(expected_urls, set(e['url'] for e in endpoints))

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_endpoint(self):
        self.skip_test_overrides(BROKEN_WRITE_FUNCTIONALITY_MSG)

    def test_delete_endpoint_group_association_by_project(self):
        # Deleting endpoint group association is not supported by the templated
        # driver, but it should be silent about it and not raise an error.
        self.catalog_api.delete_endpoint_group_association_by_project(
            uuid.uuid4().hex)

    def test_delete_association_by_endpoint(self):
        # Deleting endpoint association is not supported by the templated
        # driver, but it should be silent about it and not raise an error.
        self.catalog_api.delete_association_by_endpoint(
            uuid.uuid4().hex)

    def test_delete_association_by_project(self):
        # Deleting endpoint association is not supported by the templated
        # driver, but it should be silent about it and not raise an error.
        self.catalog_api.delete_association_by_project(
            uuid.uuid4().hex)
