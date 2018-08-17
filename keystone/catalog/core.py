# Copyright 2012 OpenStack Foundation
# Copyright 2012 Canonical Ltd.
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

"""Main entry point into the Catalog service."""

from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone import notifications


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


# This is a general cache region for catalog administration (CRUD operations).
MEMOIZE = cache.get_memoization_decorator(group='catalog')

# This builds a discrete cache region dedicated to complete service catalogs
# computed for a given user + project pair. Any write operation to create,
# modify or delete elements of the service catalog should invalidate this
# entire cache region.
COMPUTED_CATALOG_REGION = cache.create_region(name='computed catalog region')
MEMOIZE_COMPUTED_CATALOG = cache.get_memoization_decorator(
    group='catalog',
    region=COMPUTED_CATALOG_REGION)


class Manager(manager.Manager):
    """Default pivot point for the Catalog backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.catalog'
    _provides_api = 'catalog_api'

    _ENDPOINT = 'endpoint'
    _SERVICE = 'service'
    _REGION = 'region'

    def __init__(self):
        super(Manager, self).__init__(CONF.catalog.driver)
        notifications.register_event_callback(
            notifications.ACTIONS.deleted, 'project',
            self._on_project_or_endpoint_delete)
        notifications.register_event_callback(
            notifications.ACTIONS.deleted, 'endpoint',
            self._on_project_or_endpoint_delete)

    def _on_project_or_endpoint_delete(self, service, resource_type, operation,
                                       payload):
        project_or_endpoint_id = payload['resource_info']
        if resource_type == 'project':
            PROVIDERS.catalog_api.delete_association_by_project(
                project_or_endpoint_id)
            PROVIDERS.catalog_api.delete_endpoint_group_association_by_project(
                project_or_endpoint_id)
        else:
            PROVIDERS.catalog_api.delete_association_by_endpoint(
                project_or_endpoint_id)

    def create_region(self, region_ref, initiator=None):
        # Check duplicate ID
        try:
            self.get_region(region_ref['id'])
        except exception.RegionNotFound:  # nosec
            # A region with the same id doesn't exist already, good.
            pass
        else:
            msg = _('Duplicate ID, %s.') % region_ref['id']
            raise exception.Conflict(type='region', details=msg)

        # NOTE(lbragstad,dstanek): The description column of the region
        # database cannot be null. So if the user doesn't pass in a
        # description or passes in a null description then set it to an
        # empty string.
        if region_ref.get('description') is None:
            region_ref['description'] = ''
        try:
            ret = self.driver.create_region(region_ref)
        except exception.NotFound:
            parent_region_id = region_ref.get('parent_region_id')
            raise exception.RegionNotFound(region_id=parent_region_id)

        notifications.Audit.created(self._REGION, ret['id'], initiator)
        COMPUTED_CATALOG_REGION.invalidate()
        return ret

    @MEMOIZE
    def get_region(self, region_id):
        try:
            return self.driver.get_region(region_id)
        except exception.NotFound:
            raise exception.RegionNotFound(region_id=region_id)

    def update_region(self, region_id, region_ref, initiator=None):
        # NOTE(lbragstad,dstanek): The description column of the region
        # database cannot be null. So if the user passes in a null
        # description set it to an empty string.
        if 'description' in region_ref and region_ref['description'] is None:
            region_ref['description'] = ''
        ref = self.driver.update_region(region_id, region_ref)
        notifications.Audit.updated(self._REGION, region_id, initiator)
        self.get_region.invalidate(self, region_id)
        COMPUTED_CATALOG_REGION.invalidate()
        return ref

    def delete_region(self, region_id, initiator=None):
        try:
            ret = self.driver.delete_region(region_id)
            notifications.Audit.deleted(self._REGION, region_id, initiator)
            self.get_region.invalidate(self, region_id)
            COMPUTED_CATALOG_REGION.invalidate()
            return ret
        except exception.NotFound:
            raise exception.RegionNotFound(region_id=region_id)

    @manager.response_truncated
    def list_regions(self, hints=None):
        return self.driver.list_regions(hints or driver_hints.Hints())

    def create_service(self, service_id, service_ref, initiator=None):
        service_ref.setdefault('enabled', True)
        service_ref.setdefault('name', '')
        ref = self.driver.create_service(service_id, service_ref)
        notifications.Audit.created(self._SERVICE, service_id, initiator)
        COMPUTED_CATALOG_REGION.invalidate()
        return ref

    @MEMOIZE
    def get_service(self, service_id):
        try:
            return self.driver.get_service(service_id)
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    def update_service(self, service_id, service_ref, initiator=None):
        ref = self.driver.update_service(service_id, service_ref)
        notifications.Audit.updated(self._SERVICE, service_id, initiator)
        self.get_service.invalidate(self, service_id)
        COMPUTED_CATALOG_REGION.invalidate()
        return ref

    def delete_service(self, service_id, initiator=None):
        try:
            endpoints = self.list_endpoints()
            ret = self.driver.delete_service(service_id)
            notifications.Audit.deleted(self._SERVICE, service_id, initiator)
            self.get_service.invalidate(self, service_id)
            for endpoint in endpoints:
                if endpoint['service_id'] == service_id:
                    self.get_endpoint.invalidate(self, endpoint['id'])
            COMPUTED_CATALOG_REGION.invalidate()
            return ret
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    @manager.response_truncated
    def list_services(self, hints=None):
        return self.driver.list_services(hints or driver_hints.Hints())

    def _assert_region_exists(self, region_id):
        try:
            if region_id is not None:
                self.get_region(region_id)
        except exception.RegionNotFound:
            raise exception.ValidationError(attribute='endpoint region_id',
                                            target='region table')

    def _assert_service_exists(self, service_id):
        try:
            if service_id is not None:
                self.get_service(service_id)
        except exception.ServiceNotFound:
            raise exception.ValidationError(attribute='endpoint service_id',
                                            target='service table')

    def create_endpoint(self, endpoint_id, endpoint_ref, initiator=None):
        self._assert_region_exists(endpoint_ref.get('region_id'))
        self._assert_service_exists(endpoint_ref['service_id'])
        ref = self.driver.create_endpoint(endpoint_id, endpoint_ref)

        notifications.Audit.created(self._ENDPOINT, endpoint_id, initiator)
        COMPUTED_CATALOG_REGION.invalidate()
        return ref

    def update_endpoint(self, endpoint_id, endpoint_ref, initiator=None):
        self._assert_region_exists(endpoint_ref.get('region_id'))
        self._assert_service_exists(endpoint_ref.get('service_id'))
        ref = self.driver.update_endpoint(endpoint_id, endpoint_ref)
        notifications.Audit.updated(self._ENDPOINT, endpoint_id, initiator)
        self.get_endpoint.invalidate(self, endpoint_id)
        COMPUTED_CATALOG_REGION.invalidate()
        return ref

    def delete_endpoint(self, endpoint_id, initiator=None):
        try:
            ret = self.driver.delete_endpoint(endpoint_id)
            notifications.Audit.deleted(self._ENDPOINT, endpoint_id, initiator)
            self.get_endpoint.invalidate(self, endpoint_id)
            COMPUTED_CATALOG_REGION.invalidate()
            return ret
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    @MEMOIZE
    def get_endpoint(self, endpoint_id):
        try:
            return self.driver.get_endpoint(endpoint_id)
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    @manager.response_truncated
    def list_endpoints(self, hints=None):
        return self.driver.list_endpoints(hints or driver_hints.Hints())

    @MEMOIZE_COMPUTED_CATALOG
    def get_v3_catalog(self, user_id, project_id):
        return self.driver.get_v3_catalog(user_id, project_id)

    def add_endpoint_to_project(self, endpoint_id, project_id):
        self.driver.add_endpoint_to_project(endpoint_id, project_id)
        COMPUTED_CATALOG_REGION.invalidate()

    def remove_endpoint_from_project(self, endpoint_id, project_id):
        self.driver.remove_endpoint_from_project(endpoint_id, project_id)
        COMPUTED_CATALOG_REGION.invalidate()

    def add_endpoint_group_to_project(self, endpoint_group_id, project_id):
        self.driver.add_endpoint_group_to_project(
            endpoint_group_id, project_id)
        COMPUTED_CATALOG_REGION.invalidate()

    def remove_endpoint_group_from_project(self, endpoint_group_id,
                                           project_id):
        self.driver.remove_endpoint_group_from_project(
            endpoint_group_id, project_id)
        COMPUTED_CATALOG_REGION.invalidate()

    def delete_endpoint_group_association_by_project(self, project_id):
        try:
            self.driver.delete_endpoint_group_association_by_project(
                project_id)
        except exception.NotImplemented:
            # Some catalog drivers don't support this
            pass

    def get_endpoint_groups_for_project(self, project_id):
        # recover the project endpoint group memberships and for each
        # membership recover the endpoint group
        PROVIDERS.resource_api.get_project(project_id)
        try:
            refs = self.list_endpoint_groups_for_project(project_id)
            endpoint_groups = [self.get_endpoint_group(
                ref['endpoint_group_id']) for ref in refs]
            return endpoint_groups
        except exception.EndpointGroupNotFound:
            return []

    def get_endpoints_filtered_by_endpoint_group(self, endpoint_group_id):
        endpoints = self.list_endpoints()
        filters = self.get_endpoint_group(endpoint_group_id)['filters']
        filtered_endpoints = []

        for endpoint in endpoints:
            is_candidate = True
            for key, value in filters.items():
                if endpoint[key] != value:
                    is_candidate = False
                    break
            if is_candidate:
                filtered_endpoints.append(endpoint)
        return filtered_endpoints

    def list_endpoints_for_project(self, project_id):
        """List all endpoints associated with a project.

        :param project_id: project identifier to check
        :type project_id: string
        :returns: a list of endpoint ids or an empty list.

        """
        refs = self.driver.list_endpoints_for_project(project_id)
        filtered_endpoints = {}
        for ref in refs:
            try:
                endpoint = self.get_endpoint(ref['endpoint_id'])
                filtered_endpoints.update({ref['endpoint_id']: endpoint})
            except exception.EndpointNotFound:
                # remove bad reference from association
                self.remove_endpoint_from_project(ref['endpoint_id'],
                                                  project_id)

        # need to recover endpoint_groups associated with project
        # then for each endpoint group return the endpoints.
        endpoint_groups = self.get_endpoint_groups_for_project(project_id)
        for endpoint_group in endpoint_groups:
            endpoint_refs = self.get_endpoints_filtered_by_endpoint_group(
                endpoint_group['id'])
            # now check if any endpoints for current endpoint group are not
            # contained in the list of filtered endpoints
            for endpoint_ref in endpoint_refs:
                if endpoint_ref['id'] not in filtered_endpoints:
                    filtered_endpoints[endpoint_ref['id']] = endpoint_ref

        return filtered_endpoints

    def delete_association_by_endpoint(self, endpoint_id):
        try:
            self.driver.delete_association_by_endpoint(endpoint_id)
        except exception.NotImplemented:
            # Some catalog drivers don't support this
            pass

    def delete_association_by_project(self, project_id):
        try:
            self.driver.delete_association_by_project(project_id)
        except exception.NotImplemented:
            # Some catalog drivers don't support this
            pass
