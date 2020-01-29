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

import abc

from keystone.common import provider_api
import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


class CatalogDriverBase(provider_api.ProviderAPIMixin, object,
                        metaclass=abc.ABCMeta):
    """Interface description for the Catalog driver."""

    def _get_list_limit(self):
        return CONF.catalog.list_limit or CONF.list_limit

    def _ensure_no_circle_in_hierarchical_regions(self, region_ref):
        if region_ref.get('parent_region_id') is None:
            return

        root_region_id = region_ref['id']
        parent_region_id = region_ref['parent_region_id']

        while parent_region_id:
            # NOTE(wanghong): check before getting parent region can ensure no
            # self circle
            if parent_region_id == root_region_id:
                raise exception.CircularRegionHierarchyError(
                    parent_region_id=parent_region_id)
            parent_region = self.get_region(parent_region_id)
            parent_region_id = parent_region.get('parent_region_id')

    @abc.abstractmethod
    def create_region(self, region_ref):
        """Create a new region.

        :raises keystone.exception.Conflict: If the region already exists.
        :raises keystone.exception.RegionNotFound: If the parent region
            is invalid.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_regions(self, hints):
        """List all regions.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: list of region_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_region(self, region_id):
        """Get region by id.

        :returns: region_ref dict
        :raises keystone.exception.RegionNotFound: If the region doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_region(self, region_id, region_ref):
        """Update region by id.

        :returns: region_ref dict
        :raises keystone.exception.RegionNotFound: If the region doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_region(self, region_id):
        """Delete an existing region.

        :raises keystone.exception.RegionNotFound: If the region doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_service(self, service_id, service_ref):
        """Create a new service.

        :raises keystone.exception.Conflict: If a duplicate service exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_services(self, hints):
        """List all services.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: list of service_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_service(self, service_id):
        """Get service by id.

        :returns: service_ref dict
        :raises keystone.exception.ServiceNotFound: If the service doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_service(self, service_id, service_ref):
        """Update service by id.

        :returns: service_ref dict
        :raises keystone.exception.ServiceNotFound: If the service doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_service(self, service_id):
        """Delete an existing service.

        :raises keystone.exception.ServiceNotFound: If the service doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_endpoint(self, endpoint_id, endpoint_ref):
        """Create a new endpoint for a service.

        :raises keystone.exception.Conflict: If a duplicate endpoint exists.
        :raises keystone.exception.ServiceNotFound: If the service doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_endpoint(self, endpoint_id):
        """Get endpoint by id.

        :returns: endpoint_ref dict
        :raises keystone.exception.EndpointNotFound: If the endpoint doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_endpoints(self, hints):
        """List all endpoints.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: list of endpoint_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_endpoint(self, endpoint_id, endpoint_ref):
        """Get endpoint by id.

        :returns: endpoint_ref dict
        :raises keystone.exception.EndpointNotFound: If the endpoint doesn't
            exist.
        :raises keystone.exception.ServiceNotFound: If the service doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_endpoint(self, endpoint_id):
        """Delete an endpoint for a service.

        :raises keystone.exception.EndpointNotFound: If the endpoint doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_catalog(self, user_id, project_id):
        """Retrieve and format the current service catalog.

        Example::

            { 'RegionOne':
                {'compute': {
                    'adminURL': u'http://host:8774/v1.1/project_id',
                    'internalURL': u'http://host:8774/v1.1/project_id',
                    'name': 'Compute Service',
                    'publicURL': u'http://host:8774/v1.1/project_id'},
                 'ec2': {
                    'adminURL': 'http://host:8773/services/Admin',
                    'internalURL': 'http://host:8773/services/Cloud',
                    'name': 'EC2 Service',
                    'publicURL': 'http://host:8773/services/Cloud'}}

        :returns: A nested dict representing the service catalog or an
                  empty dict.
        :raises keystone.exception.NotFound: If the endpoint doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    def get_v3_catalog(self, user_id, project_id):
        """Retrieve and format the current V3 service catalog.

        Example::

            [
                {
                    "endpoints": [
                    {
                        "interface": "public",
                        "id": "--endpoint-id--",
                        "region": "RegionOne",
                        "url": "http://external:8776/v1/--project-id--"
                    },
                    {
                        "interface": "internal",
                        "id": "--endpoint-id--",
                        "region": "RegionOne",
                        "url": "http://internal:8776/v1/--project-id--"
                    }],
                "id": "--service-id--",
                "type": "volume"
            }]

        :returns: A list representing the service catalog or an empty list
        :raises keystone.exception.NotFound: If the endpoint doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_endpoint_to_project(self, endpoint_id, project_id):
        """Create an endpoint to project association.

        :param endpoint_id: identity of endpoint to associate
        :type endpoint_id: string
        :param project_id: identity of the project to be associated with
        :type project_id: string
        :raises: keystone.exception.Conflict: If the endpoint was already
            added to project.
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_endpoint_from_project(self, endpoint_id, project_id):
        """Remove an endpoint to project association.

        :param endpoint_id: identity of endpoint to remove
        :type endpoint_id: string
        :param project_id: identity of the project associated with
        :type project_id: string
        :raises keystone.exception.NotFound: If the endpoint was not found
            in the project.
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_endpoint_in_project(self, endpoint_id, project_id):
        """Check if an endpoint is associated with a project.

        :param endpoint_id: identity of endpoint to check
        :type endpoint_id: string
        :param project_id: identity of the project associated with
        :type project_id: string
        :raises keystone.exception.NotFound: If the endpoint was not found
            in the project.
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_endpoints_for_project(self, project_id):
        """List all endpoints associated with a project.

        :param project_id: identity of the project to check
        :type project_id: string
        :returns: a list of identity endpoint ids or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_projects_for_endpoint(self, endpoint_id):
        """List all projects associated with an endpoint.

        :param endpoint_id: identity of endpoint to check
        :type endpoint_id: string
        :returns: a list of projects or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_association_by_endpoint(self, endpoint_id):
        """Remove all the endpoints to project association with endpoint.

        :param endpoint_id: identity of endpoint to check
        :type endpoint_id: string
        :returns: None

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_association_by_project(self, project_id):
        """Remove all the endpoints to project association with project.

        :param project_id: identity of the project to check
        :type project_id: string
        :returns: None

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_endpoint_group(self, endpoint_group):
        """Create an endpoint group.

        :param endpoint_group: endpoint group to create
        :type endpoint_group: dictionary
        :raises: keystone.exception.Conflict: If a duplicate endpoint group
            already exists.
        :returns: an endpoint group representation.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_endpoint_group(self, endpoint_group_id):
        """Get an endpoint group.

        :param endpoint_group_id: identity of endpoint group to retrieve
        :type endpoint_group_id: string
        :raises keystone.exception.NotFound: If the endpoint group was not
            found.
        :returns: an endpoint group representation.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_endpoint_group(self, endpoint_group_id, endpoint_group):
        """Update an endpoint group.

        :param endpoint_group_id: identity of endpoint group to retrieve
        :type endpoint_group_id: string
        :param endpoint_group: A full or partial endpoint_group
        :type endpoint_group: dictionary
        :raises keystone.exception.NotFound: If the endpoint group was not
            found.
        :returns: an endpoint group representation.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_endpoint_group(self, endpoint_group_id):
        """Delete an endpoint group.

        :param endpoint_group_id: identity of endpoint group to delete
        :type endpoint_group_id: string
        :raises keystone.exception.NotFound: If the endpoint group was not
            found.
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_endpoint_group_to_project(self, endpoint_group_id, project_id):
        """Add an endpoint group to project association.

        :param endpoint_group_id: identity of endpoint to associate
        :type endpoint_group_id: string
        :param project_id: identity of project to associate
        :type project_id: string
        :raises keystone.exception.Conflict: If the endpoint group was already
            added to the project.
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_endpoint_group_in_project(self, endpoint_group_id, project_id):
        """Get endpoint group to project association.

        :param endpoint_group_id: identity of endpoint group to retrieve
        :type endpoint_group_id: string
        :param project_id: identity of project to associate
        :type project_id: string
        :raises keystone.exception.NotFound: If the endpoint group to the
            project association was not found.
        :returns: a project endpoint group representation.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_endpoint_groups(self, hints):
        """List all endpoint groups.

        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_endpoint_groups_for_project(self, project_id):
        """List all endpoint group to project associations for a project.

        :param project_id: identity of project to associate
        :type project_id: string
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_projects_associated_with_endpoint_group(self, endpoint_group_id):
        """List all projects associated with endpoint group.

        :param endpoint_group_id: identity of endpoint to associate
        :type endpoint_group_id: string
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_endpoint_group_from_project(self, endpoint_group_id,
                                           project_id):
        """Remove an endpoint to project association.

        :param endpoint_group_id: identity of endpoint to associate
        :type endpoint_group_id: string
        :param project_id: identity of project to associate
        :type project_id: string
        :raises keystone.exception.NotFound: If endpoint group project
            association was not found.
        :returns: None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_endpoint_group_association_by_project(self, project_id):
        """Remove endpoint group to project associations.

        :param project_id: identity of the project to check
        :type project_id: string
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover
