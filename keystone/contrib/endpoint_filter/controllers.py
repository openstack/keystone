# Copyright 2013 OpenStack Foundation
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

import six

from keystone.catalog import controllers as catalog_controllers
from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.contrib.endpoint_filter import schema
from keystone import exception
from keystone import notifications
from keystone import resource


@dependency.requires('catalog_api', 'endpoint_filter_api', 'resource_api')
class _ControllerBase(controller.V3Controller):
    """Base behaviors for endpoint filter controllers."""

    def _get_endpoint_groups_for_project(self, project_id):
        # recover the project endpoint group memberships and for each
        # membership recover the endpoint group
        self.resource_api.get_project(project_id)
        try:
            refs = self.endpoint_filter_api.list_endpoint_groups_for_project(
                project_id)
            endpoint_groups = [self.endpoint_filter_api.get_endpoint_group(
                ref['endpoint_group_id']) for ref in refs]
            return endpoint_groups
        except exception.EndpointGroupNotFound:
            return []

    def _get_endpoints_filtered_by_endpoint_group(self, endpoint_group_id):
        endpoints = self.catalog_api.list_endpoints()
        filters = self.endpoint_filter_api.get_endpoint_group(
            endpoint_group_id)['filters']
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


class EndpointFilterV3Controller(_ControllerBase):

    def __init__(self):
        super(EndpointFilterV3Controller, self).__init__()
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
            self.endpoint_filter_api.delete_association_by_project(
                project_or_endpoint_id)
        else:
            self.endpoint_filter_api.delete_association_by_endpoint(
                project_or_endpoint_id)

    @controller.protected()
    def add_endpoint_to_project(self, context, project_id, endpoint_id):
        """Establishes an association between an endpoint and a project."""
        # NOTE(gyee): we just need to make sure endpoint and project exist
        # first. We don't really care whether if project is disabled.
        # The relationship can still be established even with a disabled
        # project as there are no security implications.
        self.catalog_api.get_endpoint(endpoint_id)
        self.resource_api.get_project(project_id)
        self.endpoint_filter_api.add_endpoint_to_project(endpoint_id,
                                                         project_id)

    @controller.protected()
    def check_endpoint_in_project(self, context, project_id, endpoint_id):
        """Verifies endpoint is currently associated with given project."""
        self.catalog_api.get_endpoint(endpoint_id)
        self.resource_api.get_project(project_id)
        self.endpoint_filter_api.check_endpoint_in_project(endpoint_id,
                                                           project_id)

    @controller.protected()
    def list_endpoints_for_project(self, context, project_id):
        """List all endpoints currently associated with a given project."""
        self.resource_api.get_project(project_id)
        refs = self.endpoint_filter_api.list_endpoints_for_project(project_id)
        filtered_endpoints = {ref['endpoint_id']:
                              self.catalog_api.get_endpoint(ref['endpoint_id'])
                              for ref in refs}

        # need to recover endpoint_groups associated with project
        # then for each endpoint group return the endpoints.
        endpoint_groups = self._get_endpoint_groups_for_project(project_id)
        for endpoint_group in endpoint_groups:
            endpoint_refs = self._get_endpoints_filtered_by_endpoint_group(
                endpoint_group['id'])
            # now check if any endpoints for current endpoint group are not
            # contained in the list of filtered endpoints
            for endpoint_ref in endpoint_refs:
                if endpoint_ref['id'] not in filtered_endpoints:
                    filtered_endpoints[endpoint_ref['id']] = endpoint_ref

        return catalog_controllers.EndpointV3.wrap_collection(
            context, [v for v in six.itervalues(filtered_endpoints)])

    @controller.protected()
    def remove_endpoint_from_project(self, context, project_id, endpoint_id):
        """Remove the endpoint from the association with given project."""
        self.endpoint_filter_api.remove_endpoint_from_project(endpoint_id,
                                                              project_id)

    @controller.protected()
    def list_projects_for_endpoint(self, context, endpoint_id):
        """Return a list of projects associated with the endpoint."""
        self.catalog_api.get_endpoint(endpoint_id)
        refs = self.endpoint_filter_api.list_projects_for_endpoint(endpoint_id)

        projects = [self.resource_api.get_project(
            ref['project_id']) for ref in refs]
        return resource.controllers.ProjectV3.wrap_collection(context,
                                                              projects)


class EndpointGroupV3Controller(_ControllerBase):
    collection_name = 'endpoint_groups'
    member_name = 'endpoint_group'

    VALID_FILTER_KEYS = ['service_id', 'region_id', 'interface']

    def __init__(self):
        super(EndpointGroupV3Controller, self).__init__()

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""

        path = '/OS-EP-FILTER/' + cls.collection_name
        return super(EndpointGroupV3Controller, cls).base_url(context,
                                                              path=path)

    @controller.protected()
    @validation.validated(schema.endpoint_group_create, 'endpoint_group')
    def create_endpoint_group(self, context, endpoint_group):
        """Creates an Endpoint Group with the associated filters."""
        ref = self._assign_unique_id(self._normalize_dict(endpoint_group))
        self._require_attribute(ref, 'filters')
        self._require_valid_filter(ref)
        ref = self.endpoint_filter_api.create_endpoint_group(ref['id'], ref)
        return EndpointGroupV3Controller.wrap_member(context, ref)

    def _require_valid_filter(self, endpoint_group):
        filters = endpoint_group.get('filters')
        for key in six.iterkeys(filters):
            if key not in self.VALID_FILTER_KEYS:
                raise exception.ValidationError(
                    attribute=self._valid_filter_keys(),
                    target='endpoint_group')

    def _valid_filter_keys(self):
        return ' or '.join(self.VALID_FILTER_KEYS)

    @controller.protected()
    def get_endpoint_group(self, context, endpoint_group_id):
        """Retrieve the endpoint group associated with the id if exists."""
        ref = self.endpoint_filter_api.get_endpoint_group(endpoint_group_id)
        return EndpointGroupV3Controller.wrap_member(
            context, ref)

    @controller.protected()
    @validation.validated(schema.endpoint_group_update, 'endpoint_group')
    def update_endpoint_group(self, context, endpoint_group_id,
                              endpoint_group):
        """Update fixed values and/or extend the filters."""
        if 'filters' in endpoint_group:
            self._require_valid_filter(endpoint_group)
        ref = self.endpoint_filter_api.update_endpoint_group(endpoint_group_id,
                                                             endpoint_group)
        return EndpointGroupV3Controller.wrap_member(
            context, ref)

    @controller.protected()
    def delete_endpoint_group(self, context, endpoint_group_id):
        """Delete endpoint_group."""
        self.endpoint_filter_api.delete_endpoint_group(endpoint_group_id)

    @controller.protected()
    def list_endpoint_groups(self, context):
        """List all endpoint groups."""
        refs = self.endpoint_filter_api.list_endpoint_groups()
        return EndpointGroupV3Controller.wrap_collection(
            context, refs)

    @controller.protected()
    def list_endpoint_groups_for_project(self, context, project_id):
        """List all endpoint groups associated with a given project."""
        return EndpointGroupV3Controller.wrap_collection(
            context, self._get_endpoint_groups_for_project(project_id))

    @controller.protected()
    def list_projects_associated_with_endpoint_group(self,
                                                     context,
                                                     endpoint_group_id):
        """List all projects associated with endpoint group."""
        endpoint_group_refs = (self.endpoint_filter_api.
                               list_projects_associated_with_endpoint_group(
                                   endpoint_group_id))
        projects = []
        for endpoint_group_ref in endpoint_group_refs:
            project = self.resource_api.get_project(
                endpoint_group_ref['project_id'])
            if project:
                projects.append(project)
        return resource.controllers.ProjectV3.wrap_collection(context,
                                                              projects)

    @controller.protected()
    def list_endpoints_associated_with_endpoint_group(self,
                                                      context,
                                                      endpoint_group_id):
        """List all the endpoints filtered by a specific endpoint group."""
        filtered_endpoints = self._get_endpoints_filtered_by_endpoint_group(
            endpoint_group_id)
        return catalog_controllers.EndpointV3.wrap_collection(
            context, filtered_endpoints)


class ProjectEndpointGroupV3Controller(_ControllerBase):
    collection_name = 'project_endpoint_groups'
    member_name = 'project_endpoint_group'

    def __init__(self):
        super(ProjectEndpointGroupV3Controller, self).__init__()
        notifications.register_event_callback(
            notifications.ACTIONS.deleted, 'project',
            self._on_project_delete)

    def _on_project_delete(self, service, resource_type,
                           operation, payload):
        project_id = payload['resource_info']
        (self.endpoint_filter_api.
            delete_endpoint_group_association_by_project(
                project_id))

    @controller.protected()
    def get_endpoint_group_in_project(self, context, endpoint_group_id,
                                      project_id):
        """Retrieve the endpoint group associated with the id if exists."""
        self.resource_api.get_project(project_id)
        self.endpoint_filter_api.get_endpoint_group(endpoint_group_id)
        ref = self.endpoint_filter_api.get_endpoint_group_in_project(
            endpoint_group_id, project_id)
        return ProjectEndpointGroupV3Controller.wrap_member(
            context, ref)

    @controller.protected()
    def add_endpoint_group_to_project(self, context, endpoint_group_id,
                                      project_id):
        """Creates an association between an endpoint group and project."""
        self.resource_api.get_project(project_id)
        self.endpoint_filter_api.get_endpoint_group(endpoint_group_id)
        self.endpoint_filter_api.add_endpoint_group_to_project(
            endpoint_group_id, project_id)

    @controller.protected()
    def remove_endpoint_group_from_project(self, context, endpoint_group_id,
                                           project_id):
        """Remove the endpoint group from associated project."""
        self.resource_api.get_project(project_id)
        self.endpoint_filter_api.get_endpoint_group(endpoint_group_id)
        self.endpoint_filter_api.remove_endpoint_group_from_project(
            endpoint_group_id, project_id)

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        url = ('/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s'
               '/projects/%(project_id)s' % {
                   'endpoint_group_id': ref['endpoint_group_id'],
                   'project_id': ref['project_id']})
        ref.setdefault('links', {})
        ref['links']['self'] = url
