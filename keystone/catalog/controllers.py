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

from six.moves import http_client

from keystone.catalog import schema
from keystone.common import controller
from keystone.common import provider_api
from keystone.common import utils
from keystone.common import validation
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone import notifications
from keystone import resource


INTERFACES = ['public', 'internal', 'admin']
PROVIDERS = provider_api.ProviderAPIs


class RegionV3(controller.V3Controller):
    collection_name = 'regions'
    member_name = 'region'

    def create_region_with_id(self, request, region_id, region):
        """Create a region with a user-specified ID.

        This method is unprotected because it depends on ``self.create_region``
        to enforce policy.
        """
        if 'id' in region and region_id != region['id']:
            raise exception.ValidationError(
                _('Conflicting region IDs specified: '
                  '"%(url_id)s" != "%(ref_id)s"') % {
                      'url_id': region_id,
                      'ref_id': region['id']})
        region['id'] = region_id
        return self.create_region(request, region)

    @controller.protected()
    def create_region(self, request, region):
        validation.lazy_validate(schema.region_create, region)
        ref = self._normalize_dict(region)

        if not ref.get('id'):
            ref = self._assign_unique_id(ref)

        ref = PROVIDERS.catalog_api.create_region(
            ref, initiator=request.audit_initiator
        )
        return wsgi.render_response(
            RegionV3.wrap_member(request.context_dict, ref),
            status=(http_client.CREATED,
                    http_client.responses[http_client.CREATED]))

    @controller.filterprotected('parent_region_id')
    def list_regions(self, request, filters):
        hints = RegionV3.build_driver_hints(request, filters)
        refs = PROVIDERS.catalog_api.list_regions(hints)
        return RegionV3.wrap_collection(request.context_dict,
                                        refs,
                                        hints=hints)

    @controller.protected()
    def get_region(self, request, region_id):
        ref = PROVIDERS.catalog_api.get_region(region_id)
        return RegionV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_region(self, request, region_id, region):
        validation.lazy_validate(schema.region_update, region)
        self._require_matching_id(region_id, region)
        ref = PROVIDERS.catalog_api.update_region(
            region_id, region, initiator=request.audit_initiator
        )
        return RegionV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_region(self, request, region_id):
        return PROVIDERS.catalog_api.delete_region(
            region_id, initiator=request.audit_initiator
        )


class ServiceV3(controller.V3Controller):
    collection_name = 'services'
    member_name = 'service'

    def __init__(self):
        super(ServiceV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.catalog_api.get_service

    @controller.protected()
    def create_service(self, request, service):
        validation.lazy_validate(schema.service_create, service)
        ref = self._assign_unique_id(self._normalize_dict(service))
        ref = PROVIDERS.catalog_api.create_service(
            ref['id'], ref, initiator=request.audit_initiator
        )
        return ServiceV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('type', 'name')
    def list_services(self, request, filters):
        hints = ServiceV3.build_driver_hints(request, filters)
        refs = PROVIDERS.catalog_api.list_services(hints=hints)
        return ServiceV3.wrap_collection(request.context_dict,
                                         refs,
                                         hints=hints)

    @controller.protected()
    def get_service(self, request, service_id):
        ref = PROVIDERS.catalog_api.get_service(service_id)
        return ServiceV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_service(self, request, service_id, service):
        validation.lazy_validate(schema.service_update, service)
        self._require_matching_id(service_id, service)
        ref = PROVIDERS.catalog_api.update_service(
            service_id, service, initiator=request.audit_initiator
        )
        return ServiceV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_service(self, request, service_id):
        return PROVIDERS.catalog_api.delete_service(
            service_id, initiator=request.audit_initiator
        )


class EndpointV3(controller.V3Controller):
    collection_name = 'endpoints'
    member_name = 'endpoint'

    def __init__(self):
        super(EndpointV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.catalog_api.get_endpoint

    @classmethod
    def filter_endpoint(cls, ref):
        if 'legacy_endpoint_id' in ref:
            ref.pop('legacy_endpoint_id')
        ref['region'] = ref['region_id']
        return ref

    @classmethod
    def wrap_member(cls, context, ref):
        ref = cls.filter_endpoint(ref)
        return super(EndpointV3, cls).wrap_member(context, ref)

    def _validate_endpoint_region(self, endpoint, request):
        """Ensure the region for the endpoint exists.

        If 'region_id' is used to specify the region, then we will let the
        manager/driver take care of this.  If, however, 'region' is used,
        then for backward compatibility, we will auto-create the region.

        """
        if (endpoint.get('region_id') is None and
                endpoint.get('region') is not None):
            # To maintain backward compatibility with clients that are
            # using the v3 API in the same way as they used the v2 API,
            # create the endpoint region, if that region does not exist
            # in keystone.
            endpoint['region_id'] = endpoint.pop('region')
            try:
                PROVIDERS.catalog_api.get_region(endpoint['region_id'])
            except exception.RegionNotFound:
                region = dict(id=endpoint['region_id'])
                PROVIDERS.catalog_api.create_region(
                    region, initiator=request.audit_initiator
                )

        return endpoint

    @controller.protected()
    def create_endpoint(self, request, endpoint):
        validation.lazy_validate(schema.endpoint_create, endpoint)
        utils.check_endpoint_url(endpoint['url'])
        ref = self._assign_unique_id(self._normalize_dict(endpoint))
        ref = self._validate_endpoint_region(ref, request)
        ref = PROVIDERS.catalog_api.create_endpoint(
            ref['id'], ref, initiator=request.audit_initiator
        )
        return EndpointV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('interface', 'service_id', 'region_id')
    def list_endpoints(self, request, filters):
        hints = EndpointV3.build_driver_hints(request, filters)
        refs = PROVIDERS.catalog_api.list_endpoints(hints=hints)
        return EndpointV3.wrap_collection(request.context_dict,
                                          refs,
                                          hints=hints)

    @controller.protected()
    def get_endpoint(self, request, endpoint_id):
        ref = PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        return EndpointV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_endpoint(self, request, endpoint_id, endpoint):
        validation.lazy_validate(schema.endpoint_update, endpoint)
        self._require_matching_id(endpoint_id, endpoint)

        endpoint = self._validate_endpoint_region(endpoint.copy(),
                                                  request)

        ref = PROVIDERS.catalog_api.update_endpoint(
            endpoint_id, endpoint, initiator=request.audit_initiator
        )
        return EndpointV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_endpoint(self, request, endpoint_id):
        return PROVIDERS.catalog_api.delete_endpoint(
            endpoint_id, initiator=request.audit_initiator
        )


class EndpointFilterV3Controller(controller.V3Controller):

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
            PROVIDERS.catalog_api.delete_association_by_project(
                project_or_endpoint_id)
        else:
            PROVIDERS.catalog_api.delete_association_by_endpoint(
                project_or_endpoint_id)

    @controller.protected()
    def add_endpoint_to_project(self, request, project_id, endpoint_id):
        """Establish an association between an endpoint and a project."""
        # NOTE(gyee): we just need to make sure endpoint and project exist
        # first. We don't really care whether if project is disabled.
        # The relationship can still be established even with a disabled
        # project as there are no security implications.
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.add_endpoint_to_project(endpoint_id,
                                                      project_id)

    @controller.protected()
    def check_endpoint_in_project(self, request, project_id, endpoint_id):
        """Verify endpoint is currently associated with given project."""
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.check_endpoint_in_project(endpoint_id,
                                                        project_id)

    @controller.protected()
    def list_endpoints_for_project(self, request, project_id):
        """List all endpoints currently associated with a given project."""
        PROVIDERS.resource_api.get_project(project_id)
        filtered_endpoints = PROVIDERS.catalog_api.list_endpoints_for_project(
            project_id)

        return EndpointV3.wrap_collection(
            request.context_dict,
            [v for v in filtered_endpoints.values()])

    @controller.protected()
    def remove_endpoint_from_project(self, request, project_id, endpoint_id):
        """Remove the endpoint from the association with given project."""
        PROVIDERS.catalog_api.remove_endpoint_from_project(endpoint_id,
                                                           project_id)

    @controller.protected()
    def list_projects_for_endpoint(self, request, endpoint_id):
        """Return a list of projects associated with the endpoint."""
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        refs = PROVIDERS.catalog_api.list_projects_for_endpoint(endpoint_id)

        projects = [PROVIDERS.resource_api.get_project(
            ref['project_id']) for ref in refs]
        return resource.controllers.ProjectV3.wrap_collection(
            request.context_dict, projects)


class EndpointGroupV3Controller(controller.V3Controller):
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
    def create_endpoint_group(self, request, endpoint_group):
        """Create an Endpoint Group with the associated filters."""
        validation.lazy_validate(schema.endpoint_group_create, endpoint_group)
        ref = self._assign_unique_id(self._normalize_dict(endpoint_group))
        self._require_attribute(ref, 'filters')
        self._require_valid_filter(ref)
        ref = PROVIDERS.catalog_api.create_endpoint_group(ref['id'], ref)
        return EndpointGroupV3Controller.wrap_member(request.context_dict, ref)

    def _require_valid_filter(self, endpoint_group):
        filters = endpoint_group.get('filters')
        for key in filters.keys():
            if key not in self.VALID_FILTER_KEYS:
                raise exception.ValidationError(
                    attribute=self._valid_filter_keys(),
                    target='endpoint_group')

    def _valid_filter_keys(self):
        return ' or '.join(self.VALID_FILTER_KEYS)

    @controller.protected()
    def get_endpoint_group(self, request, endpoint_group_id):
        """Retrieve the endpoint group associated with the id if exists."""
        ref = PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id)
        return EndpointGroupV3Controller.wrap_member(
            request.context_dict, ref)

    @controller.protected()
    def update_endpoint_group(self, request, endpoint_group_id,
                              endpoint_group):
        """Update fixed values and/or extend the filters."""
        validation.lazy_validate(schema.endpoint_group_update, endpoint_group)
        if 'filters' in endpoint_group:
            self._require_valid_filter(endpoint_group)
        ref = PROVIDERS.catalog_api.update_endpoint_group(endpoint_group_id,
                                                          endpoint_group)
        return EndpointGroupV3Controller.wrap_member(
            request.context_dict, ref)

    @controller.protected()
    def delete_endpoint_group(self, request, endpoint_group_id):
        """Delete endpoint_group."""
        PROVIDERS.catalog_api.delete_endpoint_group(endpoint_group_id)

    @controller.protected()
    def list_endpoint_groups(self, request):
        """List all endpoint groups."""
        refs = PROVIDERS.catalog_api.list_endpoint_groups()
        return EndpointGroupV3Controller.wrap_collection(
            request.context_dict, refs)

    @controller.protected()
    def list_endpoint_groups_for_project(self, request, project_id):
        """List all endpoint groups associated with a given project."""
        return EndpointGroupV3Controller.wrap_collection(
            request.context_dict,
            PROVIDERS.catalog_api.get_endpoint_groups_for_project(project_id))

    @controller.protected()
    def list_projects_associated_with_endpoint_group(self,
                                                     request,
                                                     endpoint_group_id):
        """List all projects associated with endpoint group."""
        endpoint_group_refs = (PROVIDERS.catalog_api.
                               list_projects_associated_with_endpoint_group(
                                   endpoint_group_id))
        projects = []
        for endpoint_group_ref in endpoint_group_refs:
            project = PROVIDERS.resource_api.get_project(
                endpoint_group_ref['project_id'])
            if project:
                projects.append(project)
        return resource.controllers.ProjectV3.wrap_collection(
            request.context_dict, projects)

    @controller.protected()
    def list_endpoints_associated_with_endpoint_group(self,
                                                      request,
                                                      endpoint_group_id):
        """List all the endpoints filtered by a specific endpoint group."""
        filtered_endpoints = (PROVIDERS.catalog_api.
                              get_endpoints_filtered_by_endpoint_group(
                                  endpoint_group_id))
        return EndpointV3.wrap_collection(request.context_dict,
                                          filtered_endpoints)


class ProjectEndpointGroupV3Controller(controller.V3Controller):
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
        PROVIDERS.catalog_api.delete_endpoint_group_association_by_project(
            project_id)

    @controller.protected()
    def get_endpoint_group_in_project(self, request, endpoint_group_id,
                                      project_id):
        """Retrieve the endpoint group associated with the id if exists."""
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id)
        ref = PROVIDERS.catalog_api.get_endpoint_group_in_project(
            endpoint_group_id, project_id)
        return ProjectEndpointGroupV3Controller.wrap_member(
            request.context_dict, ref)

    @controller.protected()
    def add_endpoint_group_to_project(self, request, endpoint_group_id,
                                      project_id):
        """Create an association between an endpoint group and project."""
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id)
        PROVIDERS.catalog_api.add_endpoint_group_to_project(
            endpoint_group_id, project_id)

    @controller.protected()
    def remove_endpoint_group_from_project(self, request, endpoint_group_id,
                                           project_id):
        """Remove the endpoint group from associated project."""
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id)
        PROVIDERS.catalog_api.remove_endpoint_group_from_project(
            endpoint_group_id, project_id)

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        url = ('/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s'
               '/projects/%(project_id)s' % {
                   'endpoint_group_id': ref['endpoint_group_id'],
                   'project_id': ref['project_id']})
        ref.setdefault('links', {})
        ref['links']['self'] = url
