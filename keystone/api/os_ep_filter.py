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

# This file handles all flask-restful resources for /OS-EP-FILTER

import flask_restful
import http.client

from keystone.api._shared import json_home_relations
from keystone.api import endpoints as _endpoints_api
from keystone.catalog import schema
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask


ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs

_build_resource_relation = json_home_relations.os_ep_filter_resource_rel_func
_build_parameter_relation = json_home_relations.os_ep_filter_parameter_rel_func

_ENDPOINT_GROUP_PARAMETER_RELATION = _build_parameter_relation(
    parameter_name='endpoint_group_id')


# NOTE(morgan): This is shared from keystone.api.endpoint, this is a special
# case where cross-api code is used. This pattern should not be replicated.
_filter_endpoint = _endpoints_api._filter_endpoint


class EndpointGroupsResource(ks_flask.ResourceBase):
    collection_key = 'endpoint_groups'
    member_key = 'endpoint_group'
    api_prefix = '/OS-EP-FILTER'
    json_home_resource_rel_func = _build_resource_relation
    json_home_parameter_rel_func = _build_parameter_relation

    @staticmethod
    def _require_valid_filter(endpoint_group):
        valid_filter_keys = ['service_id', 'region_id', 'interface']

        filters = endpoint_group.get('filters')
        for key in filters.keys():
            if key not in valid_filter_keys:
                raise exception.ValidationError(
                    attribute=' or '.join(valid_filter_keys),
                    target='endpoint_group')

    def _get_endpoint_group(self, endpoint_group_id):
        ENFORCER.enforce_call(action='identity:get_endpoint_group')
        return self.wrap_member(
            PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id))

    def _list_endpoint_groups(self):
        filters = ('name')
        ENFORCER.enforce_call(action='identity:list_endpoint_groups',
                              filters=filters)
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.catalog_api.list_endpoint_groups(hints)
        return self.wrap_collection(refs, hints=hints)

    def get(self, endpoint_group_id=None):
        if endpoint_group_id is not None:
            return self._get_endpoint_group(endpoint_group_id)
        return self._list_endpoint_groups()

    def post(self):
        ENFORCER.enforce_call(action='identity:create_endpoint_group')
        ep_group = self.request_body_json.get('endpoint_group', {})
        validation.lazy_validate(schema.endpoint_group_create, ep_group)
        if not ep_group.get('filters'):
            # TODO(morgan): Make this not require substitution. Substitution is
            # done here due to String Freeze in the Rocky release.
            msg = _('%s field is required and cannot be empty') % 'filters'
            raise exception.ValidationError(message=msg)
        self._require_valid_filter(ep_group)
        ep_group = self._assign_unique_id(ep_group)
        return self.wrap_member(PROVIDERS.catalog_api.create_endpoint_group(
            ep_group['id'], ep_group)), http.client.CREATED

    def patch(self, endpoint_group_id):
        ENFORCER.enforce_call(action='identity:update_endpoint_group')
        ep_group = self.request_body_json.get('endpoint_group', {})
        validation.lazy_validate(schema.endpoint_group_update, ep_group)
        if 'filters' in ep_group:
            self._require_valid_filter(ep_group)
        self._require_matching_id(ep_group)
        return self.wrap_member(PROVIDERS.catalog_api.update_endpoint_group(
            endpoint_group_id, ep_group))

    def delete(self, endpoint_group_id):
        ENFORCER.enforce_call(action='identity:delete_endpoint_group')
        return (PROVIDERS.catalog_api.delete_endpoint_group(endpoint_group_id),
                http.client.NO_CONTENT)


class EPFilterEndpointProjectsResource(flask_restful.Resource):
    def get(self, endpoint_id):
        """"Return a list of projects associated with the endpoint."""
        ENFORCER.enforce_call(action='identity:list_projects_for_endpoint')
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        refs = PROVIDERS.catalog_api.list_projects_for_endpoint(endpoint_id)
        projects = [PROVIDERS.resource_api.get_project(ref['project_id'])
                    for ref in refs]
        return ks_flask.ResourceBase.wrap_collection(
            projects, collection_name='projects')


class EPFilterProjectsEndpointsResource(flask_restful.Resource):
    def get(self, project_id, endpoint_id):
        ENFORCER.enforce_call(action='identity:check_endpoint_in_project')
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.check_endpoint_in_project(
            endpoint_id, project_id)
        return None, http.client.NO_CONTENT

    def put(self, project_id, endpoint_id):
        ENFORCER.enforce_call(action='identity:add_endpoint_to_project')
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.add_endpoint_to_project(endpoint_id, project_id)
        return None, http.client.NO_CONTENT

    def delete(self, project_id, endpoint_id):
        ENFORCER.enforce_call(action='identity:remove_endpoint_from_project')
        return (PROVIDERS.catalog_api.remove_endpoint_from_project(
            endpoint_id, project_id), http.client.NO_CONTENT)


class EPFilterProjectEndpointsListResource(flask_restful.Resource):
    def get(self, project_id):
        ENFORCER.enforce_call(action='identity:list_endpoints_for_project')
        PROVIDERS.resource_api.get_project(project_id)
        filtered_endpoints = PROVIDERS.catalog_api.list_endpoints_for_project(
            project_id)

        return ks_flask.ResourceBase.wrap_collection(
            [_filter_endpoint(v) for v in filtered_endpoints.values()],
            collection_name='endpoints')


class EndpointFilterProjectEndpointGroupsListResource(flask_restful.Resource):
    def get(self, project_id):
        ENFORCER.enforce_call(
            action='identity:list_endpoint_groups_for_project')
        return EndpointGroupsResource.wrap_collection(
            PROVIDERS.catalog_api.get_endpoint_groups_for_project(project_id))


class EndpointFilterEPGroupsProjects(flask_restful.Resource):
    def get(self, endpoint_group_id):
        ENFORCER.enforce_call(
            action='identity:list_projects_associated_with_endpoint_group')
        endpoint_group_refs = (PROVIDERS.catalog_api.
                               list_projects_associated_with_endpoint_group(
                                   endpoint_group_id))
        projects = []
        for endpoint_group_ref in endpoint_group_refs:
            project = PROVIDERS.resource_api.get_project(
                endpoint_group_ref['project_id'])
            if project:
                projects.append(project)

        return ks_flask.ResourceBase.wrap_collection(
            projects, collection_name='projects')


class EndpointFilterEPGroupsEndpoints(flask_restful.Resource):
    def get(self, endpoint_group_id):
        ENFORCER.enforce_call(
            action='identity:list_endpoints_associated_with_endpoint_group')
        filtered_endpoints = (PROVIDERS.catalog_api.
                              get_endpoints_filtered_by_endpoint_group(
                                  endpoint_group_id))
        return ks_flask.ResourceBase.wrap_collection(
            [_filter_endpoint(e) for e in filtered_endpoints],
            collection_name='endpoints')


class EPFilterGroupsProjectsResource(ks_flask.ResourceBase):
    collection_key = 'project_endpoint_groups'
    member_key = 'project_endpoint_group'

    @classmethod
    def _add_self_referential_link(cls, ref, collection_name=None):
        url = ('/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s'
               '/projects/%(project_id)s' % {
                   'endpoint_group_id': ref['endpoint_group_id'],
                   'project_id': ref['project_id']})
        ref.setdefault('links', {})
        ref['links']['self'] = url

    def get(self, endpoint_group_id, project_id):
        ENFORCER.enforce_call(action='identity:get_endpoint_group_in_project')
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id)
        ref = PROVIDERS.catalog_api.get_endpoint_group_in_project(
            endpoint_group_id, project_id)
        return self.wrap_member(ref)

    def put(self, endpoint_group_id, project_id):
        ENFORCER.enforce_call(action='identity:add_endpoint_group_to_project')
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id)
        PROVIDERS.catalog_api.add_endpoint_group_to_project(
            endpoint_group_id, project_id)
        return None, http.client.NO_CONTENT

    def delete(self, endpoint_group_id, project_id):
        ENFORCER.enforce_call(
            action='identity:remove_endpoint_group_from_project')
        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.catalog_api.get_endpoint_group(endpoint_group_id)
        PROVIDERS.catalog_api.remove_endpoint_group_from_project(
            endpoint_group_id, project_id)
        return None, http.client.NO_CONTENT


class EPFilterAPI(ks_flask.APIBase):
    _name = 'OS-EP-FILTER'
    _import_name = __name__
    _api_url_prefix = '/OS-EP-FILTER'
    resources = [EndpointGroupsResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=EPFilterEndpointProjectsResource,
            url='/endpoints/<string:endpoint_id>/projects',
            resource_kwargs={},
            rel='endpoint_projects',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'endpoint_id': json_home.Parameters.ENDPOINT_ID
            }),
        ks_flask.construct_resource_map(
            resource=EPFilterProjectsEndpointsResource,
            url='/projects/<string:project_id>/endpoints/<string:endpoint_id>',
            resource_kwargs={},
            rel='project_endpoint',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'endpoint_id': json_home.Parameters.ENDPOINT_ID,
                'project_id': json_home.Parameters.PROJECT_ID}),
        ks_flask.construct_resource_map(
            resource=EPFilterProjectEndpointsListResource,
            url='/projects/<string:project_id>/endpoints',
            resource_kwargs={},
            rel='project_endpoints',
            resource_relation_func=_build_resource_relation,
            path_vars={'project_id': json_home.Parameters.PROJECT_ID}),
        ks_flask.construct_resource_map(
            resource=EndpointFilterProjectEndpointGroupsListResource,
            url='/projects/<string:project_id>/endpoint_groups',
            resource_kwargs={},
            rel='project_endpoint_groups',
            resource_relation_func=_build_resource_relation,
            path_vars={'project_id': json_home.Parameters.PROJECT_ID}),
        ks_flask.construct_resource_map(
            resource=EndpointFilterEPGroupsEndpoints,
            url='/endpoint_groups/<string:endpoint_group_id>/endpoints',
            resource_kwargs={},
            rel='endpoints_in_endpoint_group',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'endpoint_group_id': _ENDPOINT_GROUP_PARAMETER_RELATION}),
        ks_flask.construct_resource_map(
            resource=EndpointFilterEPGroupsProjects,
            url='/endpoint_groups/<string:endpoint_group_id>/projects',
            resource_kwargs={},
            rel='projects_associated_with_endpoint_group',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'endpoint_group_id': _ENDPOINT_GROUP_PARAMETER_RELATION}),
        ks_flask.construct_resource_map(
            resource=EPFilterGroupsProjectsResource,
            url=('/endpoint_groups/<string:endpoint_group_id>/projects/'
                 '<string:project_id>'),
            resource_kwargs={},
            rel='endpoint_group_to_project_association',
            resource_relation_func=_build_resource_relation,
            path_vars={'project_id': json_home.Parameters.PROJECT_ID,
                       'endpoint_group_id': _ENDPOINT_GROUP_PARAMETER_RELATION
                       }),
    ]


APIs = (EPFilterAPI,)
