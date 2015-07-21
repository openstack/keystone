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

import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib.endpoint_filter import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-EP-FILTER', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-EP-FILTER', extension_version='1.0')

ENDPOINT_GROUP_PARAMETER_RELATION = build_parameter_relation(
    parameter_name='endpoint_group_id')


class EndpointFilterExtension(wsgi.V3ExtensionRouter):
    """API Endpoints for the Endpoint Filter extension.

    The API looks like::

        PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}
        GET /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}
        HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}
        DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}
        GET /OS-EP-FILTER/endpoints/{endpoint_id}/projects
        GET /OS-EP-FILTER/projects/{project_id}/endpoints
        GET /OS-EP-FILTER/projects/{project_id}/endpoint_groups

        GET /OS-EP-FILTER/endpoint_groups
        POST /OS-EP-FILTER/endpoint_groups
        GET /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}
        HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}
        PATCH /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}
        DELETE /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

        GET /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects
        GET /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/endpoints

        PUT /OS-EP-FILTER/endpoint_groups/{endpoint_group}/projects/
            {project_id}
        GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}/projects/
            {project_id}
        HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group}/projects/
            {project_id}
        DELETE /OS-EP-FILTER/endpoint_groups/{endpoint_group}/projects/
            {project_id}

    """
    PATH_PREFIX = '/OS-EP-FILTER'
    PATH_PROJECT_ENDPOINT = '/projects/{project_id}/endpoints/{endpoint_id}'
    PATH_ENDPOINT_GROUPS = '/endpoint_groups/{endpoint_group_id}'
    PATH_ENDPOINT_GROUP_PROJECTS = PATH_ENDPOINT_GROUPS + (
        '/projects/{project_id}')

    def add_routes(self, mapper):
        endpoint_filter_controller = controllers.EndpointFilterV3Controller()
        endpoint_group_controller = controllers.EndpointGroupV3Controller()
        project_endpoint_group_controller = (
            controllers.ProjectEndpointGroupV3Controller())

        self._add_resource(
            mapper, endpoint_filter_controller,
            path=self.PATH_PREFIX + '/endpoints/{endpoint_id}/projects',
            get_action='list_projects_for_endpoint',
            rel=build_resource_relation(resource_name='endpoint_projects'),
            path_vars={
                'endpoint_id': json_home.Parameters.ENDPOINT_ID,
            })
        self._add_resource(
            mapper, endpoint_filter_controller,
            path=self.PATH_PREFIX + self.PATH_PROJECT_ENDPOINT,
            get_head_action='check_endpoint_in_project',
            put_action='add_endpoint_to_project',
            delete_action='remove_endpoint_from_project',
            rel=build_resource_relation(resource_name='project_endpoint'),
            path_vars={
                'endpoint_id': json_home.Parameters.ENDPOINT_ID,
                'project_id': json_home.Parameters.PROJECT_ID,
            })
        self._add_resource(
            mapper, endpoint_filter_controller,
            path=self.PATH_PREFIX + '/projects/{project_id}/endpoints',
            get_action='list_endpoints_for_project',
            rel=build_resource_relation(resource_name='project_endpoints'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
            })
        self._add_resource(
            mapper, endpoint_group_controller,
            path=self.PATH_PREFIX + '/projects/{project_id}/endpoint_groups',
            get_action='list_endpoint_groups_for_project',
            rel=build_resource_relation(
                resource_name='project_endpoint_groups'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
            })
        self._add_resource(
            mapper, endpoint_group_controller,
            path=self.PATH_PREFIX + '/endpoint_groups',
            get_action='list_endpoint_groups',
            post_action='create_endpoint_group',
            rel=build_resource_relation(resource_name='endpoint_groups'))
        self._add_resource(
            mapper, endpoint_group_controller,
            path=self.PATH_PREFIX + self.PATH_ENDPOINT_GROUPS,
            get_head_action='get_endpoint_group',
            patch_action='update_endpoint_group',
            delete_action='delete_endpoint_group',
            rel=build_resource_relation(resource_name='endpoint_group'),
            path_vars={
                'endpoint_group_id': ENDPOINT_GROUP_PARAMETER_RELATION
            })
        self._add_resource(
            mapper, project_endpoint_group_controller,
            path=self.PATH_PREFIX + self.PATH_ENDPOINT_GROUP_PROJECTS,
            get_head_action='get_endpoint_group_in_project',
            put_action='add_endpoint_group_to_project',
            delete_action='remove_endpoint_group_from_project',
            rel=build_resource_relation(
                resource_name='endpoint_group_to_project_association'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'endpoint_group_id': ENDPOINT_GROUP_PARAMETER_RELATION
            })
        self._add_resource(
            mapper, endpoint_group_controller,
            path=self.PATH_PREFIX + self.PATH_ENDPOINT_GROUPS + (
                '/projects'),
            get_action='list_projects_associated_with_endpoint_group',
            rel=build_resource_relation(
                resource_name='projects_associated_with_endpoint_group'),
            path_vars={
                'endpoint_group_id': ENDPOINT_GROUP_PARAMETER_RELATION
            })
        self._add_resource(
            mapper, endpoint_group_controller,
            path=self.PATH_PREFIX + self.PATH_ENDPOINT_GROUPS + (
                '/endpoints'),
            get_action='list_endpoints_associated_with_endpoint_group',
            rel=build_resource_relation(
                resource_name='endpoints_in_endpoint_group'),
            path_vars={
                'endpoint_group_id': ENDPOINT_GROUP_PARAMETER_RELATION
            })
