# Copyright 2013 Metacloud, Inc.
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

"""WSGI Routers for the Assignment service."""

from keystone.assignment import controllers
from keystone.common import json_home
from keystone.common import wsgi


class Routers(wsgi.RoutersBase):

    _path_prefixes = ('projects',)

    def append_v3_routers(self, mapper, routers):

        grant_controller = controllers.GrantAssignmentV3()
        self._add_resource(
            mapper, grant_controller,
            path='/projects/{project_id}/users/{user_id}/roles/{role_id}',
            get_head_action='check_grant',
            put_action='create_grant',
            delete_action='revoke_grant',
            rel=json_home.build_v3_resource_relation('project_user_role'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'role_id': json_home.Parameters.ROLE_ID,
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, grant_controller,
            path='/projects/{project_id}/groups/{group_id}/roles/{role_id}',
            get_head_action='check_grant',
            put_action='create_grant',
            delete_action='revoke_grant',
            rel=json_home.build_v3_resource_relation('project_group_role'),
            path_vars={
                'group_id': json_home.Parameters.GROUP_ID,
                'project_id': json_home.Parameters.PROJECT_ID,
                'role_id': json_home.Parameters.ROLE_ID,
            })
        self._add_resource(
            mapper, grant_controller,
            path='/projects/{project_id}/users/{user_id}/roles',
            get_head_action='list_grants',
            rel=json_home.build_v3_resource_relation('project_user_roles'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, grant_controller,
            path='/projects/{project_id}/groups/{group_id}/roles',
            get_head_action='list_grants',
            rel=json_home.build_v3_resource_relation('project_group_roles'),
            path_vars={
                'group_id': json_home.Parameters.GROUP_ID,
                'project_id': json_home.Parameters.PROJECT_ID,
            })
