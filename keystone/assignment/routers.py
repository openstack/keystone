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

import functools

from keystone.assignment import controllers
from keystone.common import json_home
from keystone.common import router
from keystone.common import wsgi
from keystone import config


build_os_inherit_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-INHERIT', extension_version='1.0')


class Public(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        tenant_controller = controllers.Tenant()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_projects_for_token',
                       conditions=dict(method=['GET']))


class Admin(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        # Tenant Operations
        tenant_controller = controllers.Tenant()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_all_projects',
                       conditions=dict(method=['GET']))
        mapper.connect('/tenants/{tenant_id}',
                       controller=tenant_controller,
                       action='get_project',
                       conditions=dict(method=['GET']))

        # Role Operations
        roles_controller = controllers.Role()
        mapper.connect('/tenants/{tenant_id}/users/{user_id}/roles',
                       controller=roles_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))
        mapper.connect('/users/{user_id}/roles',
                       controller=roles_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))


class Routers(wsgi.RoutersBase):

    def append_v3_routers(self, mapper, routers):
        routers.append(
            router.Router(controllers.DomainV3(),
                          'domains', 'domain',
                          resource_descriptions=self.v3_resources))

        project_controller = controllers.ProjectV3()
        routers.append(
            router.Router(project_controller,
                          'projects', 'project',
                          resource_descriptions=self.v3_resources))

        self._add_resource(
            mapper, project_controller,
            path='/users/{user_id}/projects',
            get_action='list_user_projects',
            rel=json_home.build_v3_resource_relation('user_projects'),
            path_vars={
                'user_id': json_home.Parameters.USER_ID,
            })

        role_controller = controllers.RoleV3()
        routers.append(
            router.Router(role_controller, 'roles', 'role',
                          resource_descriptions=self.v3_resources))

        self._add_resource(
            mapper, role_controller,
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
            mapper, role_controller,
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
            mapper, role_controller,
            path='/projects/{project_id}/users/{user_id}/roles',
            get_action='list_grants',
            rel=json_home.build_v3_resource_relation('project_user_roles'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, role_controller,
            path='/projects/{project_id}/groups/{group_id}/roles',
            get_action='list_grants',
            rel=json_home.build_v3_resource_relation('project_group_roles'),
            path_vars={
                'group_id': json_home.Parameters.GROUP_ID,
                'project_id': json_home.Parameters.PROJECT_ID,
            })
        self._add_resource(
            mapper, role_controller,
            path='/domains/{domain_id}/users/{user_id}/roles/{role_id}',
            get_head_action='check_grant',
            put_action='create_grant',
            delete_action='revoke_grant',
            rel=json_home.build_v3_resource_relation('domain_user_role'),
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'role_id': json_home.Parameters.ROLE_ID,
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, role_controller,
            path='/domains/{domain_id}/groups/{group_id}/roles/{role_id}',
            get_head_action='check_grant',
            put_action='create_grant',
            delete_action='revoke_grant',
            rel=json_home.build_v3_resource_relation('domain_group_role'),
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group_id': json_home.Parameters.GROUP_ID,
                'role_id': json_home.Parameters.ROLE_ID,
            })
        self._add_resource(
            mapper, role_controller,
            path='/domains/{domain_id}/users/{user_id}/roles',
            get_action='list_grants',
            rel=json_home.build_v3_resource_relation('domain_user_roles'),
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, role_controller,
            path='/domains/{domain_id}/groups/{group_id}/roles',
            get_action='list_grants',
            rel=json_home.build_v3_resource_relation('domain_group_roles'),
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group_id': json_home.Parameters.GROUP_ID,
            })

        routers.append(
            router.Router(controllers.RoleAssignmentV3(),
                          'role_assignments', 'role_assignment',
                          resource_descriptions=self.v3_resources,
                          is_entity_implemented=False))

        if config.CONF.os_inherit.enabled:
            self._add_resource(
                mapper, role_controller,
                path='/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/'
                '{role_id}/inherited_to_projects',
                get_head_action='check_grant',
                put_action='create_grant',
                delete_action='revoke_grant',
                rel=build_os_inherit_relation(
                    resource_name='domain_user_role_inherited_to_projects'),
                path_vars={
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                    'user_id': json_home.Parameters.USER_ID,
                })
            self._add_resource(
                mapper, role_controller,
                path='/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/'
                '{role_id}/inherited_to_projects',
                get_head_action='check_grant',
                put_action='create_grant',
                delete_action='revoke_grant',
                rel=build_os_inherit_relation(
                    resource_name='domain_group_role_inherited_to_projects'),
                path_vars={
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                })
            self._add_resource(
                mapper, role_controller,
                path='/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/'
                'inherited_to_projects',
                get_action='list_grants',
                rel=build_os_inherit_relation(
                    resource_name='domain_group_roles_inherited_to_projects'),
                path_vars={
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                })
            self._add_resource(
                mapper, role_controller,
                path='/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/'
                'inherited_to_projects',
                get_action='list_grants',
                rel=build_os_inherit_relation(
                    resource_name='domain_user_roles_inherited_to_projects'),
                path_vars={
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'user_id': json_home.Parameters.USER_ID,
                })
            self._add_resource(
                mapper, role_controller,
                path='/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/'
                '{role_id}/inherited_to_projects',
                get_head_action='check_grant',
                put_action='create_grant',
                delete_action='revoke_grant',
                rel=build_os_inherit_relation(
                    resource_name='project_user_role_inherited_to_projects'),
                path_vars={
                    'project_id': json_home.Parameters.PROJECT_ID,
                    'user_id': json_home.Parameters.USER_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                })
            self._add_resource(
                mapper, role_controller,
                path='/OS-INHERIT/projects/{project_id}/groups/{group_id}/'
                'roles/{role_id}/inherited_to_projects',
                get_head_action='check_grant',
                put_action='create_grant',
                delete_action='revoke_grant',
                rel=build_os_inherit_relation(
                    resource_name='project_group_role_inherited_to_projects'),
                path_vars={
                    'project_id': json_home.Parameters.PROJECT_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                })
