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

# This file handles all flask-restful resources for /v3/system

import flask
import flask_restful
import functools
import http.client

from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone import exception
from keystone.server import flask as ks_flask


ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


def _build_enforcement_target(allow_non_existing=False):
    target = {}
    if flask.request.view_args:
        if flask.request.view_args.get('role_id'):
            target['role'] = PROVIDERS.role_api.get_role(
                flask.request.view_args['role_id'])
        if flask.request.view_args.get('user_id'):
            try:
                target['user'] = PROVIDERS.identity_api.get_user(
                    flask.request.view_args['user_id'])
            except exception.UserNotFound:
                if not allow_non_existing:
                    raise
        else:
            try:
                target['group'] = PROVIDERS.identity_api.get_group(
                    flask.request.view_args.get('group_id'))
            except exception.GroupNotFound:
                if not allow_non_existing:
                    raise
    return target


class SystemUsersListResource(flask_restful.Resource):
    def get(self, user_id):
        """List all system grants for a specific user.

        GET/HEAD /system/users/{user_id}/roles
        """
        ENFORCER.enforce_call(action='identity:list_system_grants_for_user',
                              build_target=_build_enforcement_target)
        refs = PROVIDERS.assignment_api.list_system_grants_for_user(user_id)
        return ks_flask.ResourceBase.wrap_collection(
            refs, collection_name='roles')


class SystemUsersResource(flask_restful.Resource):
    def get(self, user_id, role_id):
        """Check if a user has a specific role on the system.

        GET/HEAD /system/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(action='identity:check_system_grant_for_user',
                              build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.check_system_grant_for_user(user_id, role_id)
        return None, http.client.NO_CONTENT

    def put(self, user_id, role_id):
        """Grant a role to a user on the system.

        PUT /system/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(action='identity:create_system_grant_for_user',
                              build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.create_system_grant_for_user(user_id, role_id)
        return None, http.client.NO_CONTENT

    def delete(self, user_id, role_id):
        """Revoke a role from user on the system.

        DELETE /system/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:revoke_system_grant_for_user',
            build_target=functools.partial(
                _build_enforcement_target,
                allow_non_existing=True))
        PROVIDERS.assignment_api.delete_system_grant_for_user(user_id, role_id)
        return None, http.client.NO_CONTENT


class SystemGroupsRolesListResource(flask_restful.Resource):
    def get(self, group_id):
        """List all system grants for a specific group.

        GET/HEAD /system/groups/{group_id}/roles
        """
        ENFORCER.enforce_call(action='identity:list_system_grants_for_group',
                              build_target=_build_enforcement_target)
        refs = PROVIDERS.assignment_api.list_system_grants_for_group(group_id)
        return ks_flask.ResourceBase.wrap_collection(
            refs, collection_name='roles')


class SystemGroupsRolestResource(flask_restful.Resource):
    def get(self, group_id, role_id):
        """Check if a group has a specific role on the system.

        GET/HEAD /system/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(action='identity:check_system_grant_for_group',
                              build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.check_system_grant_for_group(
            group_id, role_id)
        return None, http.client.NO_CONTENT

    def put(self, group_id, role_id):
        """Grant a role to a group on the system.

        PUT /system/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(action='identity:create_system_grant_for_group',
                              build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, role_id)
        return None, http.client.NO_CONTENT

    def delete(self, group_id, role_id):
        """Revoke a role from the group on the system.

        DELETE /system/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:revoke_system_grant_for_group',
            build_target=functools.partial(
                _build_enforcement_target,
                allow_non_existing=True))
        PROVIDERS.assignment_api.delete_system_grant_for_group(
            group_id, role_id)
        return None, http.client.NO_CONTENT


class SystemAPI(ks_flask.APIBase):
    _name = 'system'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=SystemUsersListResource,
            url='/system/users/<string:user_id>/roles',
            resource_kwargs={},
            rel='system_user_roles',
            path_vars={'user_id': json_home.Parameters.USER_ID}),
        ks_flask.construct_resource_map(
            resource=SystemUsersResource,
            url='/system/users/<string:user_id>/roles/<string:role_id>',
            resource_kwargs={},
            rel='system_user_role',
            path_vars={
                'role_id': json_home.Parameters.ROLE_ID,
                'user_id': json_home.Parameters.USER_ID}),
        ks_flask.construct_resource_map(
            resource=SystemGroupsRolesListResource,
            url='/system/groups/<string:group_id>/roles',
            resource_kwargs={},
            rel='system_group_roles',
            path_vars={'group_id': json_home.Parameters.GROUP_ID}),
        ks_flask.construct_resource_map(
            resource=SystemGroupsRolestResource,
            url='/system/groups/<string:group_id>/roles/<string:role_id>',
            resource_kwargs={},
            rel='system_group_role',
            path_vars={
                'role_id': json_home.Parameters.ROLE_ID,
                'group_id': json_home.Parameters.GROUP_ID})
    ]


APIs = (SystemAPI,)
