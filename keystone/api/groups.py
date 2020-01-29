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

# This file handles all flask-restful resources for /v3/groups

import flask
import flask_restful
import functools
import http.client

from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.identity import schema
from keystone import notifications
from keystone.server import flask as ks_flask


CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


def _build_group_target_enforcement():
    target = {}
    try:
        target['group'] = PROVIDERS.identity_api.get_group(
            flask.request.view_args.get('group_id')
        )
    except exception.NotFound:  # nosec
        # Defer existance in the event the group doesn't exist, we'll
        # check this later anyway.
        pass

    return target


class GroupsResource(ks_flask.ResourceBase):
    collection_key = 'groups'
    member_key = 'group'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='identity_api', method='get_group')

    def get(self, group_id=None):
        if group_id is not None:
            return self._get_group(group_id)
        return self._list_groups()

    def _get_group(self, group_id):
        """Get a group reference.

        GET/HEAD /groups/{group_id}
        """
        ENFORCER.enforce_call(
            action='identity:get_group',
            build_target=_build_group_target_enforcement
        )
        return self.wrap_member(PROVIDERS.identity_api.get_group(group_id))

    def _list_groups(self):
        """List groups.

        GET/HEAD /groups
        """
        filters = ['domain_id', 'name']
        target = None
        if self.oslo_context.domain_id:
            target = {'group': {'domain_id': self.oslo_context.domain_id}}
        ENFORCER.enforce_call(action='identity:list_groups', filters=filters,
                              target_attr=target)
        hints = self.build_driver_hints(filters)
        domain = self._get_domain_id_for_list_request()
        refs = PROVIDERS.identity_api.list_groups(domain_scope=domain,
                                                  hints=hints)
        if self.oslo_context.domain_id:
            filtered_refs = []
            for ref in refs:
                if ref['domain_id'] == target['group']['domain_id']:
                    filtered_refs.append(ref)
            refs = filtered_refs
        return self.wrap_collection(refs, hints=hints)

    def post(self):
        """Create group.

        POST /groups
        """
        group = self.request_body_json.get('group', {})
        target = {'group': group}
        ENFORCER.enforce_call(
            action='identity:create_group', target_attr=target
        )
        validation.lazy_validate(schema.group_create, group)
        group = self._normalize_dict(group)
        group = self._normalize_domain_id(group)
        ref = PROVIDERS.identity_api.create_group(
            group, initiator=self.audit_initiator)
        return self.wrap_member(ref), http.client.CREATED

    def patch(self, group_id):
        """Update group.

        PATCH /groups/{group_id}
        """
        ENFORCER.enforce_call(
            action='identity:update_group',
            build_target=_build_group_target_enforcement
        )
        group = self.request_body_json.get('group', {})
        validation.lazy_validate(schema.group_update, group)
        self._require_matching_id(group)
        ref = PROVIDERS.identity_api.update_group(
            group_id, group, initiator=self.audit_initiator)
        return self.wrap_member(ref)

    def delete(self, group_id):
        """Delete group.

        DELETE /groups/{group_id}
        """
        ENFORCER.enforce_call(action='identity:delete_group')
        PROVIDERS.identity_api.delete_group(
            group_id, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class GroupUsersResource(ks_flask.ResourceBase):
    def get(self, group_id):
        """Get list of users in group.

        GET/HEAD /groups/{group_id}/users
        """
        filters = ['domain_id', 'enabled', 'name', 'password_expires_at']
        target = None
        try:
            target = {'group': PROVIDERS.identity_api.get_group(group_id)}
        except exception.GroupNotFound:
            # NOTE(morgan): If we have an issue populating the group
            # data, leage target empty. This is the safest route and does not
            # leak data before enforcement happens.
            pass
        ENFORCER.enforce_call(action='identity:list_users_in_group',
                              target_attr=target, filters=filters)
        hints = ks_flask.ResourceBase.build_driver_hints(filters)
        refs = PROVIDERS.identity_api.list_users_in_group(
            group_id, hints=hints)
        if (self.oslo_context.domain_id):
            filtered_refs = []
            for ref in refs:
                if ref['domain_id'] == self.oslo_context.domain_id:
                    filtered_refs.append(ref)
            refs = filtered_refs
        return ks_flask.ResourceBase.wrap_collection(
            refs, hints=hints, collection_name='users')


class UserGroupCRUDResource(flask_restful.Resource):
    @staticmethod
    def _build_enforcement_target_attr(user_id, group_id):
        target = {}
        try:
            target['group'] = PROVIDERS.identity_api.get_group(group_id)
        except exception.GroupNotFound:
            # Don't populate group data if group is not found.
            pass

        try:
            target['user'] = PROVIDERS.identity_api.get_user(user_id)
        except exception.UserNotFound:
            # Don't populate user data if user is not found
            pass

        return target

    def get(self, group_id, user_id):
        """Check if a user is in a group.

        GET/HEAD /groups/{group_id}/users/{user_id}
        """
        ENFORCER.enforce_call(
            action='identity:check_user_in_group',
            build_target=functools.partial(self._build_enforcement_target_attr,
                                           user_id, group_id))
        PROVIDERS.identity_api.check_user_in_group(user_id, group_id)
        return None, http.client.NO_CONTENT

    def put(self, group_id, user_id):
        """Add user to group.

        PUT /groups/{group_id}/users/{user_id}
        """
        ENFORCER.enforce_call(
            action='identity:add_user_to_group',
            build_target=functools.partial(self._build_enforcement_target_attr,
                                           user_id, group_id))
        PROVIDERS.identity_api.add_user_to_group(
            user_id, group_id, initiator=notifications.build_audit_initiator())
        return None, http.client.NO_CONTENT

    def delete(self, group_id, user_id):
        """Remove user from group.

        DELETE /groups/{group_id}/users/{user_id}
        """
        ENFORCER.enforce_call(
            action='identity:remove_user_from_group',
            build_target=functools.partial(self._build_enforcement_target_attr,
                                           user_id, group_id))
        PROVIDERS.identity_api.remove_user_from_group(
            user_id, group_id, initiator=notifications.build_audit_initiator())
        return None, http.client.NO_CONTENT


class GroupAPI(ks_flask.APIBase):
    _name = 'groups'
    _import_name = __name__
    resources = [GroupsResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=GroupUsersResource,
            url='/groups/<string:group_id>/users',
            resource_kwargs={},
            rel='group_users',
            path_vars={'group_id': json_home.Parameters.GROUP_ID}),
        ks_flask.construct_resource_map(
            resource=UserGroupCRUDResource,
            url='/groups/<string:group_id>/users/<string:user_id>',
            resource_kwargs={},
            rel='group_user',
            path_vars={
                'group_id': json_home.Parameters.GROUP_ID,
                'user_id': json_home.Parameters.USER_ID})
    ]


APIs = (GroupAPI,)
