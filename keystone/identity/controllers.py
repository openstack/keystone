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

"""Workflow Logic the Identity service."""

from oslo_log import log

from keystone.common import controller
from keystone.common import provider_api
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.identity import schema


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class UserV3(controller.V3Controller):
    collection_name = 'users'
    member_name = 'user'

    def __init__(self):
        super(UserV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.identity_api.get_user

    def _check_user_and_group_protection(self, request, prep_info,
                                         user_id, group_id):
        ref = {}
        ref['user'] = PROVIDERS.identity_api.get_user(user_id)
        ref['group'] = PROVIDERS.identity_api.get_group(group_id)
        self.check_protection(request, prep_info, ref)

    def _check_group_protection(self, request, prep_info, group_id):
        ref = {}
        ref['group'] = PROVIDERS.identity_api.get_group(group_id)
        self.check_protection(request, prep_info, ref)

    @controller.protected()
    def create_user(self, request, user):
        validation.lazy_validate(schema.user_create, user)
        # The manager layer will generate the unique ID for users
        ref = self._normalize_dict(user)
        ref = self._normalize_domain_id(request, ref)
        ref = PROVIDERS.identity_api.create_user(
            ref, initiator=request.audit_initiator
        )
        return UserV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('domain_id', 'enabled', 'idp_id', 'name',
                                'protocol_id', 'unique_id',
                                'password_expires_at')
    def list_users(self, request, filters):
        hints = UserV3.build_driver_hints(request, filters)
        domain = self._get_domain_id_for_list_request(request)
        refs = PROVIDERS.identity_api.list_users(
            domain_scope=domain, hints=hints
        )
        return UserV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.filterprotected('domain_id', 'enabled', 'name',
                                'password_expires_at',
                                callback=_check_group_protection)
    def list_users_in_group(self, request, filters, group_id):
        hints = UserV3.build_driver_hints(request, filters)
        refs = PROVIDERS.identity_api.list_users_in_group(
            group_id, hints=hints
        )
        return UserV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.protected()
    def get_user(self, request, user_id):
        ref = PROVIDERS.identity_api.get_user(user_id)
        return UserV3.wrap_member(request.context_dict, ref)

    def _update_user(self, request, user_id, user):
        self._require_matching_id(user_id, user)
        ref = PROVIDERS.identity_api.update_user(
            user_id, user, initiator=request.audit_initiator
        )
        return UserV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_user(self, request, user_id, user):
        validation.lazy_validate(schema.user_update, user)
        return self._update_user(request, user_id, user)

    @controller.protected(callback=_check_user_and_group_protection)
    def add_user_to_group(self, request, user_id, group_id):
        PROVIDERS.identity_api.add_user_to_group(
            user_id, group_id, initiator=request.audit_initiator
        )

    @controller.protected(callback=_check_user_and_group_protection)
    def check_user_in_group(self, request, user_id, group_id):
        return PROVIDERS.identity_api.check_user_in_group(user_id, group_id)

    @controller.protected(callback=_check_user_and_group_protection)
    def remove_user_from_group(self, request, user_id, group_id):
        PROVIDERS.identity_api.remove_user_from_group(
            user_id, group_id, initiator=request.audit_initiator
        )

    @controller.protected()
    def delete_user(self, request, user_id):
        return PROVIDERS.identity_api.delete_user(
            user_id, initiator=request.audit_initiator
        )

    # NOTE(gagehugo): We do not need this to be @protected.
    # A user is already expected to know their password in order
    # to change it, and can be authenticated as such.
    def change_password(self, request, user_id, user):
        original_password = user.get('original_password')
        if original_password is None:
            raise exception.ValidationError(target='user',
                                            attribute='original_password')

        password = user.get('password')
        if password is None:
            raise exception.ValidationError(target='user',
                                            attribute='password')
        try:
            PROVIDERS.identity_api.change_password(
                request, user_id, original_password,
                password, initiator=request.audit_initiator)
        except AssertionError as e:
            raise exception.Unauthorized(_(
                'Error when changing user password: %s') % e)


class GroupV3(controller.V3Controller):
    collection_name = 'groups'
    member_name = 'group'

    def __init__(self):
        super(GroupV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.identity_api.get_group

    def _check_user_protection(self, request, prep_info, user_id):
        ref = {}
        ref['user'] = PROVIDERS.identity_api.get_user(user_id)
        self.check_protection(request, prep_info, ref)

    @controller.protected()
    def create_group(self, request, group):
        validation.lazy_validate(schema.group_create, group)
        # The manager layer will generate the unique ID for groups
        ref = self._normalize_dict(group)
        ref = self._normalize_domain_id(request, ref)
        ref = PROVIDERS.identity_api.create_group(
            ref, initiator=request.audit_initiator
        )
        return GroupV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('domain_id', 'name')
    def list_groups(self, request, filters):
        hints = GroupV3.build_driver_hints(request, filters)
        domain = self._get_domain_id_for_list_request(request)
        refs = PROVIDERS.identity_api.list_groups(
            domain_scope=domain, hints=hints
        )
        return GroupV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.filterprotected('name', callback=_check_user_protection)
    def list_groups_for_user(self, request, filters, user_id):
        hints = GroupV3.build_driver_hints(request, filters)
        refs = PROVIDERS.identity_api.list_groups_for_user(
            user_id, hints=hints
        )
        return GroupV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.protected()
    def get_group(self, request, group_id):
        ref = PROVIDERS.identity_api.get_group(group_id)
        return GroupV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_group(self, request, group_id, group):
        validation.lazy_validate(schema.group_update, group)
        self._require_matching_id(group_id, group)
        ref = PROVIDERS.identity_api.update_group(
            group_id, group, initiator=request.audit_initiator
        )
        return GroupV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_group(self, request, group_id):
        PROVIDERS.identity_api.delete_group(
            group_id, initiator=request.audit_initiator
        )
