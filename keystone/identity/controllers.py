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
from keystone.common import dependency
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.i18n import _, _LW
from keystone.identity import schema


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api', 'resource_api')
class User(controller.V2Controller):

    @controller.v2_deprecated
    def get_user(self, request, user_id):
        self.assert_admin(request)
        ref = self.identity_api.get_user(user_id)
        return {'user': self.v3_to_v2_user(ref)}

    @controller.v2_deprecated
    def get_users(self, request):
        # NOTE(termie): i can't imagine that this really wants all the data
        #               about every single user in the system...
        if 'name' in request.params:
            return self.get_user_by_name(request, request.params['name'])

        self.assert_admin(request)
        user_list = self.identity_api.list_users(
            CONF.identity.default_domain_id)
        return {'users': self.v3_to_v2_user(user_list)}

    @controller.v2_deprecated
    def get_user_by_name(self, request, user_name):
        self.assert_admin(request)
        ref = self.identity_api.get_user_by_name(
            user_name, CONF.identity.default_domain_id)
        return {'user': self.v3_to_v2_user(ref)}

    # CRUD extension
    @controller.v2_deprecated
    def create_user(self, request, user):
        validation.lazy_validate(schema.user_create_v2, user)
        user = self._normalize_OSKSADM_password_on_request(user)
        user = self.normalize_username_in_request(user)
        user = self._normalize_dict(user)
        self.assert_admin(request)

        default_project_id = user.pop('tenantId', None)
        if default_project_id is not None:
            # Check to see if the project is valid before moving on.
            self.resource_api.get_project(default_project_id)
            user['default_project_id'] = default_project_id

        self.resource_api.ensure_default_domain_exists()

        # The manager layer will generate the unique ID for users
        user_ref = self._normalize_domain_id(request, user.copy())
        new_user_ref = self.v3_to_v2_user(
            self.identity_api.create_user(
                user_ref, initiator=request.audit_initiator
            )
        )

        if default_project_id is not None:
            self.assignment_api.add_user_to_project(default_project_id,
                                                    new_user_ref['id'])
        return {'user': new_user_ref}

    @controller.v2_deprecated
    def update_user(self, request, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        validation.lazy_validate(schema.user_update_v2, user)
        user = self.normalize_username_in_request(user)
        self.assert_admin(request)

        default_project_id = user.pop('tenantId', None)
        if default_project_id is not None:
            user['default_project_id'] = default_project_id

        old_user_ref = self.v3_to_v2_user(
            self.identity_api.get_user(user_id))

        # Check whether a tenant is being added or changed for the user.
        # Catch the case where the tenant is being changed for a user and also
        # where a user previously had no tenant but a tenant is now being
        # added for the user.
        if (('tenantId' in old_user_ref and
                old_user_ref['tenantId'] != default_project_id and
                default_project_id is not None) or
            ('tenantId' not in old_user_ref and
                default_project_id is not None)):
            # Make sure the new project actually exists before we perform the
            # user update.
            self.resource_api.get_project(default_project_id)

        user_ref = self.identity_api.update_user(
            user_id, user, initiator=request.audit_initiator
        )
        user_ref = self.v3_to_v2_user(user_ref)

        # If 'tenantId' is in either ref, we might need to add or remove the
        # user from a project.
        if 'tenantId' in user_ref or 'tenantId' in old_user_ref:
            if user_ref['tenantId'] != old_user_ref.get('tenantId'):
                if old_user_ref.get('tenantId'):
                    try:
                        member_role_id = CONF.member_role_id
                        self.assignment_api.remove_role_from_user_and_project(
                            user_id, old_user_ref['tenantId'], member_role_id)
                    except exception.NotFound:
                        # NOTE(morganfainberg): This is not a critical error it
                        # just means that the user cannot be removed from the
                        # old tenant.  This could occur if roles aren't found
                        # or if the project is invalid or if there are no roles
                        # for the user on that project.
                        msg = _LW('Unable to remove user %(user)s from '
                                  '%(tenant)s.')
                        LOG.warning(msg, {'user': user_id,
                                          'tenant': old_user_ref['tenantId']})

                if user_ref['tenantId']:
                    try:
                        self.assignment_api.add_user_to_project(
                            user_ref['tenantId'], user_id)
                    except exception.Conflict:  # nosec
                        # We are already a member of that tenant
                        pass
                    except exception.NotFound:
                        # NOTE(morganfainberg): Log this and move on. This is
                        # not the end of the world if we can't add the user to
                        # the appropriate tenant. Most of the time this means
                        # that the project is invalid or roles are some how
                        # incorrect.  This shouldn't prevent the return of the
                        # new ref.
                        msg = _LW('Unable to add user %(user)s to %(tenant)s.')
                        LOG.warning(msg, {'user': user_id,
                                          'tenant': user_ref['tenantId']})

        return {'user': user_ref}

    @controller.v2_deprecated
    def delete_user(self, request, user_id):
        self.assert_admin(request)
        self.identity_api.delete_user(
            user_id, initiator=request.audit_initiator
        )

    @controller.v2_deprecated
    def set_user_enabled(self, request, user_id, user):
        validation.lazy_validate(schema.enable_user_v2, user)
        return self.update_user(request, user_id, user)

    @controller.v2_deprecated
    def set_user_password(self, request, user_id, user):
        user = self._normalize_OSKSADM_password_on_request(user)
        return self.update_user(request, user_id, user)

    @staticmethod
    def _normalize_OSKSADM_password_on_request(ref):
        """Set the password from the OS-KSADM Admin Extension.

        The OS-KSADM Admin Extension documentation says that
        `OS-KSADM:password` can be used in place of `password`.

        """
        if 'OS-KSADM:password' in ref:
            ref['password'] = ref.pop('OS-KSADM:password')
        return ref


@dependency.requires('identity_api')
class UserV3(controller.V3Controller):
    collection_name = 'users'
    member_name = 'user'

    def __init__(self):
        super(UserV3, self).__init__()
        self.get_member_from_driver = self.identity_api.get_user

    def _check_user_and_group_protection(self, request, prep_info,
                                         user_id, group_id):
        ref = {}
        ref['user'] = self.identity_api.get_user(user_id)
        ref['group'] = self.identity_api.get_group(group_id)
        self.check_protection(request, prep_info, ref)

    def _check_group_protection(self, request, prep_info, group_id):
        ref = {}
        ref['group'] = self.identity_api.get_group(group_id)
        self.check_protection(request, prep_info, ref)

    @controller.protected()
    def create_user(self, request, user):
        validation.lazy_validate(schema.user_create, user)
        # The manager layer will generate the unique ID for users
        ref = self._normalize_dict(user)
        ref = self._normalize_domain_id(request, ref)
        ref = self.identity_api.create_user(
            ref, initiator=request.audit_initiator
        )
        return UserV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('domain_id', 'enabled', 'idp_id', 'name',
                                'protocol_id', 'unique_id',
                                'password_expires_at')
    def list_users(self, request, filters):
        hints = UserV3.build_driver_hints(request, filters)
        domain = self._get_domain_id_for_list_request(request)
        refs = self.identity_api.list_users(domain_scope=domain, hints=hints)
        return UserV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.filterprotected('domain_id', 'enabled', 'name',
                                'password_expires_at',
                                callback=_check_group_protection)
    def list_users_in_group(self, request, filters, group_id):
        hints = UserV3.build_driver_hints(request, filters)
        refs = self.identity_api.list_users_in_group(group_id, hints=hints)
        return UserV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.protected()
    def get_user(self, request, user_id):
        ref = self.identity_api.get_user(user_id)
        return UserV3.wrap_member(request.context_dict, ref)

    def _update_user(self, request, user_id, user):
        self._require_matching_id(user_id, user)
        ref = self.identity_api.update_user(
            user_id, user, initiator=request.audit_initiator
        )
        return UserV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_user(self, request, user_id, user):
        validation.lazy_validate(schema.user_update, user)
        return self._update_user(request, user_id, user)

    @controller.protected(callback=_check_user_and_group_protection)
    def add_user_to_group(self, request, user_id, group_id):
        self.identity_api.add_user_to_group(
            user_id, group_id, initiator=request.audit_initiator
        )

    @controller.protected(callback=_check_user_and_group_protection)
    def check_user_in_group(self, request, user_id, group_id):
        return self.identity_api.check_user_in_group(user_id, group_id)

    @controller.protected(callback=_check_user_and_group_protection)
    def remove_user_from_group(self, request, user_id, group_id):
        self.identity_api.remove_user_from_group(
            user_id, group_id, initiator=request.audit_initiator
        )

    @controller.protected()
    def delete_user(self, request, user_id):
        return self.identity_api.delete_user(
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
            self.identity_api.change_password(
                request, user_id, original_password,
                password, initiator=request.audit_initiator)
        except AssertionError as e:
            raise exception.Unauthorized(_(
                'Error when changing user password: %s') % e)


@dependency.requires('identity_api')
class GroupV3(controller.V3Controller):
    collection_name = 'groups'
    member_name = 'group'

    def __init__(self):
        super(GroupV3, self).__init__()
        self.get_member_from_driver = self.identity_api.get_group

    def _check_user_protection(self, request, prep_info, user_id):
        ref = {}
        ref['user'] = self.identity_api.get_user(user_id)
        self.check_protection(request, prep_info, ref)

    @controller.protected()
    def create_group(self, request, group):
        validation.lazy_validate(schema.group_create, group)
        # The manager layer will generate the unique ID for groups
        ref = self._normalize_dict(group)
        ref = self._normalize_domain_id(request, ref)
        ref = self.identity_api.create_group(
            ref, initiator=request.audit_initiator
        )
        return GroupV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('domain_id', 'name')
    def list_groups(self, request, filters):
        hints = GroupV3.build_driver_hints(request, filters)
        domain = self._get_domain_id_for_list_request(request)
        refs = self.identity_api.list_groups(domain_scope=domain, hints=hints)
        return GroupV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.filterprotected('name', callback=_check_user_protection)
    def list_groups_for_user(self, request, filters, user_id):
        hints = GroupV3.build_driver_hints(request, filters)
        refs = self.identity_api.list_groups_for_user(user_id, hints=hints)
        return GroupV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.protected()
    def get_group(self, request, group_id):
        ref = self.identity_api.get_group(group_id)
        return GroupV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_group(self, request, group_id, group):
        validation.lazy_validate(schema.group_update, group)
        self._require_matching_id(group_id, group)
        ref = self.identity_api.update_group(
            group_id, group, initiator=request.audit_initiator
        )
        return GroupV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_group(self, request, group_id):
        self.identity_api.delete_group(
            group_id, initiator=request.audit_initiator
        )
