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

"""Workflow Logic the Assignment service."""

import functools

from oslo_log import log

from keystone.common import controller
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class GrantAssignmentV3(controller.V3Controller):
    """The V3 Grant Assignment APIs."""

    collection_name = 'roles'
    member_name = 'role'

    def __init__(self):
        super(GrantAssignmentV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.role_api.get_role

    def _require_domain_xor_project(self, domain_id, project_id):
        if domain_id and project_id:
            msg = _('Specify a domain or project, not both')
            raise exception.ValidationError(msg)
        if not domain_id and not project_id:
            msg = _('Specify one of domain or project')
            raise exception.ValidationError(msg)

    def _require_user_xor_group(self, user_id, group_id):
        if user_id and group_id:
            msg = _('Specify a user or group, not both')
            raise exception.ValidationError(msg)
        if not user_id and not group_id:
            msg = _('Specify one of user or group')
            raise exception.ValidationError(msg)

    def _check_if_inherited(self, context):
        return (context['path'].startswith('/OS-INHERIT') and
                context['path'].endswith('/inherited_to_projects'))

    def _check_grant_protection(self, request, protection, role_id=None,
                                user_id=None, group_id=None,
                                domain_id=None, project_id=None,
                                allow_non_existing=False):
        """Check protection for role grant APIs.

        The policy rule might want to inspect attributes of any of the entities
        involved in the grant.  So we get these and pass them to the
        check_protection() handler in the controller.

        """
        ref = {}
        if role_id:
            ref['role'] = PROVIDERS.role_api.get_role(role_id)
        if user_id:
            try:
                ref['user'] = PROVIDERS.identity_api.get_user(user_id)
            except exception.UserNotFound:
                if not allow_non_existing:
                    raise
        else:
            try:
                ref['group'] = PROVIDERS.identity_api.get_group(group_id)
            except exception.GroupNotFound:
                if not allow_non_existing:
                    raise

        # NOTE(lbragstad): This if/else check will need to be expanded in the
        # future to handle system hierarchies if that is implemented.
        if domain_id:
            ref['domain'] = PROVIDERS.resource_api.get_domain(domain_id)
        elif project_id:
            ref['project'] = PROVIDERS.resource_api.get_project(project_id)

        self.check_protection(request, protection, ref)

    @controller.protected(callback=_check_grant_protection)
    def create_grant(self, request, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Grant a role to a user or group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        inherited_to_projects = self._check_if_inherited(request.context_dict)
        PROVIDERS.assignment_api.create_grant(
            role_id, user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects,
            context=request.context_dict)

    @controller.protected(callback=_check_grant_protection)
    def list_grants(self, request, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """List roles granted to user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        inherited_to_projects = self._check_if_inherited(request.context_dict)
        refs = PROVIDERS.assignment_api.list_grants(
            user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects
        )
        return GrantAssignmentV3.wrap_collection(request.context_dict, refs)

    @controller.protected(callback=_check_grant_protection)
    def check_grant(self, request, role_id, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """Check if a role has been granted on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        inherited_to_projects = self._check_if_inherited(request.context_dict)
        PROVIDERS.assignment_api.get_grant(
            role_id, user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects
        )

    # NOTE(lbragstad): This will allow users to clean up role assignments
    # from the backend in the event the user was removed prior to the role
    # assignment being removed.
    @controller.protected(callback=functools.partial(
        _check_grant_protection, allow_non_existing=True))
    def revoke_grant(self, request, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Revoke a role from user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        inherited_to_projects = self._check_if_inherited(request.context_dict)
        PROVIDERS.assignment_api.delete_grant(
            role_id, user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects,
            context=request.context_dict)
