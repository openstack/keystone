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
import uuid

from oslo_log import log
from six.moves import urllib

from keystone.assignment import schema
from keystone.common import controller
from keystone.common import dependency
from keystone.common import utils
from keystone.common import validation
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api', 'token_provider_api')
class TenantAssignment(controller.V2Controller):
    """The V2 Project APIs that are processing assignments."""

    @controller.v2_auth_deprecated
    def get_projects_for_token(self, request, **kw):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        token_ref = utils.get_token_ref(request.context_dict)

        tenant_refs = (
            self.assignment_api.list_projects_for_user(token_ref.user_id))
        tenant_refs = [self.v3_to_v2_project(ref) for ref in tenant_refs
                       if ref['domain_id'] == CONF.identity.default_domain_id]
        params = {
            'limit': request.params.get('limit'),
            'marker': request.params.get('marker'),
        }
        return self.format_project_list(tenant_refs, **params)

    @controller.v2_deprecated
    def get_project_users(self, request, tenant_id, **kw):
        self.assert_admin(request)
        user_refs = []
        user_ids = self.assignment_api.list_user_ids_for_project(tenant_id)
        for user_id in user_ids:
            try:
                user_ref = self.identity_api.get_user(user_id)
            except exception.UserNotFound:
                # Log that user is missing and continue on.
                message = ("User %(user_id)s in project %(project_id)s "
                           "doesn't exist.")
                LOG.debug(message,
                          {'user_id': user_id, 'project_id': tenant_id})
            else:
                user_refs.append(self.v3_to_v2_user(user_ref))
        return {'users': user_refs}


@dependency.requires('assignment_api', 'role_api')
class Role(controller.V2Controller):
    """The Role management APIs."""

    @controller.v2_deprecated
    def get_role(self, request, role_id):
        self.assert_admin(request)
        return {'role': self.role_api.get_role(role_id)}

    @controller.v2_deprecated
    def create_role(self, request, role):
        validation.lazy_validate(schema.role_create_v2, role)
        role = self._normalize_dict(role)
        self.assert_admin(request)

        if role['name'] == CONF.member_role_name:
            # Use the configured member role ID when creating the configured
            # member role name. This avoids the potential of creating a
            # "member" role with an unexpected ID.
            role_id = CONF.member_role_id
        else:
            role_id = uuid.uuid4().hex

        role['id'] = role_id
        role_ref = self.role_api.create_role(role_id,
                                             role,
                                             initiator=request.audit_initiator)
        return {'role': role_ref}

    @controller.v2_deprecated
    def delete_role(self, request, role_id):
        self.assert_admin(request)
        self.role_api.delete_role(role_id, initiator=request.audit_initiator)

    @controller.v2_deprecated
    def get_roles(self, request):
        self.assert_admin(request)
        return {'roles': self.role_api.list_roles()}


@dependency.requires('assignment_api', 'resource_api', 'role_api')
class RoleAssignmentV2(controller.V2Controller):
    """The V2 Role APIs that are processing assignments."""

    # COMPAT(essex-3)
    @controller.v2_deprecated
    def get_user_roles(self, request, user_id, tenant_id=None):
        """Get the roles for a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(request)
        # NOTE(davechen): Router without project id is defined,
        # but we don't plan on implementing this.
        if tenant_id is None:
            raise exception.NotImplemented(
                message=_('User roles not supported: tenant_id required'))
        roles = self.assignment_api.get_roles_for_user_and_project(
            user_id, tenant_id)
        return {'roles': [self.role_api.get_role(x)
                          for x in roles]}

    @controller.v2_deprecated
    def add_role_to_user(self, request, user_id, role_id, tenant_id=None):
        """Add a role to a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(request)
        if tenant_id is None:
            raise exception.NotImplemented(
                message=_('User roles not supported: tenant_id required'))

        self.assignment_api.add_role_to_user_and_project(
            user_id, tenant_id, role_id)

        role_ref = self.role_api.get_role(role_id)
        return {'role': role_ref}

    @controller.v2_deprecated
    def remove_role_from_user(self, request, user_id, role_id, tenant_id=None):
        """Remove a role from a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(request)
        if tenant_id is None:
            raise exception.NotImplemented(
                message=_('User roles not supported: tenant_id required'))

        # This still has the weird legacy semantics that adding a role to
        # a user also adds them to a tenant, so we must follow up on that
        self.assignment_api.remove_role_from_user_and_project(
            user_id, tenant_id, role_id)

    # COMPAT(diablo): CRUD extension
    @controller.v2_deprecated
    def get_role_refs(self, request, user_id):
        """Ultimate hack to get around having to make role_refs first-class.

        This will basically iterate over the various roles the user has in
        all tenants the user is a member of and create fake role_refs where
        the id encodes the user-tenant-role information so we can look
        up the appropriate data when we need to delete them.

        """
        self.assert_admin(request)
        tenants = self.assignment_api.list_projects_for_user(user_id)
        o = []
        for tenant in tenants:
            # As a v2 call, we should limit the response to those projects in
            # the default domain.
            if tenant['domain_id'] != CONF.identity.default_domain_id:
                continue
            role_ids = self.assignment_api.get_roles_for_user_and_project(
                user_id, tenant['id'])
            for role_id in role_ids:
                ref = {'roleId': role_id,
                       'tenantId': tenant['id'],
                       'userId': user_id}
                ref['id'] = urllib.parse.urlencode(ref)
                o.append(ref)
        return {'roles': o}

    # COMPAT(diablo): CRUD extension
    @controller.v2_deprecated
    def create_role_ref(self, request, user_id, role):
        """Used for adding a user to a tenant.

        In the legacy data model adding a user to a tenant required setting
        a role.

        """
        self.assert_admin(request)
        # TODO(termie): for now we're ignoring the actual role
        tenant_id = role.get('tenantId')
        role_id = role.get('roleId')
        self.assignment_api.add_role_to_user_and_project(
            user_id, tenant_id, role_id)

        role_ref = self.role_api.get_role(role_id)
        return {'role': role_ref}

    # COMPAT(diablo): CRUD extension
    @controller.v2_deprecated
    def delete_role_ref(self, request, user_id, role_ref_id):
        """Used for deleting a user from a tenant.

        In the legacy data model removing a user from a tenant required
        deleting a role.

        To emulate this, we encode the tenant and role in the role_ref_id,
        and if this happens to be the last role for the user-tenant pair,
        we remove the user from the tenant.

        """
        self.assert_admin(request)
        # TODO(termie): for now we're ignoring the actual role
        role_ref_ref = urllib.parse.parse_qs(role_ref_id)
        tenant_id = role_ref_ref.get('tenantId')[0]
        role_id = role_ref_ref.get('roleId')[0]
        self.assignment_api.remove_role_from_user_and_project(
            user_id, tenant_id, role_id)


@dependency.requires('assignment_api', 'resource_api')
class ProjectAssignmentV3(controller.V3Controller):
    """The V3 Project APIs that are processing assignments."""

    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectAssignmentV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_user_projects(self, request, filters, user_id):
        hints = ProjectAssignmentV3.build_driver_hints(request, filters)
        refs = self.assignment_api.list_projects_for_user(user_id,
                                                          hints=hints)
        return ProjectAssignmentV3.wrap_collection(request.context_dict,
                                                   refs,
                                                   hints=hints)


@dependency.requires('role_api')
class RoleV3(controller.V3Controller):
    """The V3 Role CRUD APIs.

    To ease complexity (and hence risk) in writing the policy rules for the
    role APIs, we create separate policy actions for roles that are domain
    specific, as opposed to those that are global. In order to achieve this
    each of the role API methods has a wrapper method that checks to see if the
    role is global or domain specific.

    NOTE (henry-nash): If this separate global vs scoped policy action pattern
    becomes repeated for other entities, we should consider encapsulating this
    into a specialized router class.

    """

    collection_name = 'roles'
    member_name = 'role'

    def __init__(self):
        super(RoleV3, self).__init__()
        self.get_member_from_driver = self.role_api.get_role

    def _is_domain_role(self, role):
        return role.get('domain_id') is not None

    def _is_domain_role_target(self, role_id):
        try:
            role = self.role_api.get_role(role_id)
        except exception.RoleNotFound:
            # We hide this error since we have not yet carried out a policy
            # check - and it maybe that the caller isn't authorized to make
            # this call. If so, we want that error to be raised instead.
            return False
        return self._is_domain_role(role)

    def create_role_wrapper(self, request, role):
        if self._is_domain_role(role):
            return self.create_domain_role(request, role=role)
        else:
            return self.create_role(request, role=role)

    @controller.protected()
    def create_role(self, request, role):
        validation.lazy_validate(schema.role_create, role)
        return self._create_role(request, role)

    @controller.protected()
    def create_domain_role(self, request, role):
        validation.lazy_validate(schema.role_create, role)
        return self._create_role(request, role)

    def list_roles_wrapper(self, request):
        if request.params.get('domain_id'):
            return self.list_domain_roles(request)
        else:
            return self.list_roles(request)

    @controller.filterprotected('name', 'domain_id')
    def list_roles(self, request, filters):
        return self._list_roles(request, filters)

    @controller.filterprotected('name', 'domain_id')
    def list_domain_roles(self, request, filters):
        return self._list_roles(request, filters)

    def get_role_wrapper(self, request, role_id):
        if self._is_domain_role_target(role_id):
            return self.get_domain_role(request, role_id=role_id)
        else:
            return self.get_role(request, role_id=role_id)

    @controller.protected()
    def get_role(self, request, role_id):
        return self._get_role(request, role_id)

    @controller.protected()
    def get_domain_role(self, request, role_id):
        return self._get_role(request, role_id)

    def update_role_wrapper(self, request, role_id, role):
        # Since we don't allow you change whether a role is global or domain
        # specific, we can ignore the new update attributes and just look at
        # the existing role.
        if self._is_domain_role_target(role_id):
            return self.update_domain_role(
                request, role_id=role_id, role=role)
        else:
            return self.update_role(request, role_id=role_id, role=role)

    @controller.protected()
    def update_role(self, request, role_id, role):
        validation.lazy_validate(schema.role_update, role)
        return self._update_role(request, role_id, role)

    @controller.protected()
    def update_domain_role(self, request, role_id, role):
        validation.lazy_validate(schema.role_update, role)
        return self._update_role(request, role_id, role)

    def delete_role_wrapper(self, request, role_id):
        if self._is_domain_role_target(role_id):
            return self.delete_domain_role(request, role_id=role_id)
        else:
            return self.delete_role(request, role_id=role_id)

    @controller.protected()
    def delete_role(self, request, role_id):
        return self._delete_role(request, role_id)

    @controller.protected()
    def delete_domain_role(self, request, role_id):
        return self._delete_role(request, role_id)

    def _create_role(self, request, role):
        if role['name'] == CONF.member_role_name:
            # Use the configured member role ID when creating the configured
            # member role name. This avoids the potential of creating a
            # "member" role with an unexpected ID.
            role['id'] = CONF.member_role_id
        else:
            role = self._assign_unique_id(role)

        ref = self._normalize_dict(role)
        ref = self.role_api.create_role(ref['id'],
                                        ref,
                                        initiator=request.audit_initiator)
        return RoleV3.wrap_member(request.context_dict, ref)

    def _list_roles(self, request, filters):
        hints = RoleV3.build_driver_hints(request, filters)
        refs = self.role_api.list_roles(hints=hints)
        return RoleV3.wrap_collection(request.context_dict, refs, hints=hints)

    def _get_role(self, request, role_id):
        ref = self.role_api.get_role(role_id)
        return RoleV3.wrap_member(request.context_dict, ref)

    def _update_role(self, request, role_id, role):
        self._require_matching_id(role_id, role)
        ref = self.role_api.update_role(
            role_id, role, initiator=request.audit_initiator
        )
        return RoleV3.wrap_member(request.context_dict, ref)

    def _delete_role(self, request, role_id):
        self.role_api.delete_role(role_id, initiator=request.audit_initiator)

    @classmethod
    def build_driver_hints(cls, request, supported_filters):
        # NOTE(jamielennox): To handle the default case of no domain_id defined
        # the role_assignment backend does some hackery to distinguish between
        # global and domain scoped roles. This backend behaviour relies upon a
        # value of domain_id being set (not just defaulting to None). Manually
        # set the empty filter if its not provided.

        hints = super(RoleV3, cls).build_driver_hints(request,
                                                      supported_filters)

        if not request.params.get('domain_id'):
            hints.add_filter('domain_id', None)

        return hints


@dependency.requires('role_api')
class ImpliedRolesV3(controller.V3Controller):
    """The V3 ImpliedRoles CRD APIs.  There is no Update."""

    def _check_implies_role(self, request, prep_info,
                            prior_role_id, implied_role_id=None):
        ref = {}
        ref['prior_role'] = self.role_api.get_role(prior_role_id)
        if implied_role_id:
            ref['implied_role'] = self.role_api.get_role(implied_role_id)

        self.check_protection(request, prep_info, ref)

    def _prior_role_stanza(self, endpoint, prior_role_id, prior_role_name):
        return {
            "id": prior_role_id,
            "links": {
                "self": endpoint + "/v3/roles/" + prior_role_id
            },
            "name": prior_role_name
        }

    def _implied_role_stanza(self, endpoint, implied_role):
        implied_id = implied_role['id']
        implied_response = {
            "id": implied_id,
            "links": {
                "self": endpoint + "/v3/roles/" + implied_id
            },
            "name": implied_role['name']
        }
        return implied_response

    def _populate_prior_role_response(self, endpoint, prior_id):
        prior_role = self.role_api.get_role(prior_id)
        response = {
            "role_inference": {
                "prior_role": self._prior_role_stanza(
                    endpoint, prior_id, prior_role['name'])
            }
        }
        return response

    def _populate_implied_roles_response(self, endpoint,
                                         prior_id, implied_ids):
        response = self._populate_prior_role_response(endpoint, prior_id)
        response["role_inference"]['implies'] = []
        for implied_id in implied_ids:
            implied_role = self.role_api.get_role(implied_id)
            implied_response = self._implied_role_stanza(
                endpoint, implied_role)
            response["role_inference"]['implies'].append(implied_response)
        response["links"] = {
            "self": endpoint + "/v3/roles/" + prior_id + "/implies"
        }
        return response

    def _populate_implied_role_response(self, endpoint, prior_id, implied_id):
        response = self._populate_prior_role_response(endpoint, prior_id)
        implied_role = self.role_api.get_role(implied_id)
        stanza = self._implied_role_stanza(endpoint, implied_role)
        response["role_inference"]['implies'] = stanza
        return response

    @controller.protected(callback=_check_implies_role)
    def get_implied_role(self, request, prior_role_id, implied_role_id):
        ref = self.role_api.get_implied_role(prior_role_id, implied_role_id)

        prior_id = ref['prior_role_id']
        implied_id = ref['implied_role_id']
        endpoint = super(controller.V3Controller, ImpliedRolesV3).base_url(
            request.context_dict, 'public')
        response = self._populate_implied_role_response(
            endpoint, prior_id, implied_id)
        return response

    @controller.protected(callback=_check_implies_role)
    def check_implied_role(self, request, prior_role_id, implied_role_id):
        self.role_api.get_implied_role(prior_role_id, implied_role_id)

    @controller.protected(callback=_check_implies_role)
    def create_implied_role(self, request, prior_role_id, implied_role_id):
        self.role_api.create_implied_role(prior_role_id, implied_role_id)
        return wsgi.render_response(
            self.get_implied_role(request,
                                  prior_role_id,
                                  implied_role_id),
            status=(201, 'Created'))

    @controller.protected(callback=_check_implies_role)
    def delete_implied_role(self, request, prior_role_id, implied_role_id):
        self.role_api.delete_implied_role(prior_role_id, implied_role_id)

    @controller.protected(callback=_check_implies_role)
    def list_implied_roles(self, request, prior_role_id):
        ref = self.role_api.list_implied_roles(prior_role_id)
        implied_ids = [r['implied_role_id'] for r in ref]
        endpoint = super(controller.V3Controller, ImpliedRolesV3).base_url(
            request.context_dict, 'public')

        results = self._populate_implied_roles_response(
            endpoint, prior_role_id, implied_ids)

        return results

    @controller.protected()
    def list_role_inference_rules(self, request):
        refs = self.role_api.list_role_inference_rules()
        role_dict = {role_ref['id']: role_ref
                     for role_ref in self.role_api.list_roles()}

        rules = dict()
        endpoint = super(controller.V3Controller, ImpliedRolesV3).base_url(
            request.context_dict, 'public')

        for ref in refs:
            implied_role_id = ref['implied_role_id']
            prior_role_id = ref['prior_role_id']
            implied = rules.get(prior_role_id, [])
            implied.append(self._implied_role_stanza(
                endpoint, role_dict[implied_role_id]))
            rules[prior_role_id] = implied

        inferences = []
        for prior_id, implied in rules.items():
            prior_response = self._prior_role_stanza(
                endpoint, prior_id, role_dict[prior_id]['name'])
            inferences.append({'prior_role': prior_response,
                               'implies': implied})
        results = {'role_inferences': inferences}
        return results


@dependency.requires('assignment_api', 'identity_api', 'resource_api',
                     'role_api')
class GrantAssignmentV3(controller.V3Controller):
    """The V3 Grant Assignment APIs."""

    collection_name = 'roles'
    member_name = 'role'

    def __init__(self):
        super(GrantAssignmentV3, self).__init__()
        self.get_member_from_driver = self.role_api.get_role

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
                                allow_no_user=False):
        """Check protection for role grant APIs.

        The policy rule might want to inspect attributes of any of the entities
        involved in the grant.  So we get these and pass them to the
        check_protection() handler in the controller.

        """
        ref = {}
        if role_id:
            ref['role'] = self.role_api.get_role(role_id)
        if user_id:
            try:
                ref['user'] = self.identity_api.get_user(user_id)
            except exception.UserNotFound:
                if not allow_no_user:
                    raise
        else:
            ref['group'] = self.identity_api.get_group(group_id)

        if domain_id:
            ref['domain'] = self.resource_api.get_domain(domain_id)
        else:
            ref['project'] = self.resource_api.get_project(project_id)

        self.check_protection(request, protection, ref)

    @controller.protected(callback=_check_grant_protection)
    def create_grant(self, request, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Grant a role to a user or group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.assignment_api.create_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(request.context_dict),
            request.context_dict)

    @controller.protected(callback=_check_grant_protection)
    def list_grants(self, request, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """List roles granted to user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        refs = self.assignment_api.list_grants(
            user_id, group_id, domain_id, project_id,
            self._check_if_inherited(request.context_dict))
        return GrantAssignmentV3.wrap_collection(request.context_dict, refs)

    @controller.protected(callback=_check_grant_protection)
    def check_grant(self, request, role_id, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """Check if a role has been granted on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.assignment_api.get_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(request.context_dict))

    # NOTE(lbragstad): This will allow users to clean up role assignments
    # from the backend in the event the user was removed prior to the role
    # assignment being removed.
    @controller.protected(callback=functools.partial(
        _check_grant_protection, allow_no_user=True))
    def revoke_grant(self, request, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Revoke a role from user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.assignment_api.delete_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(request.context_dict),
            request.context_dict)


@dependency.requires('assignment_api', 'identity_api', 'resource_api')
class RoleAssignmentV3(controller.V3Controller):
    """The V3 Role Assignment APIs, really just list_role_assignment()."""

    # TODO(henry-nash): The current implementation does not provide a full
    # first class entity for role-assignment. There is no role_assignment_id
    # and only the list_role_assignment call is supported. Further, since it
    # is not a first class entity, the links for the individual entities
    # reference the individual role grant APIs.

    collection_name = 'role_assignments'
    member_name = 'role_assignment'

    @classmethod
    def wrap_member(cls, context, ref):
        # NOTE(henry-nash): Since we are not yet a true collection, we override
        # the wrapper as have already included the links in the entities
        pass

    def _format_entity(self, context, entity):
        """Format an assignment entity for API response.

        The driver layer returns entities as dicts containing the ids of the
        actor (e.g. user or group), target (e.g. domain or project) and role.
        If it is an inherited role, then this is also indicated. Examples:

        For a non-inherited expanded assignment from group membership:
        {'user_id': user_id,
         'project_id': project_id,
         'role_id': role_id,
         'indirect': {'group_id': group_id}}

        or, for a project inherited role:

        {'user_id': user_id,
         'project_id': project_id,
         'role_id': role_id,
         'indirect': {'project_id': parent_id}}

        or, for a role that was implied by a prior role:

        {'user_id': user_id,
         'project_id': project_id,
         'role_id': role_id,
         'indirect': {'role_id': prior role_id}}

        It is possible to deduce if a role assignment came from group
        membership if it has both 'user_id' in the main body of the dict and
        'group_id' in the 'indirect' subdict, as well as it is possible to
        deduce if it has come from inheritance if it contains both a
        'project_id' in the main body of the dict and 'parent_id' in the
        'indirect' subdict.

        This function maps this into the format to be returned via the API,
        e.g. for the second example above:

        {
            'user': {
                {'id': user_id}
            },
            'scope': {
                'project': {
                    {'id': project_id}
                },
                'OS-INHERIT:inherited_to': 'projects'
            },
            'role': {
                {'id': role_id}
            },
            'links': {
                'assignment': '/OS-INHERIT/projects/parent_id/users/user_id/'
                              'roles/role_id/inherited_to_projects'
            }
        }

        """
        formatted_entity = {'links': {}}
        inherited_assignment = entity.get('inherited_to_projects')

        if 'project_id' in entity:
            if 'project_name' in entity:
                formatted_entity['scope'] = {'project': {
                    'id': entity['project_id'],
                    'name': entity['project_name'],
                    'domain': {'id': entity['project_domain_id'],
                               'name': entity['project_domain_name']}}}
            else:
                formatted_entity['scope'] = {
                    'project': {'id': entity['project_id']}}

            if 'domain_id' in entity.get('indirect', {}):
                inherited_assignment = True
                formatted_link = ('/domains/%s' %
                                  entity['indirect']['domain_id'])
            elif 'project_id' in entity.get('indirect', {}):
                inherited_assignment = True
                formatted_link = ('/projects/%s' %
                                  entity['indirect']['project_id'])
            else:
                formatted_link = '/projects/%s' % entity['project_id']
        elif 'domain_id' in entity:
            if 'domain_name' in entity:
                formatted_entity['scope'] = {
                    'domain': {'id': entity['domain_id'],
                               'name': entity['domain_name']}}
            else:
                formatted_entity['scope'] = {
                    'domain': {'id': entity['domain_id']}}
            formatted_link = '/domains/%s' % entity['domain_id']

        if 'user_id' in entity:
            if 'user_name' in entity:
                formatted_entity['user'] = {
                    'id': entity['user_id'],
                    'name': entity['user_name'],
                    'domain': {'id': entity['user_domain_id'],
                               'name': entity['user_domain_name']}}
            else:
                formatted_entity['user'] = {'id': entity['user_id']}
            if 'group_id' in entity.get('indirect', {}):
                membership_url = (
                    self.base_url(context, '/groups/%s/users/%s' % (
                        entity['indirect']['group_id'], entity['user_id'])))
                formatted_entity['links']['membership'] = membership_url
                formatted_link += '/groups/%s' % entity['indirect']['group_id']
            else:
                formatted_link += '/users/%s' % entity['user_id']
        elif 'group_id' in entity:
            if 'group_name' in entity:
                formatted_entity['group'] = {
                    'id': entity['group_id'],
                    'name': entity['group_name'],
                    'domain': {'id': entity['group_domain_id'],
                               'name': entity['group_domain_name']}}
            else:
                formatted_entity['group'] = {'id': entity['group_id']}
            formatted_link += '/groups/%s' % entity['group_id']

        if 'role_name' in entity:
            formatted_entity['role'] = {'id': entity['role_id'],
                                        'name': entity['role_name']}
            if 'role_domain_id' in entity and 'role_domain_name' in entity:
                formatted_entity['role'].update(
                    {'domain': {'id': entity['role_domain_id'],
                                'name': entity['role_domain_name']}})
        else:
            formatted_entity['role'] = {'id': entity['role_id']}
        prior_role_link = ''
        if 'role_id' in entity.get('indirect', {}):
            formatted_link += '/roles/%s' % entity['indirect']['role_id']
            prior_role_link = (
                '/prior_role/%(prior)s/implies/%(implied)s' % {
                    'prior': entity['role_id'],
                    'implied': entity['indirect']['role_id']
                })
        else:
            formatted_link += '/roles/%s' % entity['role_id']

        if inherited_assignment:
            formatted_entity['scope']['OS-INHERIT:inherited_to'] = (
                'projects')
            formatted_link = ('/OS-INHERIT%s/inherited_to_projects' %
                              formatted_link)

        formatted_entity['links']['assignment'] = self.base_url(context,
                                                                formatted_link)
        if prior_role_link:
            formatted_entity['links']['prior_role'] = (
                self.base_url(context, prior_role_link))

        return formatted_entity

    def _assert_effective_filters(self, inherited, group, domain):
        """Assert that useless filter combinations are avoided.

        In effective mode, the following filter combinations are useless, since
        they would always return an empty list of role assignments:
        - group id, since no group assignment is returned in effective mode;
        - domain id and inherited, since no domain inherited assignment is
        returned in effective mode.

        """
        if group:
            msg = _('Combining effective and group filter will always '
                    'result in an empty list.')
            raise exception.ValidationError(msg)

        if inherited and domain:
            msg = _('Combining effective, domain and inherited filters will '
                    'always result in an empty list.')
            raise exception.ValidationError(msg)

    def _assert_domain_nand_project(self, domain_id, project_id):
        if domain_id and project_id:
            msg = _('Specify a domain or project, not both')
            raise exception.ValidationError(msg)

    def _assert_user_nand_group(self, user_id, group_id):
        if user_id and group_id:
            msg = _('Specify a user or group, not both')
            raise exception.ValidationError(msg)

    def _list_role_assignments(self, request, filters, include_subtree=False):
        """List role assignments to user and groups on domains and projects.

        Return a list of all existing role assignments in the system, filtered
        by assignments attributes, if provided.

        If effective option is used and OS-INHERIT extension is enabled, the
        following functions will be applied:
        1) For any group role assignment on a target, replace it by a set of
        role assignments containing one for each user of that group on that
        target;
        2) For any inherited role assignment for an actor on a target, replace
        it by a set of role assignments for that actor on every project under
        that target.

        It means that, if effective mode is used, no group or domain inherited
        assignments will be present in the resultant list. Thus, combining
        effective with them is invalid.

        As a role assignment contains only one actor and one target, providing
        both user and group ids or domain and project ids is invalid as well.

        """
        params = request.params
        effective = 'effective' in params and (
            self.query_filter_is_true(params['effective']))
        include_names = ('include_names' in params and
                         self.query_filter_is_true(params['include_names']))

        if 'scope.OS-INHERIT:inherited_to' in params:
            inherited = (
                params['scope.OS-INHERIT:inherited_to'] == 'projects')
        else:
            # None means querying both inherited and direct assignments
            inherited = None

        self._assert_domain_nand_project(params.get('scope.domain.id'),
                                         params.get('scope.project.id'))
        self._assert_user_nand_group(params.get('user.id'),
                                     params.get('group.id'))

        if effective:
            self._assert_effective_filters(inherited=inherited,
                                           group=params.get('group.id'),
                                           domain=params.get(
                                               'scope.domain.id'))

        refs = self.assignment_api.list_role_assignments(
            role_id=params.get('role.id'),
            user_id=params.get('user.id'),
            group_id=params.get('group.id'),
            domain_id=params.get('scope.domain.id'),
            project_id=params.get('scope.project.id'),
            include_subtree=include_subtree,
            inherited=inherited, effective=effective,
            include_names=include_names)

        formatted_refs = [self._format_entity(request.context_dict, ref)
                          for ref in refs]

        return self.wrap_collection(request.context_dict, formatted_refs)

    @controller.filterprotected('group.id', 'role.id',
                                'scope.domain.id', 'scope.project.id',
                                'scope.OS-INHERIT:inherited_to', 'user.id')
    def list_role_assignments(self, request, filters):
        return self._list_role_assignments(request, filters)

    def _check_list_tree_protection(self, request, protection_info):
        """Check protection for list assignment for tree API.

        The policy rule might want to inspect the domain of any project filter
        so if one is defined, then load the project ref and pass it to the
        check protection method.

        """
        ref = {}
        for filter, value in protection_info['filter_attr'].items():
            if filter == 'scope.project.id' and value:
                ref['project'] = self.resource_api.get_project(value)

        self.check_protection(request, protection_info, ref)

    @controller.filterprotected('group.id', 'role.id',
                                'scope.domain.id', 'scope.project.id',
                                'scope.OS-INHERIT:inherited_to', 'user.id',
                                callback=_check_list_tree_protection)
    def list_role_assignments_for_tree(self, request, filters):
        if not request.params.get('scope.project.id'):
            msg = _('scope.project.id must be specified if include_subtree '
                    'is also specified')
            raise exception.ValidationError(message=msg)
        return self._list_role_assignments(request, filters,
                                           include_subtree=True)

    def list_role_assignments_wrapper(self, request):
        """Main entry point from router for list role assignments.

        Since we want different policy file rules to be applicable based on
        whether there the include_subtree query parameter is part of the API
        call, this method checks for this and then calls the appropriate
        protected entry point.

        """
        params = request.params
        if 'include_subtree' in params and (
                self.query_filter_is_true(params['include_subtree'])):
            return self.list_role_assignments_for_tree(request)
        else:
            return self.list_role_assignments(request)
