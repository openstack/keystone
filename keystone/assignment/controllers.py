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

from keystone.assignment import schema
from keystone.common import controller
from keystone.common import provider_api
from keystone.common import validation
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class ProjectAssignmentV3(controller.V3Controller):
    """The V3 Project APIs that are processing assignments."""

    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectAssignmentV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.resource_api.get_project

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_user_projects(self, request, filters, user_id):
        hints = ProjectAssignmentV3.build_driver_hints(request, filters)
        refs = PROVIDERS.assignment_api.list_projects_for_user(user_id)
        return ProjectAssignmentV3.wrap_collection(request.context_dict,
                                                   refs,
                                                   hints=hints)


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
        self.get_member_from_driver = PROVIDERS.role_api.get_role

    def _is_domain_role(self, role):
        return role.get('domain_id') is not None

    def _is_domain_role_target(self, role_id):
        try:
            role = PROVIDERS.role_api.get_role(role_id)
        except exception.RoleNotFound:
            # We hide this error since we have not yet carried out a policy
            # check - and it maybe that the caller isn't authorized to make
            # this call. If so, we want that error to be raised instead.
            return None, False
        return role, self._is_domain_role(role)

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
        role, is_domain_role = self._is_domain_role_target(role_id)
        if is_domain_role:
            return self.get_domain_role(request, role_id=role_id, role=role)
        else:
            return self.get_role(request, role_id=role_id, role=role)

    @controller.protected()
    def get_role(self, request, role_id, role):
        if not role:
            raise exception.RoleNotFound(role_id=role_id)
        return RoleV3.wrap_member(request.context_dict, role)

    @controller.protected()
    def get_domain_role(self, request, role_id, role):
        if not role:
            raise exception.RoleNotFound(role_id=role_id)
        return RoleV3.wrap_member(request.context_dict, role)

    def update_role_wrapper(self, request, role_id, role):
        # Since we don't allow you change whether a role is global or domain
        # specific, we can ignore the new update attributes and just look at
        # the existing role.
        _, is_domain_role = self._is_domain_role_target(role_id)
        if is_domain_role:
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
        _, is_domain_role = self._is_domain_role_target(role_id)
        if is_domain_role:
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
        ref = PROVIDERS.role_api.create_role(
            ref['id'],
            ref,
            initiator=request.audit_initiator)
        return RoleV3.wrap_member(request.context_dict, ref)

    def _list_roles(self, request, filters):
        hints = RoleV3.build_driver_hints(request, filters)
        refs = PROVIDERS.role_api.list_roles(hints=hints)
        return RoleV3.wrap_collection(request.context_dict, refs, hints=hints)

    def _update_role(self, request, role_id, role):
        self._require_matching_id(role_id, role)
        ref = PROVIDERS.role_api.update_role(
            role_id, role, initiator=request.audit_initiator
        )
        return RoleV3.wrap_member(request.context_dict, ref)

    def _delete_role(self, request, role_id):
        PROVIDERS.role_api.delete_role(role_id,
                                       initiator=request.audit_initiator)

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


class ImpliedRolesV3(controller.V3Controller):
    """The V3 ImpliedRoles CRD APIs.  There is no Update."""

    def _check_implies_role(self, request, prep_info,
                            prior_role_id, implied_role_id=None):
        ref = {}
        ref['prior_role'] = PROVIDERS.role_api.get_role(prior_role_id)
        if implied_role_id:
            ref['implied_role'] = PROVIDERS.role_api.get_role(implied_role_id)

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
        prior_role = PROVIDERS.role_api.get_role(prior_id)
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
            implied_role = PROVIDERS.role_api.get_role(implied_id)
            implied_response = self._implied_role_stanza(
                endpoint, implied_role)
            response["role_inference"]['implies'].append(implied_response)
        response["links"] = {
            "self": endpoint + "/v3/roles/" + prior_id + "/implies"
        }
        return response

    def _populate_implied_role_response(self, endpoint, prior_id, implied_id):
        response = self._populate_prior_role_response(endpoint, prior_id)
        implied_role = PROVIDERS.role_api.get_role(implied_id)
        stanza = self._implied_role_stanza(endpoint, implied_role)
        response["role_inference"]['implies'] = stanza
        response["links"] = {
            "self": (endpoint + "/v3/roles/" + prior_id
                     + "/implies/" + implied_id)
        }
        return response

    @controller.protected(callback=_check_implies_role)
    def get_implied_role(self, request, prior_role_id, implied_role_id):
        ref = PROVIDERS.role_api.get_implied_role(prior_role_id,
                                                  implied_role_id)

        prior_id = ref['prior_role_id']
        implied_id = ref['implied_role_id']
        endpoint = super(controller.V3Controller, ImpliedRolesV3).base_url(
            request.context_dict, 'public')
        response = self._populate_implied_role_response(
            endpoint, prior_id, implied_id)
        return response

    @controller.protected(callback=_check_implies_role)
    def check_implied_role(self, request, prior_role_id, implied_role_id):
        PROVIDERS.role_api.get_implied_role(prior_role_id, implied_role_id)

    @controller.protected(callback=_check_implies_role)
    def create_implied_role(self, request, prior_role_id, implied_role_id):
        PROVIDERS.role_api.create_implied_role(prior_role_id, implied_role_id)
        return wsgi.render_response(
            self.get_implied_role(request,
                                  prior_role_id,
                                  implied_role_id),
            status=(201, 'Created'))

    @controller.protected(callback=_check_implies_role)
    def delete_implied_role(self, request, prior_role_id, implied_role_id):
        PROVIDERS.role_api.delete_implied_role(prior_role_id, implied_role_id)

    @controller.protected(callback=_check_implies_role)
    def list_implied_roles(self, request, prior_role_id):
        ref = PROVIDERS.role_api.list_implied_roles(prior_role_id)
        implied_ids = [r['implied_role_id'] for r in ref]
        endpoint = super(controller.V3Controller, ImpliedRolesV3).base_url(
            request.context_dict, 'public')

        results = self._populate_implied_roles_response(
            endpoint, prior_role_id, implied_ids)

        return results

    @controller.protected()
    def list_role_inference_rules(self, request):
        refs = PROVIDERS.role_api.list_role_inference_rules()
        role_dict = {role_ref['id']: role_ref
                     for role_ref in PROVIDERS.role_api.list_roles()}

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

    @controller.protected(callback=_check_grant_protection)
    def list_system_grants_for_user(self, request, user_id):
        """List all system grants for a specific user.

        :param request: the request object
        :param user_id: ID of the user
        :returns: a list of grants the user has on the system

        """
        refs = PROVIDERS.assignment_api.list_system_grants_for_user(user_id)
        return GrantAssignmentV3.wrap_collection(request.context_dict, refs)

    @controller.protected(callback=_check_grant_protection)
    def check_system_grant_for_user(self, request, role_id, user_id):
        """Check if a user has a specific role on the system.

        :param request: the request object
        :param role_id: the ID of the role to check
        :param user_id: the ID of the user to check

        """
        PROVIDERS.assignment_api.check_system_grant_for_user(user_id, role_id)

    @controller.protected(callback=_check_grant_protection)
    def create_system_grant_for_user(self, request, role_id, user_id):
        """Grant a role to a user on the system.

        :param request: the request object
        :param role_id: the ID of the role to grant to the user
        :param user_id: the ID of the user

        """
        PROVIDERS.assignment_api.create_system_grant_for_user(user_id, role_id)

    @controller.protected(callback=functools.partial(
        _check_grant_protection, allow_non_existing=True))
    def revoke_system_grant_for_user(self, request, role_id, user_id):
        """Revoke a role from user on the system.

        :param request: the request object
        :param role_id: the ID of the role to remove
        :param user_id: the ID of the user

        """
        PROVIDERS.assignment_api.delete_system_grant_for_user(user_id, role_id)

    @controller.protected(callback=_check_grant_protection)
    def list_system_grants_for_group(self, request, group_id):
        """List all system grants for a specific group.

        :param request: the request object
        :param group_id: ID of the group
        :returns: a list of grants the group has on the system

        """
        refs = PROVIDERS.assignment_api.list_system_grants_for_group(group_id)
        return GrantAssignmentV3.wrap_collection(request.context_dict, refs)

    @controller.protected(callback=_check_grant_protection)
    def check_system_grant_for_group(self, request, role_id, group_id):
        """Check if a group has a specific role on the system.

        :param request: the request object
        :param role_id: the ID of the role to check
        :param group_id: the ID of the group to check

        """
        PROVIDERS.assignment_api.check_system_grant_for_group(
            group_id, role_id
        )

    @controller.protected(callback=_check_grant_protection)
    def create_system_grant_for_group(self, request, role_id, group_id):
        """Grant a role to a group on the system.

        :param request: the request object
        :param role_id: the ID of the role to grant to the group
        :param group_id: the ID of the group

        """
        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, role_id
        )

    @controller.protected(callback=functools.partial(_check_grant_protection))
    def revoke_system_grant_for_group(self, request, role_id, group_id):
        """Revoke a role from the group on the system.

        :param request: the request object
        :param role_id: the ID of the role to remove
        :param user_id: the ID of the user

        """
        PROVIDERS.assignment_api.delete_system_grant_for_group(
            group_id, role_id
        )


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
        formatted_link = ''
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
        elif 'system' in entity:
            formatted_link = '/system'
            formatted_entity['scope'] = {'system': entity['system']}

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

    def _assert_system_nand_domain(self, system, domain_id):
        if system and domain_id:
            msg = _('Specify system or domain, not both')
            raise exception.ValidationError(msg)

    def _assert_system_nand_project(self, system, project_id):
        if system and project_id:
            msg = _('Specify system or project, not both')
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
        self._assert_system_nand_domain(
            params.get('scope.system'), params.get('scope.domain.id')
        )
        self._assert_system_nand_project(
            params.get('scope.system'), params.get('scope.project.id')
        )
        self._assert_user_nand_group(params.get('user.id'),
                                     params.get('group.id'))

        if effective:
            self._assert_effective_filters(inherited=inherited,
                                           group=params.get('group.id'),
                                           domain=params.get(
                                               'scope.domain.id'))

        refs = PROVIDERS.assignment_api.list_role_assignments(
            role_id=params.get('role.id'),
            user_id=params.get('user.id'),
            group_id=params.get('group.id'),
            system=params.get('scope.system'),
            domain_id=params.get('scope.domain.id'),
            project_id=params.get('scope.project.id'),
            include_subtree=include_subtree,
            inherited=inherited, effective=effective,
            include_names=include_names)

        formatted_refs = [self._format_entity(request.context_dict, ref)
                          for ref in refs]

        return self.wrap_collection(request.context_dict, formatted_refs)

    @controller.filterprotected('group.id', 'role.id', 'scope.system',
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
        for filter, value in protection_info.get('filter_attr', {}).items():
            if filter == 'scope.project.id' and value:
                ref['project'] = PROVIDERS.resource_api.get_project(value)

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
