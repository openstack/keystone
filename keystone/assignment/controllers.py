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

import copy
import functools
import uuid

from oslo_config import cfg
from oslo_log import log
from six.moves import urllib

from keystone.assignment import schema
from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import exception
from keystone.i18n import _, _LW
from keystone.models import token_model
from keystone import notifications


CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api', 'token_provider_api')
class TenantAssignment(controller.V2Controller):
    """The V2 Project APIs that are processing assignments."""

    @controller.v2_deprecated
    def get_projects_for_token(self, context, **kw):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        try:
            token_data = self.token_provider_api.validate_token(
                context['token_id'])
            token_ref = token_model.KeystoneToken(token_id=context['token_id'],
                                                  token_data=token_data)
        except exception.NotFound as e:
            LOG.warning(_LW('Authentication failed: %s'), e)
            raise exception.Unauthorized(e)

        tenant_refs = (
            self.assignment_api.list_projects_for_user(token_ref.user_id))
        tenant_refs = [self.v3_to_v2_project(ref) for ref in tenant_refs
                       if ref['domain_id'] == CONF.identity.default_domain_id]
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self.format_project_list(tenant_refs, **params)

    @controller.v2_deprecated
    def get_project_users(self, context, tenant_id, **kw):
        self.assert_admin(context)
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
    def get_role(self, context, role_id):
        self.assert_admin(context)
        return {'role': self.role_api.get_role(role_id)}

    @controller.v2_deprecated
    def create_role(self, context, role):
        role = self._normalize_dict(role)
        self.assert_admin(context)

        if 'name' not in role or not role['name']:
            msg = _('Name field is required and cannot be empty')
            raise exception.ValidationError(message=msg)

        if role['name'] == CONF.member_role_name:
            # Use the configured member role ID when creating the configured
            # member role name. This avoids the potential of creating a
            # "member" role with an unexpected ID.
            role_id = CONF.member_role_id
        else:
            role_id = uuid.uuid4().hex

        role['id'] = role_id
        role_ref = self.role_api.create_role(role_id, role)
        return {'role': role_ref}

    @controller.v2_deprecated
    def delete_role(self, context, role_id):
        self.assert_admin(context)
        self.role_api.delete_role(role_id)

    @controller.v2_deprecated
    def get_roles(self, context):
        self.assert_admin(context)
        return {'roles': self.role_api.list_roles()}


@dependency.requires('assignment_api', 'resource_api', 'role_api')
class RoleAssignmentV2(controller.V2Controller):
    """The V2 Role APIs that are processing assignments."""

    # COMPAT(essex-3)
    @controller.v2_deprecated
    def get_user_roles(self, context, user_id, tenant_id=None):
        """Get the roles for a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        roles = self.assignment_api.get_roles_for_user_and_project(
            user_id, tenant_id)
        return {'roles': [self.role_api.get_role(x)
                          for x in roles]}

    @controller.v2_deprecated
    def add_role_to_user(self, context, user_id, role_id, tenant_id=None):
        """Add a role to a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant_id required')

        self.assignment_api.add_role_to_user_and_project(
            user_id, tenant_id, role_id)

        role_ref = self.role_api.get_role(role_id)
        return {'role': role_ref}

    @controller.v2_deprecated
    def remove_role_from_user(self, context, user_id, role_id, tenant_id=None):
        """Remove a role from a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant_id required')

        # This still has the weird legacy semantics that adding a role to
        # a user also adds them to a tenant, so we must follow up on that
        self.assignment_api.remove_role_from_user_and_project(
            user_id, tenant_id, role_id)

    # COMPAT(diablo): CRUD extension
    @controller.v2_deprecated
    def get_role_refs(self, context, user_id):
        """Ultimate hack to get around having to make role_refs first-class.

        This will basically iterate over the various roles the user has in
        all tenants the user is a member of and create fake role_refs where
        the id encodes the user-tenant-role information so we can look
        up the appropriate data when we need to delete them.

        """
        self.assert_admin(context)
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
    def create_role_ref(self, context, user_id, role):
        """This is actually used for adding a user to a tenant.

        In the legacy data model adding a user to a tenant required setting
        a role.

        """
        self.assert_admin(context)
        # TODO(termie): for now we're ignoring the actual role
        tenant_id = role.get('tenantId')
        role_id = role.get('roleId')
        self.assignment_api.add_role_to_user_and_project(
            user_id, tenant_id, role_id)

        role_ref = self.role_api.get_role(role_id)
        return {'role': role_ref}

    # COMPAT(diablo): CRUD extension
    @controller.v2_deprecated
    def delete_role_ref(self, context, user_id, role_ref_id):
        """This is actually used for deleting a user from a tenant.

        In the legacy data model removing a user from a tenant required
        deleting a role.

        To emulate this, we encode the tenant and role in the role_ref_id,
        and if this happens to be the last role for the user-tenant pair,
        we remove the user from the tenant.

        """
        self.assert_admin(context)
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

    @controller.filterprotected('enabled', 'name')
    def list_user_projects(self, context, filters, user_id):
        hints = ProjectAssignmentV3.build_driver_hints(context, filters)
        refs = self.assignment_api.list_projects_for_user(user_id,
                                                          hints=hints)
        return ProjectAssignmentV3.wrap_collection(context, refs, hints=hints)


@dependency.requires('role_api')
class RoleV3(controller.V3Controller):
    """The V3 Role CRUD APIs."""

    collection_name = 'roles'
    member_name = 'role'

    def __init__(self):
        super(RoleV3, self).__init__()
        self.get_member_from_driver = self.role_api.get_role

    @controller.protected()
    @validation.validated(schema.role_create, 'role')
    def create_role(self, context, role):
        if role['name'] == CONF.member_role_name:
            # Use the configured member role ID when creating the configured
            # member role name. This avoids the potential of creating a
            # "member" role with an unexpected ID.
            role['id'] = CONF.member_role_id
        else:
            role = self._assign_unique_id(role)

        ref = self._normalize_dict(role)

        initiator = notifications._get_request_audit_info(context)
        ref = self.role_api.create_role(ref['id'], ref, initiator)
        return RoleV3.wrap_member(context, ref)

    @controller.filterprotected('name')
    def list_roles(self, context, filters):
        hints = RoleV3.build_driver_hints(context, filters)
        refs = self.role_api.list_roles(
            hints=hints)
        return RoleV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_role(self, context, role_id):
        ref = self.role_api.get_role(role_id)
        return RoleV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.role_update, 'role')
    def update_role(self, context, role_id, role):
        self._require_matching_id(role_id, role)
        initiator = notifications._get_request_audit_info(context)
        ref = self.role_api.update_role(role_id, role, initiator)
        return RoleV3.wrap_member(context, ref)

    @controller.protected()
    def delete_role(self, context, role_id):
        initiator = notifications._get_request_audit_info(context)
        self.role_api.delete_role(role_id, initiator)


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
        return (CONF.os_inherit.enabled and
                context['path'].startswith('/OS-INHERIT') and
                context['path'].endswith('/inherited_to_projects'))

    def _check_grant_protection(self, context, protection, role_id=None,
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

        self.check_protection(context, protection, ref)

    @controller.protected(callback=_check_grant_protection)
    def create_grant(self, context, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Grants a role to a user or group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.assignment_api.create_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context), context)

    @controller.protected(callback=_check_grant_protection)
    def list_grants(self, context, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """Lists roles granted to user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        refs = self.assignment_api.list_grants(
            user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context))
        return GrantAssignmentV3.wrap_collection(context, refs)

    @controller.protected(callback=_check_grant_protection)
    def check_grant(self, context, role_id, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """Checks if a role has been granted on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.assignment_api.get_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context))

    # NOTE(lbragstad): This will allow users to clean up role assignments
    # from the backend in the event the user was removed prior to the role
    # assignment being removed.
    @controller.protected(callback=functools.partial(
        _check_grant_protection, allow_no_user=True))
    def revoke_grant(self, context, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Revokes a role from user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.assignment_api.delete_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context), context)


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

        {'user_id': user_id,
         'project_id': domain_id,
         'role_id': role_id}

        or, for an inherited role:

        {'user_id': user_id,
         'domain_id': domain_id,
         'role_id': role_id,
         'inherited_to_projects': true}

        This function maps this into the format to be returned via the API,
        e.g. for the second example above:

        {
            'user': {
                {'id': user_id}
            },
            'scope': {
                'domain': {
                    {'id': domain_id}
                },
                'OS-INHERIT:inherited_to': 'projects
            },
            'role': {
                {'id': role_id}
            },
            'links': {
                'assignment': '/domains/domain_id/users/user_id/roles/'
                              'role_id/inherited_to_projects'
            }
        }

        """

        formatted_entity = {}
        suffix = ""
        if 'user_id' in entity:
            formatted_entity['user'] = {'id': entity['user_id']}
            actor_link = 'users/%s' % entity['user_id']
        if 'group_id' in entity:
            formatted_entity['group'] = {'id': entity['group_id']}
            actor_link = 'groups/%s' % entity['group_id']
        if 'role_id' in entity:
            formatted_entity['role'] = {'id': entity['role_id']}
        if 'project_id' in entity:
            formatted_entity['scope'] = (
                {'project': {'id': entity['project_id']}})
            if 'inherited_to_projects' in entity:
                formatted_entity['scope']['OS-INHERIT:inherited_to'] = (
                    'projects')
                target_link = '/OS-INHERIT/projects/%s' % entity['project_id']
                suffix = '/inherited_to_projects'
            else:
                target_link = '/projects/%s' % entity['project_id']
        if 'domain_id' in entity:
            formatted_entity['scope'] = (
                {'domain': {'id': entity['domain_id']}})
            if 'inherited_to_projects' in entity:
                formatted_entity['scope']['OS-INHERIT:inherited_to'] = (
                    'projects')
                target_link = '/OS-INHERIT/domains/%s' % entity['domain_id']
                suffix = '/inherited_to_projects'
            else:
                target_link = '/domains/%s' % entity['domain_id']
        formatted_entity.setdefault('links', {})

        path = '%(target)s/%(actor)s/roles/%(role)s%(suffix)s' % {
            'target': target_link,
            'actor': actor_link,
            'role': entity['role_id'],
            'suffix': suffix}
        formatted_entity['links']['assignment'] = self.base_url(context, path)

        return formatted_entity

    def _expand_indirect_assignments(self, context, refs):
        """Processes entity list into all-direct assignments.

        For any group role assignments in the list, create a role assignment
        entity for each member of that group, and then remove the group
        assignment entity itself from the list.

        If the OS-INHERIT extension is enabled, then honor any inherited
        roles on the domain by creating the equivalent on all projects
        owned by the domain.

        For any new entity created by virtue of group membership, add in an
        additional link to that membership.

        """
        def _get_group_members(ref):
            """Get a list of group members.

            Get the list of group members.  If this fails with
            GroupNotFound, then log this as a warning, but allow
            overall processing to continue.

            """
            try:
                members = self.identity_api.list_users_in_group(
                    ref['group']['id'])
            except exception.GroupNotFound:
                members = []
                # The group is missing, which should not happen since
                # group deletion should remove any related assignments, so
                # log a warning
                target = 'Unknown'
                # Should always be a domain or project, but since to get
                # here things have gone astray, let's be cautious.
                if 'scope' in ref:
                    if 'domain' in ref['scope']:
                        dom_id = ref['scope']['domain'].get('id', 'Unknown')
                        target = 'Domain: %s' % dom_id
                    elif 'project' in ref['scope']:
                        proj_id = ref['scope']['project'].get('id', 'Unknown')
                        target = 'Project: %s' % proj_id
                role_id = 'Unknown'
                if 'role' in ref and 'id' in ref['role']:
                    role_id = ref['role']['id']
                LOG.warning(
                    _LW('Group %(group)s not found for role-assignment - '
                        '%(target)s with Role: %(role)s'), {
                            'group': ref['group']['id'], 'target': target,
                            'role': role_id})
            return members

        def _build_user_assignment_equivalent_of_group(
                user, group_id, template):
            """Create a user assignment equivalent to the group one.

            The template has had the 'group' entity removed, so
            substitute a 'user' one. The 'assignment' link stays as it is,
            referring to the group assignment that led to this role.
            A 'membership' link is added that refers to this particular
            user's membership of this group.

            """
            user_entry = copy.deepcopy(template)
            user_entry['user'] = {'id': user['id']}
            user_entry['links']['membership'] = (
                self.base_url(context, '/groups/%s/users/%s' %
                              (group_id, user['id'])))
            return user_entry

        def _build_project_equivalent_of_user_target_role(
                project_id, target_id, target_type, template):
            """Create a user project assignment equivalent to the domain one.

            The template has had the 'domain' entity removed, so
            substitute a 'project' one, modifying the 'assignment' link
            to match.

            """
            project_entry = copy.deepcopy(template)
            project_entry['scope']['project'] = {'id': project_id}
            project_entry['links']['assignment'] = (
                self.base_url(
                    context,
                    '/OS-INHERIT/%s/%s/users/%s/roles/%s'
                    '/inherited_to_projects' % (
                        target_type, target_id, project_entry['user']['id'],
                        project_entry['role']['id'])))
            return project_entry

        def _build_project_equivalent_of_group_target_role(
                user_id, group_id, project_id,
                target_id, target_type, template):
            """Create a user project equivalent to the domain group one.

            The template has had the 'domain' and 'group' entities removed, so
            substitute a 'user-project' one, modifying the 'assignment' link
            to match.

            """
            project_entry = copy.deepcopy(template)
            project_entry['user'] = {'id': user_id}
            project_entry['scope']['project'] = {'id': project_id}
            project_entry['links']['assignment'] = (
                self.base_url(context,
                              '/OS-INHERIT/%s/%s/groups/%s/roles/%s'
                              '/inherited_to_projects' % (
                                  target_type, target_id, group_id,
                                  project_entry['role']['id'])))
            project_entry['links']['membership'] = (
                self.base_url(context, '/groups/%s/users/%s' %
                              (group_id, user_id)))
            return project_entry

        # Scan the list of entities for any assignments that need to be
        # expanded.
        #
        # If the OS-INERIT extension is enabled, the refs lists may
        # contain roles to be inherited from domain to project, so expand
        # these as well into project equivalents
        #
        # For any regular group entries, expand these into user entries based
        # on membership of that group.
        #
        # Due to the potentially large expansions, rather than modify the
        # list we are enumerating, we build a new one as we go.
        #

        new_refs = []
        for r in refs:
            if 'OS-INHERIT:inherited_to' in r['scope']:
                if 'domain' in r['scope']:
                    # It's an inherited domain role - so get the list of
                    # projects owned by this domain.
                    project_ids = (
                        [x['id'] for x in
                            self.resource_api.list_projects_in_domain(
                                r['scope']['domain']['id'])])
                    base_entry = copy.deepcopy(r)
                    target_type = 'domains'
                    target_id = base_entry['scope']['domain']['id']
                    base_entry['scope'].pop('domain')
                else:
                    # It's an inherited project role - so get the list of
                    # projects in this project subtree.
                    project_id = r['scope']['project']['id']
                    project_ids = (
                        [x['id'] for x in
                            self.resource_api.list_projects_in_subtree(
                                project_id)])
                    base_entry = copy.deepcopy(r)
                    target_type = 'projects'
                    target_id = base_entry['scope']['project']['id']
                    base_entry['scope'].pop('project')

                # For each project, create an equivalent role assignment
                for p in project_ids:
                    # If it's a group assignment, then create equivalent user
                    # roles based on membership of the group
                    if 'group' in base_entry:
                        members = _get_group_members(base_entry)
                        sub_entry = copy.deepcopy(base_entry)
                        group_id = sub_entry['group']['id']
                        sub_entry.pop('group')
                        for m in members:
                            new_entry = (
                                _build_project_equivalent_of_group_target_role(
                                    m['id'], group_id, p,
                                    target_id, target_type, sub_entry))
                            new_refs.append(new_entry)
                    else:
                        new_entry = (
                            _build_project_equivalent_of_user_target_role(
                                p, target_id, target_type, base_entry))
                        new_refs.append(new_entry)
            elif 'group' in r:
                # It's a non-inherited group role assignment, so get the list
                # of members.
                members = _get_group_members(r)

                # Now replace that group role assignment entry with an
                # equivalent user role assignment for each of the group members
                base_entry = copy.deepcopy(r)
                group_id = base_entry['group']['id']
                base_entry.pop('group')
                for m in members:
                    user_entry = _build_user_assignment_equivalent_of_group(
                        m, group_id, base_entry)
                    new_refs.append(user_entry)
            else:
                new_refs.append(r)

        return new_refs

    def _filter_inherited(self, entry):
        if ('inherited_to_projects' in entry and
                not CONF.os_inherit.enabled):
            return False
        else:
            return True

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

    @controller.filterprotected('group.id', 'role.id',
                                'scope.domain.id', 'scope.project.id',
                                'scope.OS-INHERIT:inherited_to', 'user.id')
    def list_role_assignments(self, context, filters):

        # TODO(henry-nash): This implementation uses the standard filtering
        # in the V3.wrap_collection. Given the large number of individual
        # assignments, this is pretty inefficient.  An alternative would be
        # to pass the filters into the driver call, so that the list size is
        # kept a minimum.

        params = context['query_string']
        effective = 'effective' in params and (
            self.query_filter_is_true(params['effective']))

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

        hints = self.build_driver_hints(context, filters)
        refs = self.assignment_api.list_role_assignments()
        formatted_refs = (
            [self._format_entity(context, x) for x in refs
             if self._filter_inherited(x)])

        if effective:
            formatted_refs = self._expand_indirect_assignments(context,
                                                               formatted_refs)

        return self.wrap_collection(context, formatted_refs, hints=hints)

    @controller.protected()
    def get_role_assignment(self, context):
        raise exception.NotImplemented()

    @controller.protected()
    def update_role_assignment(self, context):
        raise exception.NotImplemented()

    @controller.protected()
    def delete_role_assignment(self, context):
        raise exception.NotImplemented()
