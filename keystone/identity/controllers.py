# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import urllib
import urlparse
import uuid

from keystone.common import controller
from keystone.common import logging
from keystone import config
from keystone import exception


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id
LOG = logging.getLogger(__name__)


class Tenant(controller.V2Controller):
    def get_all_projects(self, context, **kw):
        """Gets a list of all tenants for an admin user."""
        if 'name' in context['query_string']:
            return self.get_project_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        tenant_refs = self.identity_api.list_projects(context)
        for tenant_ref in tenant_refs:
            tenant_ref = self._filter_domain_id(tenant_ref)
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self._format_project_list(tenant_refs, **params)

    def get_projects_for_token(self, context, **kw):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        try:
            token_ref = self.token_api.get_token(context=context,
                                                 token_id=context['token_id'])
        except exception.NotFound as e:
            LOG.warning('Authentication failed: %s' % e)
            raise exception.Unauthorized(e)

        user_ref = token_ref['user']
        tenant_ids = self.identity_api.get_projects_for_user(
            context, user_ref['id'])
        tenant_refs = []
        for tenant_id in tenant_ids:
            ref = self.identity_api.get_project(
                context=context, tenant_id=tenant_id)
            tenant_refs.append(self._filter_domain_id(ref))
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self._format_project_list(tenant_refs, **params)

    def get_project(self, context, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        ref = self.identity_api.get_project(context, tenant_id)
        return {'tenant': self._filter_domain_id(ref)}

    def get_project_by_name(self, context, tenant_name):
        self.assert_admin(context)
        ref = self.identity_api.get_project_by_name(
            context, tenant_name, DEFAULT_DOMAIN_ID)
        return {'tenant': self._filter_domain_id(ref)}

    # CRUD Extension
    def create_project(self, context, tenant):
        tenant_ref = self._normalize_dict(tenant)

        if 'name' not in tenant_ref or not tenant_ref['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        self.assert_admin(context)
        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        tenant = self.identity_api.create_project(
            context, tenant_ref['id'],
            self._normalize_domain_id(context, tenant_ref))
        return {'tenant': self._filter_domain_id(tenant)}

    def update_project(self, context, tenant_id, tenant):
        self.assert_admin(context)
        # Remove domain_id if specified - a v2 api caller should not
        # be specifying that
        clean_tenant = tenant.copy()
        clean_tenant.pop('domain_id', None)
        tenant_ref = self.identity_api.update_project(
            context, tenant_id, clean_tenant)
        return {'tenant': tenant_ref}

    def delete_project(self, context, tenant_id):
        self.assert_admin(context)
        self.identity_api.delete_project(context, tenant_id)

    def get_project_users(self, context, tenant_id, **kw):
        self.assert_admin(context)
        user_refs = self.identity_api.get_project_users(context, tenant_id)
        for user_ref in user_refs:
            self._filter_domain_id(user_ref)
        return {'users': user_refs}

    def _format_project_list(self, tenant_refs, **kwargs):
        marker = kwargs.get('marker')
        first_index = 0
        if marker is not None:
            for (marker_index, tenant) in enumerate(tenant_refs):
                if tenant['id'] == marker:
                    # we start pagination after the marker
                    first_index = marker_index + 1
                    break
            else:
                msg = 'Marker could not be found'
                raise exception.ValidationError(message=msg)

        limit = kwargs.get('limit')
        last_index = None
        if limit is not None:
            try:
                limit = int(limit)
                if limit < 0:
                    raise AssertionError()
            except (ValueError, AssertionError):
                msg = 'Invalid limit value'
                raise exception.ValidationError(message=msg)
            last_index = first_index + limit

        tenant_refs = tenant_refs[first_index:last_index]

        for x in tenant_refs:
            if 'enabled' not in x:
                x['enabled'] = True
        o = {'tenants': tenant_refs,
             'tenants_links': []}
        return o


class User(controller.V2Controller):
    def get_user(self, context, user_id):
        self.assert_admin(context)
        ref = self.identity_api.get_user(context, user_id)
        return {'user': self._filter_domain_id(ref)}

    def get_users(self, context):
        # NOTE(termie): i can't imagine that this really wants all the data
        #               about every single user in the system...
        if 'name' in context['query_string']:
            return self.get_user_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        user_list = self.identity_api.list_users(context)
        for x in user_list:
            self._filter_domain_id(x)
        return {'users': user_list}

    def get_user_by_name(self, context, user_name):
        self.assert_admin(context)
        ref = self.identity_api.get_user_by_name(
            context, user_name, DEFAULT_DOMAIN_ID)
        return {'user': self._filter_domain_id(ref)}

    # CRUD extension
    def create_user(self, context, user):
        user = self._normalize_dict(user)
        self.assert_admin(context)

        if 'name' not in user or not user['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)
        if 'enabled' in user and not isinstance(user['enabled'], bool):
            msg = 'Enabled field must be a boolean'
            raise exception.ValidationError(message=msg)

        default_tenant_id = user.get('tenantId', None)
        if (default_tenant_id is not None
                and self.identity_api.get_project(context,
                                                  default_tenant_id) is None):
            raise exception.ProjectNotFound(project_id=default_tenant_id)
        user_id = uuid.uuid4().hex
        user_ref = self._normalize_domain_id(context, user.copy())
        user_ref['id'] = user_id
        new_user_ref = self.identity_api.create_user(
            context, user_id, user_ref)
        if default_tenant_id:
            self.identity_api.add_user_to_project(context,
                                                  default_tenant_id, user_id)
        return {'user': self._filter_domain_id(new_user_ref)}

    def update_user(self, context, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        self.assert_admin(context)

        if 'enabled' in user and not isinstance(user['enabled'], bool):
            msg = 'Enabled field should be a boolean'
            raise exception.ValidationError(message=msg)

        user_ref = self.identity_api.update_user(context, user_id, user)

        if user.get('password') or not user.get('enabled', True):
        # If the password was changed or the user was disabled we clear tokens
            self._delete_tokens_for_user(context, user_id)
        return {'user': self._filter_domain_id(user_ref)}

    def delete_user(self, context, user_id):
        self.assert_admin(context)
        self.identity_api.delete_user(context, user_id)
        self._delete_tokens_for_user(context, user_id)

    def set_user_enabled(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def set_user_password(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def update_user_project(self, context, user_id, user):
        """Update the default tenant."""
        self.assert_admin(context)
        # ensure that we're a member of that tenant
        default_tenant_id = user.get('tenantId')
        self.identity_api.add_user_to_project(context,
                                              default_tenant_id, user_id)
        return self.update_user(context, user_id, user)


class Role(controller.V2Controller):
    # COMPAT(essex-3)
    def get_user_roles(self, context, user_id, tenant_id=None):
        """Get the roles for a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant ID required')

        roles = self.identity_api.get_roles_for_user_and_project(
            context, user_id, tenant_id)
        return {'roles': [self.identity_api.get_role(context, x)
                          for x in roles]}

    # CRUD extension
    def get_role(self, context, role_id):
        self.assert_admin(context)
        return {'role': self.identity_api.get_role(context, role_id)}

    def create_role(self, context, role):
        role = self._normalize_dict(role)
        self.assert_admin(context)

        if 'name' not in role or not role['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        role_id = uuid.uuid4().hex
        role['id'] = role_id
        role_ref = self.identity_api.create_role(context, role_id, role)
        return {'role': role_ref}

    def delete_role(self, context, role_id):
        self.assert_admin(context)
        self.identity_api.delete_role(context, role_id)

    def get_roles(self, context):
        self.assert_admin(context)
        return {'roles': self.identity_api.list_roles(context)}

    def add_role_to_user(self, context, user_id, role_id, tenant_id=None):
        """Add a role to a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant_id required')

        self.identity_api.add_role_to_user_and_project(
            context, user_id, tenant_id, role_id)
        self._delete_tokens_for_user(context, user_id)

        role_ref = self.identity_api.get_role(context, role_id)
        return {'role': role_ref}

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
        self.identity_api.remove_role_from_user_and_project(
            context, user_id, tenant_id, role_id)
        self._delete_tokens_for_user(context, user_id)

    # COMPAT(diablo): CRUD extension
    def get_role_refs(self, context, user_id):
        """Ultimate hack to get around having to make role_refs first-class.

        This will basically iterate over the various roles the user has in
        all tenants the user is a member of and create fake role_refs where
        the id encodes the user-tenant-role information so we can look
        up the appropriate data when we need to delete them.

        """
        self.assert_admin(context)
        # Ensure user exists by getting it first.
        self.identity_api.get_user(context, user_id)
        tenant_ids = self.identity_api.get_projects_for_user(context, user_id)
        o = []
        for tenant_id in tenant_ids:
            role_ids = self.identity_api.get_roles_for_user_and_project(
                context, user_id, tenant_id)
            for role_id in role_ids:
                ref = {'roleId': role_id,
                       'tenantId': tenant_id,
                       'userId': user_id}
                ref['id'] = urllib.urlencode(ref)
                o.append(ref)
        return {'roles': o}

    # COMPAT(diablo): CRUD extension
    def create_role_ref(self, context, user_id, role):
        """This is actually used for adding a user to a tenant.

        In the legacy data model adding a user to a tenant required setting
        a role.

        """
        self.assert_admin(context)
        # TODO(termie): for now we're ignoring the actual role
        tenant_id = role.get('tenantId')
        role_id = role.get('roleId')
        self.identity_api.add_role_to_user_and_project(
            context, user_id, tenant_id, role_id)
        self._delete_tokens_for_user(context, user_id)

        role_ref = self.identity_api.get_role(context, role_id)
        return {'role': role_ref}

    # COMPAT(diablo): CRUD extension
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
        role_ref_ref = urlparse.parse_qs(role_ref_id)
        tenant_id = role_ref_ref.get('tenantId')[0]
        role_id = role_ref_ref.get('roleId')[0]
        self.identity_api.remove_role_from_user_and_project(
            context, user_id, tenant_id, role_id)
        self._delete_tokens_for_user(context, user_id)


class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    @controller.protected
    def create_domain(self, context, domain):
        ref = self._assign_unique_id(self._normalize_dict(domain))
        ref = self.identity_api.create_domain(context, ref['id'], ref)
        return DomainV3.wrap_member(context, ref)

    @controller.filterprotected('enabled', 'name')
    def list_domains(self, context, filters):
        refs = self.identity_api.list_domains(context)
        return DomainV3.wrap_collection(context, refs, filters)

    @controller.protected
    def get_domain(self, context, domain_id):
        ref = self.identity_api.get_domain(context, domain_id)
        return DomainV3.wrap_member(context, ref)

    @controller.protected
    def update_domain(self, context, domain_id, domain):
        self._require_matching_id(domain_id, domain)

        ref = self.identity_api.update_domain(context, domain_id, domain)

        # disable owned users & projects when the API user specifically set
        #     enabled=False
        # FIXME(dolph): need a driver call to directly revoke all tokens by
        #               project or domain, regardless of user
        if not domain.get('enabled', True):
            projects = [x for x in self.identity_api.list_projects(context)
                        if x.get('domain_id') == domain_id]
            for user in self.identity_api.list_users(context):
                # TODO(dolph): disable domain-scoped tokens
                """
                self.token_api.revoke_tokens(
                    context,
                    user_id=user['id'],
                    domain_id=domain_id)
                """
                # revoke all tokens for users owned by this domain
                if user.get('domain_id') == domain_id:
                    self._delete_tokens_for_user(
                        context, user['id'])
                else:
                    # only revoke tokens on projects owned by this domain
                    for project in projects:
                        self._delete_tokens_for_user(
                            context, user['id'],
                            project_id=project['id'])
        return DomainV3.wrap_member(context, ref)

    def _delete_domain_contents(self, context, domain_id):
        """Delete the contents of a domain.

        Before we delete a domain, we need to remove all the entities
        that are owned by it, i.e. Users, Groups & Projects. To do this we
        call the respective delete functions for these entities, which are
        themselves responsible for deleting any credentials and role grants
        associated with them as well as revoking any relevant tokens.

        The order we delete entities is also important since some types
        of backend may need to maintain referential integrity
        throughout, and many of the entities have relationship with each
        other. The following deletion order is therefore used:

        Projects: Reference user and groups for grants
        Groups: Reference users for membership and domains for grants
        Users: Reference domains for grants

        """
        # Start by disabling all the users in this domain, to minimize the
        # the risk that things are changing under our feet.
        # TODO(henry-nash): In theory this step should not be necessary, since
        # users of a disabled domain are prevented from authenticating.
        # However there are some existing bugs in this area (e.g. 1130236).
        # Consider removing this code once these have been fixed.
        user_refs = self.identity_api.list_users(context)
        user_refs = [r for r in user_refs if r['domain_id'] == domain_id]
        for user in user_refs:
            if user['enabled']:
                user['enabled'] = False
                self.identity_api.update_user(context, user['id'], user)
                self._delete_tokens_for_user(context, user['id'])

        # Now, for safety, reload list of users, as well as projects, that are
        # owned by this domain.
        user_refs = self.identity_api.list_users(context)
        user_ids = [r['id'] for r in user_refs if r['domain_id'] == domain_id]

        proj_refs = self.identity_api.list_projects(context)
        proj_ids = [r['id'] for r in proj_refs if r['domain_id'] == domain_id]

        # First delete the projects themselves
        project_cntl = ProjectV3()
        for project in proj_ids:
            project_cntl._delete_project(context, project)

        # Get the list of groups owned by this domain and delete them
        group_refs = self.identity_api.list_groups(context)
        group_ids = ([r['id'] for r in group_refs
                     if r['domain_id'] == domain_id])
        group_cntl = GroupV3()
        for group in group_ids:
            group_cntl._delete_group(context, group)

        # And finally, delete the users themselves
        user_cntl = UserV3()
        for user in user_ids:
            user_cntl._delete_user(context, user)

    @controller.protected
    def delete_domain(self, context, domain_id):
        # explicitly forbid deleting the default domain (this should be a
        # carefully orchestrated manual process involving configuration
        # changes, etc)
        if domain_id == DEFAULT_DOMAIN_ID:
            raise exception.ForbiddenAction(action='delete the default domain')

        # To help avoid inadvertent deletes, we insist that the domain
        # has been previously disabled.  This also prevents a user deleting
        # their own domain since, once it is disabled, they won't be able
        # to get a valid token to issue this delete.
        ref = self.identity_api.get_domain(context, domain_id)
        if ref['enabled']:
            raise exception.ForbiddenAction(
                action='delete a domain that is not disabled')

        # OK, we are go for delete!
        self._delete_domain_contents(context, domain_id)
        return self.identity_api.delete_domain(context, domain_id)

    def _get_domain_by_name(self, context, domain_name):
        """Get the domain via its unique name.

        For use by token authentication - not for hooking to the identity
        router as a public api.

        """
        ref = self.identity_api.get_domain_by_name(
            context, domain_name)
        return {'domain': ref}


class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    @controller.protected
    def create_project(self, context, project):
        ref = self._assign_unique_id(self._normalize_dict(project))
        ref = self._normalize_domain_id(context, ref)
        ref = self.identity_api.create_project(context, ref['id'], ref)
        return ProjectV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_projects(self, context, filters):
        refs = self.identity_api.list_projects(context)
        return ProjectV3.wrap_collection(context, refs, filters)

    @controller.filterprotected('enabled', 'name')
    def list_user_projects(self, context, filters, user_id):
        refs = self.identity_api.list_user_projects(context, user_id)
        return ProjectV3.wrap_collection(context, refs, filters)

    @controller.protected
    def get_project(self, context, project_id):
        ref = self.identity_api.get_project(context, project_id)
        return ProjectV3.wrap_member(context, ref)

    @controller.protected
    def update_project(self, context, project_id, project):
        self._require_matching_id(project_id, project)

        ref = self.identity_api.update_project(context, project_id, project)
        return ProjectV3.wrap_member(context, ref)

    def _delete_project(self, context, project_id):
        # Delete any credentials that reference this project
        for cred in self.credential_api.list_credentials(context):
            if cred['project_id'] == project_id:
                self.credential_api.delete_credential(context, cred['id'])
        # Finally delete the project itself - the backend is
        # responsible for deleting any role assignments related
        # to this project
        return self.identity_api.delete_project(context, project_id)

    @controller.protected
    def delete_project(self, context, project_id):
        return self._delete_project(context, project_id)


class UserV3(controller.V3Controller):
    collection_name = 'users'
    member_name = 'user'

    @controller.protected
    def create_user(self, context, user):
        ref = self._assign_unique_id(self._normalize_dict(user))
        ref = self._normalize_domain_id(context, ref)
        ref = self.identity_api.create_user(context, ref['id'], ref)
        return UserV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'email', 'enabled', 'name')
    def list_users(self, context, filters):
        refs = self.identity_api.list_users(context)
        return UserV3.wrap_collection(context, refs, filters)

    @controller.filterprotected('domain_id', 'email', 'enabled', 'name')
    def list_users_in_group(self, context, filters, group_id):
        refs = self.identity_api.list_users_in_group(context, group_id)
        return UserV3.wrap_collection(context, refs, filters)

    @controller.protected
    def get_user(self, context, user_id):
        ref = self.identity_api.get_user(context, user_id)
        return UserV3.wrap_member(context, ref)

    @controller.protected
    def update_user(self, context, user_id, user):
        self._require_matching_id(user_id, user)
        ref = self.identity_api.update_user(context, user_id, user)

        if user.get('password') or not user.get('enabled', True):
            # revoke all tokens owned by this user
            self._delete_tokens_for_user(context, user_id)

        return UserV3.wrap_member(context, ref)

    @controller.protected
    def add_user_to_group(self, context, user_id, group_id):
        self.identity_api.add_user_to_group(
            context, user_id, group_id)
        # Delete any tokens so that group membership can have an
        # immediate effect
        self._delete_tokens_for_user(context, user_id)

    @controller.protected
    def check_user_in_group(self, context, user_id, group_id):
        return self.identity_api.check_user_in_group(context,
                                                     user_id, group_id)

    @controller.protected
    def remove_user_from_group(self, context, user_id, group_id):
        self.identity_api.remove_user_from_group(
            context, user_id, group_id)
        self._delete_tokens_for_user(context, user_id)

    def _delete_user(self, context, user_id):
        # Delete any credentials that reference this user
        for cred in self.credential_api.list_credentials(context):
            if cred['user_id'] == user_id:
                self.credential_api.delete_credential(context, cred['id'])

        # Make sure any tokens are marked as deleted
        self._delete_tokens_for_user(context, user_id)
        # Finally delete the user itself - the backend is
        # responsible for deleting any role assignments related
        # to this user
        return self.identity_api.delete_user(context, user_id)

    @controller.protected
    def delete_user(self, context, user_id):
        return self._delete_user(context, user_id)


class GroupV3(controller.V3Controller):
    collection_name = 'groups'
    member_name = 'group'

    @controller.protected
    def create_group(self, context, group):
        ref = self._assign_unique_id(self._normalize_dict(group))
        ref = self._normalize_domain_id(context, ref)
        ref = self.identity_api.create_group(context, ref['id'], ref)
        return GroupV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'name')
    def list_groups(self, context, filters):
        refs = self.identity_api.list_groups(context)
        return GroupV3.wrap_collection(context, refs, filters)

    @controller.filterprotected('name')
    def list_groups_for_user(self, context, filters, user_id):
        refs = self.identity_api.list_groups_for_user(context, user_id)
        return GroupV3.wrap_collection(context, refs, filters)

    @controller.protected
    def get_group(self, context, group_id):
        ref = self.identity_api.get_group(context, group_id)
        return GroupV3.wrap_member(context, ref)

    @controller.protected
    def update_group(self, context, group_id, group):
        self._require_matching_id(group_id, group)

        ref = self.identity_api.update_group(context, group_id, group)
        return GroupV3.wrap_member(context, ref)

    def _delete_group(self, context, group_id):
        # As well as deleting the group, we need to invalidate
        # any tokens for the users who are members of the group.
        # We get the list of users before we attempt the group
        # deletion, so that we can remove these tokens after we know
        # the group deletion succeeded.

        user_refs = self.identity_api.list_users_in_group(context, group_id)
        self.identity_api.delete_group(context, group_id)
        for user in user_refs:
            self._delete_tokens_for_user(context, user['id'])

    @controller.protected
    def delete_group(self, context, group_id):
        return self._delete_group(context, group_id)


class RoleV3(controller.V3Controller):
    collection_name = 'roles'
    member_name = 'role'

    @controller.protected
    def create_role(self, context, role):
        ref = self._assign_unique_id(self._normalize_dict(role))
        ref = self.identity_api.create_role(context, ref['id'], ref)
        return RoleV3.wrap_member(context, ref)

    @controller.filterprotected('name')
    def list_roles(self, context, filters):
        refs = self.identity_api.list_roles(context)
        return RoleV3.wrap_collection(context, refs, filters)

    @controller.protected
    def get_role(self, context, role_id):
        ref = self.identity_api.get_role(context, role_id)
        return RoleV3.wrap_member(context, ref)

    @controller.protected
    def update_role(self, context, role_id, role):
        self._require_matching_id(role_id, role)

        ref = self.identity_api.update_role(context, role_id, role)
        return RoleV3.wrap_member(context, ref)

    @controller.protected
    def delete_role(self, context, role_id):
        return self.identity_api.delete_role(context, role_id)

    def _require_domain_xor_project(self, domain_id, project_id):
        if (domain_id and project_id) or (not domain_id and not project_id):
            msg = 'Specify a domain or project, not both'
            raise exception.ValidationError(msg)

    def _require_user_xor_group(self, user_id, group_id):
        if (user_id and group_id) or (not user_id and not group_id):
            msg = 'Specify a user or group, not both'
            raise exception.ValidationError(msg)

    @controller.protected
    def create_grant(self, context, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None):
        """Grants a role to a user or group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.identity_api.create_grant(
            context, role_id, user_id, group_id, domain_id, project_id)

        # So that existing tokens don't stop the use of this grant
        # delete any tokens for this user or, in the case of a group,
        # tokens from all the uses who are members of this group.
        if user_id:
            self._delete_tokens_for_user(context, user_id)
        else:
            self._delete_tokens_for_group(context, group_id)

    @controller.protected
    def list_grants(self, context, user_id=None, group_id=None,
                    domain_id=None, project_id=None):
        """Lists roles granted to user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        refs = self.identity_api.list_grants(
            context, user_id, group_id, domain_id, project_id)
        return RoleV3.wrap_collection(context, refs)

    @controller.protected
    def check_grant(self, context, role_id, user_id=None, group_id=None,
                    domain_id=None, project_id=None):
        """Checks if a role has been granted on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.identity_api.get_grant(
            context, role_id, user_id, group_id, domain_id, project_id)

    @controller.protected
    def revoke_grant(self, context, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None):
        """Revokes a role from user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.identity_api.delete_grant(
            context, role_id, user_id, group_id, domain_id, project_id)

        # Now delete any tokens for this user or, in the case of a group,
        # tokens from all the uses who are members of this group.
        if user_id:
            self._delete_tokens_for_user(context, user_id)
        else:
            self._delete_tokens_for_group(context, group_id)
