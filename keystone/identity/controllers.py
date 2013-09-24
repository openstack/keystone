# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import copy
import urllib
import urlparse
import uuid

from keystone.common import controller
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging

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
        tenant_refs = self.identity_api.list_projects()
        for tenant_ref in tenant_refs:
            tenant_ref = self.filter_domain_id(tenant_ref)
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
            token_ref = self.token_api.get_token(context['token_id'])
        except exception.NotFound as e:
            LOG.warning('Authentication failed: %s' % e)
            raise exception.Unauthorized(e)

        user_ref = token_ref['user']
        tenant_refs = (
            self.assignment_api.list_projects_for_user(user_ref['id']))
        tenant_refs = [self.filter_domain_id(ref) for ref in tenant_refs
                       if ref['domain_id'] == DEFAULT_DOMAIN_ID]
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self._format_project_list(tenant_refs, **params)

    def get_project(self, context, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        ref = self.identity_api.get_project(tenant_id)
        return {'tenant': self.filter_domain_id(ref)}

    def get_project_by_name(self, context, tenant_name):
        self.assert_admin(context)
        ref = self.identity_api.get_project_by_name(
            tenant_name, DEFAULT_DOMAIN_ID)
        return {'tenant': self.filter_domain_id(ref)}

    # CRUD Extension
    def create_project(self, context, tenant):
        tenant_ref = self._normalize_dict(tenant)

        if 'name' not in tenant_ref or not tenant_ref['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        self.assert_admin(context)
        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        tenant = self.assignment_api.create_project(
            tenant_ref['id'],
            self._normalize_domain_id(context, tenant_ref))
        return {'tenant': self.filter_domain_id(tenant)}

    def update_project(self, context, tenant_id, tenant):
        self.assert_admin(context)
        # Remove domain_id if specified - a v2 api caller should not
        # be specifying that
        clean_tenant = tenant.copy()
        clean_tenant.pop('domain_id', None)

        # If the project has been disabled (or enabled=False) we are
        # deleting the tokens for that project.
        if not tenant.get('enabled', True):
            self._delete_tokens_for_project(tenant_id)

        tenant_ref = self.assignment_api.update_project(
            tenant_id, clean_tenant)
        return {'tenant': tenant_ref}

    def delete_project(self, context, tenant_id):
        self.assert_admin(context)
        # Delete all tokens belonging to the users for that project
        self._delete_tokens_for_project(tenant_id)
        self.assignment_api.delete_project(tenant_id)

    def get_project_users(self, context, tenant_id, **kw):
        self.assert_admin(context)
        user_refs = []
        user_ids = self.assignment_api.list_user_ids_for_project(tenant_id)
        for user_id in user_ids:
            user_ref = self.identity_api.get_user(user_id)
            user_refs.append(self.identity_api.v3_to_v2_user(user_ref))
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
        ref = self.identity_api.get_user(user_id)
        return {'user': self.identity_api.v3_to_v2_user(ref)}

    def get_users(self, context):
        # NOTE(termie): i can't imagine that this really wants all the data
        #               about every single user in the system...
        if 'name' in context['query_string']:
            return self.get_user_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        user_list = self.identity_api.list_users()
        return {'users': self.identity_api.v3_to_v2_user(user_list)}

    def get_user_by_name(self, context, user_name):
        self.assert_admin(context)
        ref = self.identity_api.get_user_by_name(user_name, DEFAULT_DOMAIN_ID)
        return {'user': self.identity_api.v3_to_v2_user(ref)}

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

        default_project_id = user.pop('tenantId', None)
        if default_project_id is not None:
            # Check to see if the project is valid before moving on.
            self.assignment_api.get_project(default_project_id)
            user['default_project_id'] = default_project_id

        user_id = uuid.uuid4().hex
        user_ref = self._normalize_domain_id(context, user.copy())
        user_ref['id'] = user_id
        new_user_ref = self.identity_api.v3_to_v2_user(
            self.identity_api.create_user(user_id, user_ref))

        if default_project_id is not None:
            self.identity_api.add_user_to_project(default_project_id, user_id)
        return {'user': new_user_ref}

    def update_user(self, context, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        self.assert_admin(context)

        if 'enabled' in user and not isinstance(user['enabled'], bool):
            msg = 'Enabled field should be a boolean'
            raise exception.ValidationError(message=msg)

        default_project_id = user.pop('tenantId', None)
        if default_project_id is not None:
            user['default_project_id'] = default_project_id

        old_user_ref = self.identity_api.v3_to_v2_user(
            self.identity_api.get_user(user_id))

        if ('tenantId' in old_user_ref and
                old_user_ref['tenantId'] != default_project_id and
                default_project_id is not None):
            # Make sure the new project actually exists before we perform the
            # user update.
            self.assignment_api.get_project(default_project_id)

        user_ref = self.identity_api.v3_to_v2_user(
            self.identity_api.update_user(user_id, user))

        if user.get('password') or not user.get('enabled', True):
        # If the password was changed or the user was disabled we clear tokens
            self._delete_tokens_for_user(user_id)

        # If 'tenantId' is in either ref, we might need to add or remove the
        # user from a project.
        if 'tenantId' in user_ref or 'tenantId' in old_user_ref:
            if user_ref['tenantId'] != old_user_ref.get('tenantId'):
                if old_user_ref.get('tenantId'):
                    try:
                        member_role_id = config.CONF.member_role_id
                        self.assignment_api.remove_role_from_user_and_project(
                            user_id, old_user_ref['tenantId'], member_role_id)
                    except exception.NotFound:
                        # NOTE(morganfainberg): This is not a critical error it
                        # just means that the user cannot be removed from the
                        # old tenant.  This could occur if roles aren't found
                        # or if the project is invalid or if there are no roles
                        # for the user on that project.
                        msg = _('Unable to remove user %(user)s from '
                                '%(tenant)s.')
                        LOG.warning(msg, {'user': user_id,
                                          'tenant': old_user_ref['tenantId']})

                if user_ref['tenantId']:
                    try:
                        self.assignment_api.add_user_to_project(
                            user_ref['tenantId'], user_id)
                    except exception.Conflict:
                        # We are already a member of that tenant
                        pass
                    except exception.NotFound:
                        # NOTE(morganfainberg): Log this and move on. This is
                        # not the end of the world if we can't add the user to
                        # the appropriate tenant. Most of the time this means
                        # that the project is invalid or roles are some how
                        # incorrect.  This shouldn't prevent the return of the
                        # new ref.
                        msg = _('Unable to add user %(user)s to %(tenant)s.')
                        LOG.warning(msg, {'user': user_id,
                                          'tenant': user_ref['tenantId']})

        return {'user': user_ref}

    def delete_user(self, context, user_id):
        self.assert_admin(context)
        self.identity_api.delete_user(user_id)
        self._delete_tokens_for_user(user_id)

    def set_user_enabled(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def set_user_password(self, context, user_id, user):
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
            user_id, tenant_id)
        return {'roles': [self.identity_api.get_role(x)
                          for x in roles]}

    # CRUD extension
    def get_role(self, context, role_id):
        self.assert_admin(context)
        return {'role': self.identity_api.get_role(role_id)}

    def create_role(self, context, role):
        role = self._normalize_dict(role)
        self.assert_admin(context)

        if 'name' not in role or not role['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        role_id = uuid.uuid4().hex
        role['id'] = role_id
        role_ref = self.identity_api.create_role(role_id, role)
        return {'role': role_ref}

    def delete_role(self, context, role_id):
        self.assert_admin(context)
        # The driver will delete any assignments for this role.
        # We must first, however, revoke any tokens for users that have an
        # assignment with this role.
        self._delete_tokens_for_role(role_id)
        self.identity_api.delete_role(role_id)

    def get_roles(self, context):
        self.assert_admin(context)
        return {'roles': self.identity_api.list_roles()}

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
            user_id, tenant_id, role_id)

        role_ref = self.identity_api.get_role(role_id)
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
            user_id, tenant_id, role_id)
        self._delete_tokens_for_user(user_id)

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
        self.identity_api.get_user(user_id)
        tenants = self.assignment_api.list_projects_for_user(user_id)
        o = []
        for tenant in tenants:
            # As a v2 call, we should limit the response to those projects in
            # the default domain.
            if tenant['domain_id'] != DEFAULT_DOMAIN_ID:
                continue
            role_ids = self.identity_api.get_roles_for_user_and_project(
                user_id, tenant['id'])
            for role_id in role_ids:
                ref = {'roleId': role_id,
                       'tenantId': tenant['id'],
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
            user_id, tenant_id, role_id)
        self._delete_tokens_for_user(user_id)

        role_ref = self.identity_api.get_role(role_id)
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
            user_id, tenant_id, role_id)
        self._delete_tokens_for_user(user_id)


class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(DomainV3, self).__init__()
        self.get_member_from_driver = self.assignment_api.get_domain

    @controller.protected()
    def create_domain(self, context, domain):
        self._require_attribute(domain, 'name')

        ref = self._assign_unique_id(self._normalize_dict(domain))
        ref = self.identity_api.create_domain(ref['id'], ref)
        return DomainV3.wrap_member(context, ref)

    @controller.filterprotected('enabled', 'name')
    def list_domains(self, context, filters):
        refs = self.identity_api.list_domains()
        return DomainV3.wrap_collection(context, refs, filters)

    @controller.protected()
    def get_domain(self, context, domain_id):
        ref = self.identity_api.get_domain(domain_id)
        return DomainV3.wrap_member(context, ref)

    @controller.protected()
    def update_domain(self, context, domain_id, domain):
        self._require_matching_id(domain_id, domain)

        ref = self.identity_api.update_domain(domain_id, domain)

        # disable owned users & projects when the API user specifically set
        #     enabled=False
        # FIXME(dolph): need a driver call to directly revoke all tokens by
        #               project or domain, regardless of user
        if not domain.get('enabled', True):
            projects = [x for x in self.identity_api.list_projects()
                        if x.get('domain_id') == domain_id]
            for user in self.identity_api.list_users():
                # TODO(dolph): disable domain-scoped tokens
                """
                self.token_api.revoke_tokens(
                    user_id=user['id'],
                    domain_id=domain_id)
                """
                # revoke all tokens for users owned by this domain
                if user.get('domain_id') == domain_id:
                    self._delete_tokens_for_user(user['id'])
                else:
                    # only revoke tokens on projects owned by this domain
                    for project in projects:
                        self._delete_tokens_for_user(
                            user['id'], project_id=project['id'])
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
        user_refs = self.identity_api.list_users()
        user_refs = [r for r in user_refs if r['domain_id'] == domain_id]
        for user in user_refs:
            if user['enabled']:
                user['enabled'] = False
                self.identity_api.update_user(user['id'], user)
                self._delete_tokens_for_user(user['id'])

        # Now, for safety, reload list of users, as well as projects, that are
        # owned by this domain.
        user_refs = self.identity_api.list_users()
        user_ids = [r['id'] for r in user_refs if r['domain_id'] == domain_id]

        proj_refs = self.identity_api.list_projects()
        proj_ids = [r['id'] for r in proj_refs if r['domain_id'] == domain_id]

        # First delete the projects themselves
        project_cntl = ProjectV3()
        for project in proj_ids:
            project_cntl._delete_project(context, project)

        # Get the list of groups owned by this domain and delete them
        group_refs = self.identity_api.list_groups()
        group_ids = ([r['id'] for r in group_refs
                     if r['domain_id'] == domain_id])
        group_cntl = GroupV3()
        for group in group_ids:
            group_cntl._delete_group(context, group)

        # And finally, delete the users themselves
        user_cntl = UserV3()
        for user in user_ids:
            user_cntl._delete_user(context, user)

    @controller.protected()
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
        ref = self.identity_api.get_domain(domain_id)
        if ref['enabled']:
            raise exception.ForbiddenAction(
                action='delete a domain that is not disabled')

        # OK, we are go for delete!
        self._delete_domain_contents(context, domain_id)
        return self.identity_api.delete_domain(domain_id)

    def _get_domain_by_name(self, context, domain_name):
        """Get the domain via its unique name.

        For use by token authentication - not for hooking to the identity
        router as a public api.

        """
        ref = self.identity_api.get_domain_by_name(domain_name)
        return {'domain': ref}


class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectV3, self).__init__()
        self.get_member_from_driver = self.assignment_api.get_project

    @controller.protected()
    def create_project(self, context, project):
        self._require_attribute(project, 'name')

        ref = self._assign_unique_id(self._normalize_dict(project))
        ref = self._normalize_domain_id(context, ref)
        ref = self.assignment_api.create_project(ref['id'], ref)
        return ProjectV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_projects(self, context, filters):
        refs = self.identity_api.list_projects()
        return ProjectV3.wrap_collection(context, refs, filters)

    @controller.filterprotected('enabled', 'name')
    def list_user_projects(self, context, filters, user_id):
        refs = self.identity_api.list_projects_for_user(user_id)
        return ProjectV3.wrap_collection(context, refs, filters)

    @controller.protected()
    def get_project(self, context, project_id):
        ref = self.identity_api.get_project(project_id)
        return ProjectV3.wrap_member(context, ref)

    @controller.protected()
    def update_project(self, context, project_id, project):
        self._require_matching_id(project_id, project)

        # The project was disabled so we delete the tokens
        if not project.get('enabled', True):
            self._delete_tokens_for_project(project_id)

        ref = self.assignment_api.update_project(project_id, project)
        return ProjectV3.wrap_member(context, ref)

    def _delete_project(self, context, project_id):
        # Delete any credentials that reference this project
        for cred in self.credential_api.list_credentials():
            if cred['project_id'] == project_id:
                self.credential_api.delete_credential(cred['id'])

        # Delete all tokens belonging to the users for that project
        self._delete_tokens_for_project(project_id)

        # Finally delete the project itself - the backend is
        # responsible for deleting any role assignments related
        # to this project
        return self.assignment_api.delete_project(project_id)

    @controller.protected()
    def delete_project(self, context, project_id):
        return self._delete_project(context, project_id)


class UserV3(controller.V3Controller):
    collection_name = 'users'
    member_name = 'user'

    def __init__(self):
        super(UserV3, self).__init__()
        self.get_member_from_driver = self.identity_api.get_user

    def _check_user_and_group_protection(self, context, prep_info,
                                         user_id, group_id):
        ref = {}
        ref['user'] = self.identity_api.get_user(user_id)
        ref['group'] = self.identity_api.get_group(group_id)
        self.check_protection(context, prep_info, ref)

    @controller.protected()
    def create_user(self, context, user):
        self._require_attribute(user, 'name')

        ref = self._assign_unique_id(self._normalize_dict(user))
        ref = self._normalize_domain_id(context, ref)
        ref = self.identity_api.create_user(ref['id'], ref)
        return UserV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'email', 'enabled', 'name')
    def list_users(self, context, filters):
        refs = self.identity_api.list_users(
            domain_scope=self._get_domain_id_for_request(context))
        return UserV3.wrap_collection(context, refs, filters)

    @controller.filterprotected('domain_id', 'email', 'enabled', 'name')
    def list_users_in_group(self, context, filters, group_id):
        refs = self.identity_api.list_users_in_group(
            group_id,
            domain_scope=self._get_domain_id_for_request(context))
        return UserV3.wrap_collection(context, refs, filters)

    @controller.protected()
    def get_user(self, context, user_id):
        ref = self.identity_api.get_user(
            user_id,
            domain_scope=self._get_domain_id_for_request(context))
        return UserV3.wrap_member(context, ref)

    @controller.protected()
    def update_user(self, context, user_id, user):
        self._require_matching_id(user_id, user)
        ref = self.identity_api.update_user(
            user_id, user,
            domain_scope=self._get_domain_id_for_request(context))

        if user.get('password') or not user.get('enabled', True):
            # revoke all tokens owned by this user
            self._delete_tokens_for_user(user_id)

        return UserV3.wrap_member(context, ref)

    @controller.protected(callback=_check_user_and_group_protection)
    def add_user_to_group(self, context, user_id, group_id):
        self.identity_api.add_user_to_group(
            user_id, group_id,
            domain_scope=self._get_domain_id_for_request(context))
        # Delete any tokens so that group membership can have an
        # immediate effect
        self._delete_tokens_for_user(user_id)

    @controller.protected(callback=_check_user_and_group_protection)
    def check_user_in_group(self, context, user_id, group_id):
        return self.identity_api.check_user_in_group(
            user_id, group_id,
            domain_scope=self._get_domain_id_for_request(context))

    @controller.protected(callback=_check_user_and_group_protection)
    def remove_user_from_group(self, context, user_id, group_id):
        self.identity_api.remove_user_from_group(
            user_id, group_id,
            domain_scope=self._get_domain_id_for_request(context))
        self._delete_tokens_for_user(user_id)

    def _delete_user(self, context, user_id):
        # Delete any credentials that reference this user
        for cred in self.credential_api.list_credentials():
            if cred['user_id'] == user_id:
                self.credential_api.delete_credential(cred['id'])

        # Make sure any tokens are marked as deleted
        domain_id = self._get_domain_id_for_request(context)
        self._delete_tokens_for_user(user_id)
        # Finally delete the user itself - the backend is
        # responsible for deleting any role assignments related
        # to this user
        return self.identity_api.delete_user(
            user_id, domain_scope=domain_id)

    @controller.protected()
    def delete_user(self, context, user_id):
        return self._delete_user(context, user_id)


class GroupV3(controller.V3Controller):
    collection_name = 'groups'
    member_name = 'group'

    def __init__(self):
        super(GroupV3, self).__init__()
        self.get_member_from_driver = self.identity_api.get_group

    @controller.protected()
    def create_group(self, context, group):
        self._require_attribute(group, 'name')

        ref = self._assign_unique_id(self._normalize_dict(group))
        ref = self._normalize_domain_id(context, ref)
        ref = self.identity_api.create_group(ref['id'], ref)
        return GroupV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'name')
    def list_groups(self, context, filters):
        refs = self.identity_api.list_groups(
            domain_scope=self._get_domain_id_for_request(context))
        return GroupV3.wrap_collection(context, refs, filters)

    @controller.filterprotected('name')
    def list_groups_for_user(self, context, filters, user_id):
        refs = self.identity_api.list_groups_for_user(
            user_id,
            domain_scope=self._get_domain_id_for_request(context))
        return GroupV3.wrap_collection(context, refs, filters)

    @controller.protected()
    def get_group(self, context, group_id):
        ref = self.identity_api.get_group(
            group_id,
            domain_scope=self._get_domain_id_for_request(context))
        return GroupV3.wrap_member(context, ref)

    @controller.protected()
    def update_group(self, context, group_id, group):
        self._require_matching_id(group_id, group)

        ref = self.identity_api.update_group(
            group_id, group,
            domain_scope=self._get_domain_id_for_request(context))
        return GroupV3.wrap_member(context, ref)

    def _delete_group(self, context, group_id):
        # As well as deleting the group, we need to invalidate
        # any tokens for the users who are members of the group.
        # We get the list of users before we attempt the group
        # deletion, so that we can remove these tokens after we know
        # the group deletion succeeded.

        domain_id = self._get_domain_id_for_request(context)
        user_refs = self.identity_api.list_users_in_group(
            group_id, domain_scope=domain_id)
        self.identity_api.delete_group(group_id, domain_scope=domain_id)
        for user in user_refs:
            self._delete_tokens_for_user(user['id'])

    @controller.protected()
    def delete_group(self, context, group_id):
        return self._delete_group(context, group_id)


class RoleV3(controller.V3Controller):
    collection_name = 'roles'
    member_name = 'role'

    def __init__(self):
        super(RoleV3, self).__init__()
        self.get_member_from_driver = self.assignment_api.get_role

    @controller.protected()
    def create_role(self, context, role):
        self._require_attribute(role, 'name')

        ref = self._assign_unique_id(self._normalize_dict(role))
        ref = self.identity_api.create_role(ref['id'], ref)
        return RoleV3.wrap_member(context, ref)

    @controller.filterprotected('name')
    def list_roles(self, context, filters):
        refs = self.identity_api.list_roles()
        return RoleV3.wrap_collection(context, refs, filters)

    @controller.protected()
    def get_role(self, context, role_id):
        ref = self.identity_api.get_role(role_id)
        return RoleV3.wrap_member(context, ref)

    @controller.protected()
    def update_role(self, context, role_id, role):
        self._require_matching_id(role_id, role)

        ref = self.identity_api.update_role(role_id, role)
        return RoleV3.wrap_member(context, ref)

    @controller.protected()
    def delete_role(self, context, role_id):
        # The driver will delete any assignments for this role.
        # We must first, however, revoke any tokens for users that have an
        # assignment with this role.
        self._delete_tokens_for_role(role_id)
        self.identity_api.delete_role(role_id)

    def _require_domain_xor_project(self, domain_id, project_id):
        if (domain_id and project_id) or (not domain_id and not project_id):
            msg = 'Specify a domain or project, not both'
            raise exception.ValidationError(msg)

    def _require_user_xor_group(self, user_id, group_id):
        if (user_id and group_id) or (not user_id and not group_id):
            msg = 'Specify a user or group, not both'
            raise exception.ValidationError(msg)

    def _check_if_inherited(self, context):
        return (CONF.os_inherit.enabled and
                context['path'].startswith('/OS-INHERIT') and
                context['path'].endswith('/inherited_to_projects'))

    def _check_grant_protection(self, context, protection, role_id=None,
                                user_id=None, group_id=None,
                                domain_id=None, project_id=None):
        """Check protection for role grant APIs.

        The policy rule might want to inspect attributes of any of the entities
        involved in the grant.  So we get these and pass them to the
        check_protection() handler in the controller.

        """
        ref = {}
        if role_id:
            ref['role'] = self.identity_api.get_role(role_id)
        if user_id:
            ref['user'] = self.identity_api.get_user(user_id)
        else:
            ref['group'] = self.identity_api.get_group(group_id)

        if domain_id:
            ref['domain'] = self.assignment_api.get_domain(domain_id)
        else:
            ref['project'] = self.assignment_api.get_project(project_id)

        self.check_protection(context, protection, ref)

    @controller.protected(callback=_check_grant_protection)
    def create_grant(self, context, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Grants a role to a user or group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        if user_id:
            self.identity_api.get_user(user_id)
        if group_id:
            self.identity_api.get_group(group_id)

        self.identity_api.create_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context))

    @controller.protected(callback=_check_grant_protection)
    def list_grants(self, context, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """Lists roles granted to user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        refs = self.identity_api.list_grants(
            user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context))
        return RoleV3.wrap_collection(context, refs)

    @controller.protected(callback=_check_grant_protection)
    def check_grant(self, context, role_id, user_id=None,
                    group_id=None, domain_id=None, project_id=None):
        """Checks if a role has been granted on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        if user_id:
            self.identity_api.get_user(user_id)
        if group_id:
            self.identity_api.get_group(group_id)

        self.identity_api.get_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context))

    @controller.protected(callback=_check_grant_protection)
    def revoke_grant(self, context, role_id, user_id=None,
                     group_id=None, domain_id=None, project_id=None):
        """Revokes a role from user/group on either a domain or project."""
        self._require_domain_xor_project(domain_id, project_id)
        self._require_user_xor_group(user_id, group_id)

        self.identity_api.delete_grant(
            role_id, user_id, group_id, domain_id, project_id,
            self._check_if_inherited(context))

        # Now delete any tokens for this user or, in the case of a group,
        # tokens from all the uses who are members of this group.
        if user_id:
            self._delete_tokens_for_user(user_id)
        else:
            self._delete_tokens_for_group(group_id)


class RoleAssignmentV3(controller.V3Controller):

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

    def _format_entity(self, entity):
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
        formatted_entity['links']['assignment'] = (
            self.base_url('%(target)s/%(actor)s/roles/%(role)s%(suffix)s' % {
                'target': target_link,
                'actor': actor_link,
                'role': entity['role_id'],
                'suffix': suffix}))

        return formatted_entity

    def _expand_indirect_assignments(self, refs):
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
                if 'domain' in ref:
                    target = 'Domain: %s' % ref['domain'].get('domain_id')
                elif 'project' in ref:
                    target = 'Project: %s' % ref['project'].get('project_id')
                else:
                    # Should always be a domain or project, but since to get
                    # here things have gone astray, let's be cautious.
                    target = 'Unknown'
                LOG.warning(
                    _('Group %(group)s not found for role-assignment - '
                      '%(target)s with Role: %(role)s') % {
                          'group': ref['group_id'], 'target': target,
                          'role': ref.get('role_id')})
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
                self.base_url('/groups/%s/users/%s' %
                              (group_id, user['id'])))
            return user_entry

        def _build_project_equivalent_of_user_domain_role(
                project_id, domain_id, template):
            """Create a user project assignment equivalent to the domain one.

            The template has had the 'domain' entity removed, so
            substitute a 'project' one, modifying the 'assignment' link
            to match.

            """
            project_entry = copy.deepcopy(template)
            project_entry['scope']['project'] = {'id': project_id}
            project_entry['links']['assignment'] = (
                self.base_url(
                    '/OS-INHERIT/domains/%s/users/%s/roles/%s'
                    '/inherited_to_projects' % (
                        domain_id, project_entry['user']['id'],
                        project_entry['role']['id'])))
            return project_entry

        def _build_project_equivalent_of_group_domain_role(
                user_id, group_id, project_id, domain_id, template):
            """Create a user project equivalent to the domain group one.

            The template has had the 'domain' and 'group' entities removed, so
            substitute a 'user-project' one, modifying the 'assignment' link
            to match.

            """
            project_entry = copy.deepcopy(template)
            project_entry['user'] = {'id': user_id}
            project_entry['scope']['project'] = {'id': project_id}
            project_entry['links']['assignment'] = (
                self.base_url('/OS-INHERIT/domains/%s/groups/%s/roles/%s'
                              '/inherited_to_projects' % (
                                  domain_id, group_id,
                                  project_entry['role']['id'])))
            project_entry['links']['membership'] = (
                self.base_url('/groups/%s/users/%s' %
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
                # It's an inherited domain role - so get the list of projects
                # owned by this domain. A domain scope is guaranteed since we
                # checked this when we built the refs list
                project_ids = (
                    [x['id'] for x in self.assignment_api.list_projects(
                        r['scope']['domain']['id'])])
                base_entry = copy.deepcopy(r)
                domain_id = base_entry['scope']['domain']['id']
                base_entry['scope'].pop('domain')
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
                                _build_project_equivalent_of_group_domain_role(
                                    m['id'], group_id, p,
                                    domain_id, sub_entry))
                            new_refs.append(new_entry)
                    else:
                        new_entry = (
                            _build_project_equivalent_of_user_domain_role(
                                p, domain_id, base_entry))
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

    def _query_filter_is_true(self, filter_value):
        """Determine if bool query param is 'True'.

        We treat this the same way as we do for policy
        enforcement:

        {bool_param}=0 is treated as False

        Any other value is considered to be equivalent to
        True, including the absence of a value

        """

        if (isinstance(filter_value, basestring) and
                filter_value == '0'):
            val = False
        else:
            val = True
        return val

    def _filter_inherited(self, entry):
        if ('inherited_to_projects' in entry and
                not CONF.os_inherit.enabled):
                    return False
        else:
            return True

    @controller.filterprotected('group.id', 'role.id',
                                'scope.domain.id', 'scope.project.id',
                                'scope.OS-INHERIT:inherited_to', 'user.id')
    def list_role_assignments(self, context, filters):

        # TODO(henry-nash): This implementation uses the standard filtering
        # in the V3.wrap_collection. Given the large number of individual
        # assignments, this is pretty inefficient.  An alternative would be
        # to pass the filters into the driver call, so that the list size is
        # kept a minimum.

        refs = self.assignment_api.list_role_assignments()
        formatted_refs = (
            [self._format_entity(x) for x in refs
             if self._filter_inherited(x)])

        if ('effective' in context['query_string'] and
                self._query_filter_is_true(
                    context['query_string']['effective'])):

            formatted_refs = self._expand_indirect_assignments(formatted_refs)

        return self.wrap_collection(context, formatted_refs, filters)

    @controller.protected()
    def get_role_assignment(self, context):
        raise exception.NotImplemented()

    @controller.protected()
    def update_role_assignment(self, context):
        raise exception.NotImplemented()

    @controller.protected()
    def delete_role_assignment(self, context):
        raise exception.NotImplemented()
