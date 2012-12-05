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
from keystone.common import wsgi
from keystone import exception
from keystone.identity import core
from keystone import policy
from keystone import token


LOG = logging.getLogger(__name__)


class Tenant(wsgi.Application):
    def __init__(self):
        self.identity_api = core.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(Tenant, self).__init__()

    def get_all_tenants(self, context, **kw):
        """Gets a list of all tenants for an admin user."""
        if 'name' in context['query_string']:
            return self.get_tenant_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        tenant_refs = self.identity_api.get_tenants(context)
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self._format_tenant_list(tenant_refs, **params)

    def get_tenants_for_token(self, context, **kw):
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
        tenant_ids = self.identity_api.get_tenants_for_user(
            context, user_ref['id'])
        tenant_refs = []
        for tenant_id in tenant_ids:
            tenant_refs.append(self.identity_api.get_tenant(
                context=context,
                tenant_id=tenant_id))
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self._format_tenant_list(tenant_refs, **params)

    def get_tenant(self, context, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        return {'tenant': self.identity_api.get_tenant(context, tenant_id)}

    def get_tenant_by_name(self, context, tenant_name):
        self.assert_admin(context)
        return {'tenant': self.identity_api.get_tenant_by_name(
            context, tenant_name)}

    # CRUD Extension
    def create_tenant(self, context, tenant):
        tenant_ref = self._normalize_dict(tenant)

        if not 'name' in tenant_ref or not tenant_ref['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        self.assert_admin(context)
        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        tenant = self.identity_api.create_tenant(
            context, tenant_ref['id'], tenant_ref)
        return {'tenant': tenant}

    def update_tenant(self, context, tenant_id, tenant):
        self.assert_admin(context)
        tenant_ref = self.identity_api.update_tenant(
            context, tenant_id, tenant)
        return {'tenant': tenant_ref}

    def delete_tenant(self, context, tenant_id):
        self.assert_admin(context)
        self.identity_api.delete_tenant(context, tenant_id)

    def get_tenant_users(self, context, tenant_id, **kw):
        self.assert_admin(context)
        user_refs = self.identity_api.get_tenant_users(context, tenant_id)
        return {'users': user_refs}

    def _format_tenant_list(self, tenant_refs, **kwargs):
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


class User(wsgi.Application):
    def __init__(self):
        self.identity_api = core.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(User, self).__init__()

    def get_user(self, context, user_id):
        self.assert_admin(context)
        return {'user': self.identity_api.get_user(context, user_id)}

    def get_users(self, context):
        # NOTE(termie): i can't imagine that this really wants all the data
        #               about every single user in the system...
        if 'name' in context['query_string']:
            return self.get_user_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        return {'users': self.identity_api.list_users(context)}

    def get_user_by_name(self, context, user_name):
        self.assert_admin(context)
        return {'user': self.identity_api.get_user_by_name(context, user_name)}

    # CRUD extension
    def create_user(self, context, user):
        user = self._normalize_dict(user)
        self.assert_admin(context)

        if not 'name' in user or not user['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        tenant_id = user.get('tenantId', None)
        if (tenant_id is not None
                and self.identity_api.get_tenant(context, tenant_id) is None):
            raise exception.TenantNotFound(tenant_id=tenant_id)
        user_id = uuid.uuid4().hex
        user_ref = user.copy()
        user_ref['id'] = user_id
        new_user_ref = self.identity_api.create_user(
            context, user_id, user_ref)
        if tenant_id:
            self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        return {'user': new_user_ref}

    def update_user(self, context, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        self.assert_admin(context)
        user_ref = self.identity_api.update_user(context, user_id, user)

        # If the password was changed or the user was disabled we clear tokens
        if user.get('password') or not user.get('enabled', True):
            try:
                for token_id in self.token_api.list_tokens(context, user_id):
                    self.token_api.delete_token(context, token_id)
            except exception.NotImplemented:
                # The users status has been changed but tokens remain valid for
                # backends that can't list tokens for users
                LOG.warning('User %s status has changed, but existing tokens '
                            'remain valid' % user_id)
        return {'user': user_ref}

    def delete_user(self, context, user_id):
        self.assert_admin(context)
        self.identity_api.delete_user(context, user_id)

    def set_user_enabled(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def set_user_password(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def update_user_tenant(self, context, user_id, user):
        """Update the default tenant."""
        self.assert_admin(context)
        # ensure that we're a member of that tenant
        tenant_id = user.get('tenantId')
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        return self.update_user(context, user_id, user)


class Role(wsgi.Application):
    def __init__(self):
        self.identity_api = core.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(Role, self).__init__()

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

        roles = self.identity_api.get_roles_for_user_and_tenant(
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

        if not 'name' in role or not role['name']:
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

        # This still has the weird legacy semantics that adding a role to
        # a user also adds them to a tenant
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        self.identity_api.add_role_to_user_and_tenant(
            context, user_id, tenant_id, role_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)

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
        self.identity_api.remove_role_from_user_and_tenant(
            context, user_id, tenant_id, role_id)
        roles = self.identity_api.get_roles_for_user_and_tenant(
            context, user_id, tenant_id)
        if not roles:
            self.identity_api.remove_user_from_tenant(
                context, tenant_id, user_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)

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
        tenant_ids = self.identity_api.get_tenants_for_user(context, user_id)
        o = []
        for tenant_id in tenant_ids:
            role_ids = self.identity_api.get_roles_for_user_and_tenant(
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
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        self.identity_api.add_role_to_user_and_tenant(
            context, user_id, tenant_id, role_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)

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
        self.identity_api.remove_role_from_user_and_tenant(
            context, user_id, tenant_id, role_id)
        roles = self.identity_api.get_roles_for_user_and_tenant(
            context, user_id, tenant_id)
        if not roles:
            self.identity_api.remove_user_from_tenant(
                context, tenant_id, user_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)


class DomainV3(controller.V3Controller):
    @controller.protected
    def create_domain(self, context, domain):
        ref = self._assign_unique_id(self._normalize_dict(domain))
        ref = self.identity_api.create_domain(context, ref['id'], ref)
        return {'domain': ref}

    @controller.protected
    def list_domains(self, context):
        refs = self.identity_api.list_domains(context)
        return {'domains': self._paginate(context, refs)}

    @controller.protected
    def get_domain(self, context, domain_id):
        ref = self.identity_api.get_domain(context, domain_id)
        return {'domain': ref}

    @controller.protected
    def update_domain(self, context, domain_id, domain):
        self._require_matching_id(domain_id, domain)

        ref = self.identity_api.update_domain(context, domain_id, domain)
        return {'domain': ref}

    @controller.protected
    def delete_domain(self, context, domain_id):
        return self.identity_api.delete_domain(context, domain_id)


class ProjectV3(controller.V3Controller):
    @controller.protected
    def create_project(self, context, project):
        ref = self._assign_unique_id(self._normalize_dict(project))
        ref = self.identity_api.create_project(context, ref['id'], ref)
        return {'project': ref}

    @controller.protected
    def list_projects(self, context):
        refs = self.identity_api.list_projects(context)
        return {'projects': self._paginate(context, refs)}

    @controller.protected
    def list_user_projects(self, context, user_id):
        refs = self.identity_api.list_user_projects(context, user_id)
        return {'projects': self._paginate(context, refs)}

    @controller.protected
    def get_project(self, context, project_id):
        ref = self.identity_api.get_project(context, project_id)
        return {'project': ref}

    @controller.protected
    def update_project(self, context, project_id, project):
        self._require_matching_id(project_id, project)

        ref = self.identity_api.update_project(context, project_id, project)
        return {'project': ref}

    @controller.protected
    def delete_project(self, context, project_id):
        return self.identity_api.delete_project(context, project_id)


class UserV3(controller.V3Controller):
    @controller.protected
    def create_user(self, context, user):
        ref = self._assign_unique_id(self._normalize_dict(user))
        ref = self.identity_api.create_user(context, ref['id'], ref)
        return {'user': ref}

    @controller.protected
    def list_users(self, context):
        refs = self.identity_api.list_users(context)
        return {'users': self._paginate(context, refs)}

    @controller.protected
    def get_user(self, context, user_id):
        ref = self.identity_api.get_user(context, user_id)
        return {'user': ref}

    @controller.protected
    def update_user(self, context, user_id, user):
        self._require_matching_id(user_id, user)

        ref = self.identity_api.update_user(context, user_id, user)
        return {'user': ref}

    @controller.protected
    def delete_user(self, context, user_id):
        return self.identity_api.delete_user(context, user_id)


class CredentialV3(controller.V3Controller):
    @controller.protected
    def create_credential(self, context, credential):
        ref = self._assign_unique_id(self._normalize_dict(credential))
        ref = self.identity_api.create_credential(context, ref['id'], ref)
        return {'credential': ref}

    @controller.protected
    def list_credentials(self, context):
        refs = self.identity_api.list_credentials(context)
        return {'credentials': self._paginate(context, refs)}

    @controller.protected
    def get_credential(self, context, credential_id):
        ref = self.identity_api.get_credential(context, credential_id)
        return {'credential': ref}

    @controller.protected
    def update_credential(self, context, credential_id, credential):
        self._require_matching_id(credential_id, credential)

        ref = self.identity_api.update_credential(
            context,
            credential_id,
            credential)
        return {'credential': ref}

    @controller.protected
    def delete_credential(self, context, credential_id):
        return self.identity_api.delete_credential(context, credential_id)


class RoleV3(controller.V3Controller):
    @controller.protected
    def create_role(self, context, role):
        ref = self._assign_unique_id(self._normalize_dict(role))
        ref = self.identity_api.create_role(context, ref['id'], ref)
        return {'role': ref}

    @controller.protected
    def list_roles(self, context):
        refs = self.identity_api.list_roles(context)
        return {'roles': self._paginate(context, refs)}

    @controller.protected
    def get_role(self, context, role_id):
        ref = self.identity_api.get_role(context, role_id)
        return {'role': ref}

    @controller.protected
    def update_role(self, context, role_id, role):
        self._require_matching_id(role_id, role)

        ref = self.identity_api.update_role(context, role_id, role)
        return {'role': ref}

    @controller.protected
    def delete_role(self, context, role_id):
        return self.identity_api.delete_role(context, role_id)

    def _require_domain_or_project(self, domain_id, project_id):
        if (domain_id and project_id) or (not domain_id and not project_id):
            msg = 'Specify a domain or project, not both'
            raise exception.ValidationError(msg)

    @controller.protected
    def create_grant(self, context, role_id, user_id, domain_id=None,
                     project_id=None):
        """Grants a role to a user on either a domain or project."""
        self._require_domain_or_project(domain_id, project_id)

        return self.identity_api.create_grant(
            context, role_id, user_id, domain_id, project_id)

    @controller.protected
    def list_grants(self, context, user_id, domain_id=None,
                    project_id=None):
        """Lists roles granted to a user on either a domain or project."""
        self._require_domain_or_project(domain_id, project_id)

        return self.identity_api.list_grants(
            context, user_id, domain_id, project_id)

    @controller.protected
    def check_grant(self, context, role_id, user_id, domain_id=None,
                    project_id=None):
        """Checks if a role has been granted on either a domain or project."""
        self._require_domain_or_project(domain_id, project_id)

        self.identity_api.get_grant(
            context, role_id, user_id, domain_id, project_id)

    @controller.protected
    def revoke_grant(self, context, role_id, user_id, domain_id=None,
                     project_id=None):
        """Revokes a role from a user on either a domain or project."""
        self._require_domain_or_project(domain_id, project_id)

        self.identity_api.delete_grant(
            context, role_id, user_id, domain_id, project_id)
