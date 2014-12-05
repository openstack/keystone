# Copyright 2012-2013 OpenStack Foundation
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
from __future__ import absolute_import

import uuid

import ldap as ldap
import ldap.filter

from keystone import assignment
from keystone import clean
from keystone.common import driver_hints
from keystone.common import ldap as common_ldap
from keystone.common import models
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone.identity.backends import ldap as ldap_identity
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)


class Assignment(assignment.Driver):
    def __init__(self):
        super(Assignment, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        # These are the only deep dependency from assignment back
        # to identity.  The assumption is that if you are using
        # LDAP for assignments, you are using it for Id as well.
        self.user = ldap_identity.UserApi(CONF)
        self.group = ldap_identity.GroupApi(CONF)

        self.project = ProjectApi(CONF)
        self.role = RoleApi(CONF, self.user)

    def _set_default_parent_project(self, ref):
        """If the parent project ID has not been set, set it to None."""
        if isinstance(ref, dict):
            if 'parent_id' not in ref:
                ref = dict(ref, parent_id=None)
            return ref
        elif isinstance(ref, list):
            return [self._set_default_parent_project(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _validate_parent_project_is_none(self, ref):
        """If a parent_id different from None was given,
           raises InvalidProjectException.

        """
        parent_id = ref.get('parent_id')
        if parent_id is not None:
            raise exception.InvalidParentProject(parent_id)

    def _set_default_attributes(self, project_ref):
        project_ref = self._set_default_domain(project_ref)
        return self._set_default_parent_project(project_ref)

    def get_project(self, tenant_id):
        return self._set_default_attributes(
            self.project.get(tenant_id))

    def list_projects(self, hints):
        return self._set_default_attributes(
            self.project.get_all())

    def list_projects_in_domain(self, domain_id):
        # We don't support multiple domains within this driver, so ignore
        # any domain specified
        return self.list_projects(driver_hints.Hints())

    def list_projects_in_subtree(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will never have children
        return []

    def list_project_parents(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will never have parents
        return []

    def is_leaf_project(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will always be a root and a leaf at the same time
        return True

    def get_project_by_name(self, tenant_name, domain_id):
        self._validate_default_domain_id(domain_id)
        return self._set_default_attributes(
            self.project.get_by_name(tenant_name))

    def create_project(self, tenant_id, tenant):
        self.project.check_allow_create()
        tenant = self._validate_default_domain(tenant)
        self._validate_parent_project_is_none(tenant)
        tenant['name'] = clean.project_name(tenant['name'])
        data = tenant.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4().hex)
        if 'description' in data and data['description'] in ['', None]:
            data.pop('description')
        return self._set_default_attributes(
            self.project.create(data))

    def update_project(self, tenant_id, tenant):
        self.project.check_allow_update()
        tenant = self._validate_default_domain(tenant)
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])
        return self._set_default_attributes(
            self.project.update(tenant_id, tenant))

    def get_group_project_roles(self, groups, project_id, project_domain_id):
        self.get_project(project_id)
        group_dns = [self.group._id_to_dn(group_id) for group_id in groups]
        role_list = [self.role._dn_to_id(role_assignment.role_dn)
                     for role_assignment in self.role.get_role_assignments
                     (self.project._id_to_dn(project_id))
                     if role_assignment.user_dn.upper() in group_dns]
        # NOTE(morganfainberg): Does not support OS-INHERIT as domain
        # metadata/roles are not supported by LDAP backend. Skip OS-INHERIT
        # logic.
        return role_list

    def _get_metadata(self, user_id=None, tenant_id=None,
                      domain_id=None, group_id=None):

        def _get_roles_for_just_user_and_project(user_id, tenant_id):
            self.get_project(tenant_id)
            user_dn = self.user._id_to_dn(user_id)
            return [self.role._dn_to_id(a.role_dn)
                    for a in self.role.get_role_assignments
                    (self.project._id_to_dn(tenant_id))
                    if common_ldap.is_dn_equal(a.user_dn, user_dn)]

        def _get_roles_for_group_and_project(group_id, project_id):
            self.get_project(project_id)
            group_dn = self.group._id_to_dn(group_id)
            return [self.role._dn_to_id(a.role_dn)
                    for a in self.role.get_role_assignments
                    (self.project._id_to_dn(project_id))
                    if common_ldap.is_dn_equal(a.user_dn, group_dn)]

        if domain_id is not None:
            msg = _('Domain metadata not supported by LDAP')
            raise exception.NotImplemented(message=msg)
        if group_id is None and user_id is None:
            return {}

        if tenant_id is None:
            return {}
        if user_id is None:
            metadata_ref = _get_roles_for_group_and_project(group_id,
                                                            tenant_id)
        else:
            metadata_ref = _get_roles_for_just_user_and_project(user_id,
                                                                tenant_id)
        if not metadata_ref:
            return {}
        return {'roles': [self._role_to_dict(r, False) for r in metadata_ref]}

    def get_role(self, role_id):
        return self.role.get(role_id)

    def list_roles(self, hints):
        return self.role.get_all()

    def list_projects_for_user(self, user_id, group_ids, hints):
        user_dn = self.user._id_to_dn(user_id)
        associations = (self.role.list_project_roles_for_user
                        (user_dn, self.project.tree_dn))

        for group_id in group_ids:
            group_dn = self.group._id_to_dn(group_id)
            for group_role in self.role.list_project_roles_for_group(
                    group_dn, self.project.tree_dn):
                associations.append(group_role)

        # Since the LDAP backend doesn't store the domain_id in the LDAP
        # records (and only supports the default domain), we fill in the
        # domain_id before we return the list.
        return [self._set_default_attributes(x) for x in
                self.project.get_user_projects(user_dn, associations)]

    def get_roles_for_groups(self, group_ids, project_id=None, domain_id=None):
        raise exception.NotImplemented()

    def list_projects_for_groups(self, group_ids):
        raise exception.NotImplemented()

    def list_domains_for_user(self, user_id, group_ids, hints):
        raise exception.NotImplemented()

    def list_domains_for_groups(self, group_ids):
        raise exception.NotImplemented()

    def list_user_ids_for_project(self, tenant_id):
        self.get_project(tenant_id)
        tenant_dn = self.project._id_to_dn(tenant_id)
        rolegrants = self.role.get_role_assignments(tenant_dn)
        return [self.user._dn_to_id(user_dn) for user_dn in
                self.project.get_user_dns(tenant_id, rolegrants)]

    def _subrole_id_to_dn(self, role_id, tenant_id):
        if tenant_id is None:
            return self.role._id_to_dn(role_id)
        else:
            return '%s=%s,%s' % (self.role.id_attr,
                                 ldap.dn.escape_dn_chars(role_id),
                                 self.project._id_to_dn(tenant_id))

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.get_project(tenant_id)
        self.get_role(role_id)
        user_dn = self.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        self.role.add_user(role_id, role_dn, user_dn, user_id, tenant_id)
        tenant_dn = self.project._id_to_dn(tenant_id)
        return UserRoleAssociation(role_dn=role_dn,
                                   user_dn=user_dn,
                                   tenant_dn=tenant_dn)

    def _add_role_to_group_and_project(self, group_id, tenant_id, role_id):
        self.get_project(tenant_id)
        self.get_role(role_id)
        group_dn = self.group._id_to_dn(group_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        self.role.add_user(role_id, role_dn, group_dn, group_id, tenant_id)
        tenant_dn = self.project._id_to_dn(tenant_id)
        return GroupRoleAssociation(group_dn=group_dn,
                                    role_dn=role_dn,
                                    tenant_dn=tenant_dn)

    def create_role(self, role_id, role):
        self.role.check_allow_create()
        try:
            self.get_role(role_id)
        except exception.NotFound:
            pass
        else:
            msg = _('Duplicate ID, %s.') % role_id
            raise exception.Conflict(type='role', details=msg)

        try:
            self.role.get_by_name(role['name'])
        except exception.NotFound:
            pass
        else:
            msg = _('Duplicate name, %s.') % role['name']
            raise exception.Conflict(type='role', details=msg)

        return self.role.create(role)

    def delete_role(self, role_id):
        self.role.check_allow_delete()
        return self.role.delete(role_id, self.project.tree_dn)

    def delete_project(self, tenant_id):
        self.project.check_allow_delete()
        if self.project.subtree_delete_enabled:
            self.project.deleteTree(tenant_id)
        else:
            tenant_dn = self.project._id_to_dn(tenant_id)
            self.role.roles_delete_subtree_by_project(tenant_dn)
            self.project.delete(tenant_id)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        return self.role.delete_user(role_dn,
                                     self.user._id_to_dn(user_id), role_id)

    def _remove_role_from_group_and_project(self, group_id, tenant_id,
                                            role_id):
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        return self.role.delete_user(role_dn,
                                     self.group._id_to_dn(group_id), role_id)

    def update_role(self, role_id, role):
        self.role.check_allow_update()
        self.get_role(role_id)
        return self.role.update(role_id, role)

    def create_domain(self, domain_id, domain):
        if domain_id == CONF.identity.default_domain_id:
            msg = _('Duplicate ID, %s.') % domain_id
            raise exception.Conflict(type='domain', details=msg)
        raise exception.Forbidden(_('Domains are read-only against LDAP'))

    def get_domain(self, domain_id):
        self._validate_default_domain_id(domain_id)
        return assignment.calc_default_domain()

    def update_domain(self, domain_id, domain):
        self._validate_default_domain_id(domain_id)
        raise exception.Forbidden(_('Domains are read-only against LDAP'))

    def delete_domain(self, domain_id):
        self._validate_default_domain_id(domain_id)
        raise exception.Forbidden(_('Domains are read-only against LDAP'))

    def list_domains(self, hints):
        return [assignment.calc_default_domain()]

# Bulk actions on User From identity
    def delete_user(self, user_id):
        user_dn = self.user._id_to_dn(user_id)
        for ref in self.role.list_global_roles_for_user(user_dn):
            self.role.delete_user(ref.role_dn, ref.user_dn,
                                  self.role._dn_to_id(ref.role_dn))
        for ref in self.role.list_project_roles_for_user(user_dn,
                                                         self.project.tree_dn):
            self.role.delete_user(ref.role_dn, ref.user_dn,
                                  self.role._dn_to_id(ref.role_dn))

    def delete_group(self, group_id):
        """Called when the group was deleted.

        Any role assignments for the group should be cleaned up.

        """
        group_dn = self.group._id_to_dn(group_id)
        group_role_assignments = self.role.list_project_roles_for_group(
            group_dn, self.project.tree_dn)
        for ref in group_role_assignments:
            self.role.delete_user(ref.role_dn, ref.group_dn,
                                  self.role._dn_to_id(ref.role_dn))

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        self.get_role(role_id)

        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        if project_id and inherited_to_projects:
            msg = _('Inherited roles can only be assigned to domains')
            raise exception.Conflict(type='role grant', details=msg)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        if user_id is None:
            metadata_ref['roles'] = self._add_role_to_group_and_project(
                group_id, project_id, role_id)
        else:
            metadata_ref['roles'] = self.add_role_to_user_and_project(
                user_id, project_id, role_id)

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        role_ref = self.get_role(role_id)

        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}
        role_ids = set(self._roles_from_role_dicts(
            metadata_ref.get('roles', []), inherited_to_projects))
        if role_id not in role_ids:
            raise exception.RoleNotFound(role_id=role_id)
        return role_ref

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        self.get_role(role_id)

        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        try:
            if user_id is None:
                metadata_ref['roles'] = (
                    self._remove_role_from_group_and_project(
                        group_id, project_id, role_id))
            else:
                metadata_ref['roles'] = self.remove_role_from_user_and_project(
                    user_id, project_id, role_id)
        except KeyError:
            raise exception.RoleNotFound(role_id=role_id)

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        return [self.get_role(role_id) for role_id in
                self._roles_from_role_dicts(metadata_ref.get('roles', []),
                                            inherited_to_projects)]

    def get_domain_by_name(self, domain_name):
        default_domain = assignment.calc_default_domain()
        if domain_name != default_domain['name']:
            raise exception.DomainNotFound(domain_id=domain_name)
        return default_domain

    def list_role_assignments(self):
        role_assignments = []
        for a in self.role.list_role_assignments(self.project.tree_dn):
            if isinstance(a, UserRoleAssociation):
                assignment = {
                    'role_id': self.role._dn_to_id(a.role_dn),
                    'user_id': self.user._dn_to_id(a.user_dn),
                    'project_id': self.project._dn_to_id(a.project_dn)}
            else:
                assignment = {
                    'role_id': self.role._dn_to_id(a.role_dn),
                    'group_id': self.group._dn_to_id(a.group_dn),
                    'project_id': self.project._dn_to_id(a.project_dn)}
            role_assignments.append(assignment)
        return role_assignments


# TODO(termie): turn this into a data object and move logic to driver
class ProjectApi(common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Groups'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'groupOfNames'
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_MEMBER_ATTRIBUTE = 'member'
    NotFound = exception.ProjectNotFound
    notfound_arg = 'project_id'  # NOTE(yorik-sar): while options_name = tenant
    options_name = 'project'
    attribute_options_names = {'name': 'name',
                               'description': 'desc',
                               'enabled': 'enabled',
                               'domain_id': 'domain_id'}
    immutable_attrs = ['name']
    model = models.Project

    def __init__(self, conf):
        super(ProjectApi, self).__init__(conf)
        self.member_attribute = (getattr(conf.ldap, 'project_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)

    def create(self, values):
        data = values.copy()
        if data.get('id') is None:
            data['id'] = uuid.uuid4().hex
        return super(ProjectApi, self).create(data)

    def get_user_projects(self, user_dn, associations):
        """Returns list of tenants a user has access to
        """

        project_ids = set()
        for assoc in associations:
            project_ids.add(self._dn_to_id(assoc.project_dn))
        projects = []
        for project_id in project_ids:
            # slower to get them one at a time, but a huge list could blow out
            # the connection.  This is the safer way
            projects.append(self.get(project_id))
        return projects

    def get_user_dns(self, tenant_id, rolegrants, role_dn=None):
        tenant = self._ldap_get(tenant_id)
        res = set()
        if not role_dn:
            # Get users who have default tenant mapping
            for user_dn in tenant[1].get(self.member_attribute, []):
                if self._is_dumb_member(user_dn):
                    continue
                res.add(user_dn)

        # Get users who are explicitly mapped via a tenant
        for rolegrant in rolegrants:
            if role_dn is None or rolegrant.role_dn == role_dn:
                res.add(rolegrant.user_dn)
        return list(res)

    def update(self, project_id, values):
        old_obj = self.get(project_id)
        return super(ProjectApi, self).update(project_id, values, old_obj)


class UserRoleAssociation(object):
    """Role Grant model."""

    def __init__(self, user_dn=None, role_dn=None, tenant_dn=None,
                 *args, **kw):
        self.user_dn = user_dn
        self.role_dn = role_dn
        self.project_dn = tenant_dn


class GroupRoleAssociation(object):
    """Role Grant model."""

    def __init__(self, group_dn=None, role_dn=None, tenant_dn=None,
                 *args, **kw):
        self.group_dn = group_dn
        self.role_dn = role_dn
        self.project_dn = tenant_dn


# TODO(termie): turn this into a data object and move logic to driver
class RoleApi(common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Roles'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'organizationalRole'
    DEFAULT_MEMBER_ATTRIBUTE = 'roleOccupant'
    NotFound = exception.RoleNotFound
    options_name = 'role'
    attribute_options_names = {'name': 'name'}
    immutable_attrs = ['id']
    model = models.Role

    def __init__(self, conf, user_api):
        super(RoleApi, self).__init__(conf)
        self.member_attribute = (getattr(conf.ldap, 'role_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self._user_api = user_api

    def get(self, role_id, role_filter=None):
        model = super(RoleApi, self).get(role_id, role_filter)
        return model

    def create(self, values):
        return super(RoleApi, self).create(values)

    def add_user(self, role_id, role_dn, user_dn, user_id, tenant_id=None):
        try:
            super(RoleApi, self).add_member(user_dn, role_dn)
        except exception.Conflict:
            msg = (_('User %(user_id)s already has role %(role_id)s in '
                     'tenant %(tenant_id)s') %
                   dict(user_id=user_id, role_id=role_id, tenant_id=tenant_id))
            raise exception.Conflict(type='role grant', details=msg)
        except self.NotFound:
            if tenant_id is None or self.get(role_id) is None:
                raise Exception(_("Role %s not found") % (role_id,))

            attrs = [('objectClass', [self.object_class]),
                     (self.member_attribute, [user_dn]),
                     (self.id_attr, [role_id])]

            if self.use_dumb_member:
                attrs[1][1].append(self.dumb_member)
            with self.get_connection() as conn:
                conn.add_s(role_dn, attrs)

    def delete_user(self, role_dn, user_dn, role_id):
        try:
            super(RoleApi, self).remove_member(user_dn, role_dn)
        except (self.NotFound, ldap.NO_SUCH_ATTRIBUTE):
            raise exception.RoleNotFound(message=_(
                'Cannot remove role that has not been granted, %s') %
                role_id)

    def get_role_assignments(self, tenant_dn):
        try:
            roles = self._ldap_get_list(tenant_dn, ldap.SCOPE_ONELEVEL,
                                        attrlist=[self.member_attribute])
        except ldap.NO_SUCH_OBJECT:
            roles = []
        res = []
        for role_dn, attrs in roles:
            try:
                user_dns = attrs[self.member_attribute]
            except KeyError:
                continue
            for user_dn in user_dns:
                if self._is_dumb_member(user_dn):
                    continue
                res.append(UserRoleAssociation(
                    user_dn=user_dn,
                    role_dn=role_dn,
                    tenant_dn=tenant_dn))

        return res

    def list_global_roles_for_user(self, user_dn):
        user_dn_esc = ldap.filter.escape_filter_chars(user_dn)
        roles = self.get_all('(%s=%s)' % (self.member_attribute, user_dn_esc))
        return [UserRoleAssociation(
                role_dn=role.dn,
                user_dn=user_dn) for role in roles]

    def list_project_roles_for_user(self, user_dn, project_subtree):
        try:
            roles = self._ldap_get_list(project_subtree, ldap.SCOPE_SUBTREE,
                                        query_params={
                                            self.member_attribute: user_dn},
                                        attrlist=common_ldap.DN_ONLY)
        except ldap.NO_SUCH_OBJECT:
            roles = []
        res = []
        for role_dn, _role_attrs in roles:
            # ldap.dn.dn2str returns an array, where the first
            # element is the first segment.
            # For a role assignment, this contains the role ID,
            # The remainder is the DN of the tenant.
            # role_dn is already utf8 encoded since it came from LDAP.
            tenant = ldap.dn.str2dn(role_dn)
            tenant.pop(0)
            tenant_dn = ldap.dn.dn2str(tenant)
            res.append(UserRoleAssociation(
                user_dn=user_dn,
                role_dn=role_dn,
                tenant_dn=tenant_dn))
        return res

    def list_project_roles_for_group(self, group_dn, project_subtree):
        group_dn_esc = ldap.filter.escape_filter_chars(group_dn)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,
                                                group_dn_esc)
        with self.get_connection() as conn:
            try:
                roles = conn.search_s(project_subtree,
                                      ldap.SCOPE_SUBTREE,
                                      query,
                                      attrlist=common_ldap.DN_ONLY)
            except ldap.NO_SUCH_OBJECT:
                # Return no roles rather than raise an exception if the project
                # subtree entry doesn't exist because an empty subtree is not
                # an error.
                return []

        res = []
        for role_dn, _role_attrs in roles:
            # ldap.dn.str2dn returns a list, where the first
            # element is the first RDN.
            # For a role assignment, this contains the role ID,
            # the remainder is the DN of the project.
            # role_dn is already utf8 encoded since it came from LDAP.
            project = ldap.dn.str2dn(role_dn)
            project.pop(0)
            project_dn = ldap.dn.dn2str(project)
            res.append(GroupRoleAssociation(
                group_dn=group_dn,
                role_dn=role_dn,
                tenant_dn=project_dn))
        return res

    def roles_delete_subtree_by_project(self, tenant_dn):
        self._delete_tree_nodes(tenant_dn, ldap.SCOPE_ONELEVEL)

    def update(self, role_id, role):
        try:
            old_name = self.get_by_name(role['name'])
            raise exception.Conflict(_('Cannot duplicate name %s') % old_name)
        except exception.NotFound:
            pass
        return super(RoleApi, self).update(role_id, role)

    def delete(self, role_id, tenant_dn):
        self._delete_tree_nodes(tenant_dn, ldap.SCOPE_SUBTREE, query_params={
            self.id_attr: role_id})
        super(RoleApi, self).delete(role_id)

    def list_role_assignments(self, project_tree_dn):
        """Returns a list of all the role assignments linked to project_tree_dn
        attribute.
        """
        try:
            roles = self._ldap_get_list(project_tree_dn, ldap.SCOPE_SUBTREE,
                                        attrlist=[self.member_attribute])
        except ldap.NO_SUCH_OBJECT:
            roles = []
        res = []
        for role_dn, role in roles:
            # role_dn is already utf8 encoded since it came from LDAP.
            tenant = ldap.dn.str2dn(role_dn)
            tenant.pop(0)
            # It obtains the tenant DN to construct the UserRoleAssociation
            # object.
            tenant_dn = ldap.dn.dn2str(tenant)
            for occupant_dn in role[self.member_attribute]:
                if self._is_dumb_member(occupant_dn):
                    continue
                if self._user_api.is_user(occupant_dn):
                    association = UserRoleAssociation(
                        user_dn=occupant_dn,
                        role_dn=role_dn,
                        tenant_dn=tenant_dn)
                else:
                    # occupant_dn is a group.
                    association = GroupRoleAssociation(
                        group_dn=occupant_dn,
                        role_dn=role_dn,
                        tenant_dn=tenant_dn)
                res.append(association)
        return res
