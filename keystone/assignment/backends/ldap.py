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

import ldap.filter
from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils

from keystone import assignment
from keystone.assignment.role_backends import ldap as ldap_role
from keystone.common import ldap as common_ldap
from keystone.common import models
from keystone import exception
from keystone.i18n import _
from keystone.identity.backends import ldap as ldap_identity


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Assignment(assignment.AssignmentDriverV8):
    @versionutils.deprecated(
        versionutils.deprecated.KILO,
        remove_in=+2,
        what='ldap assignment')
    def __init__(self):
        super(Assignment, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        # This is the only deep dependency from assignment back to identity.
        # This is safe to do since if you are using LDAP for assignment, it is
        # required that you are using it for identity as well.
        self.user = ldap_identity.UserApi(CONF)
        self.group = ldap_identity.GroupApi(CONF)

        self.project = ProjectApi(CONF)
        self.role = RoleApi(CONF, self.user)

    def default_role_driver(self):
        return 'ldap'

    def default_resource_driver(self):
        return 'ldap'

    def list_role_ids_for_groups_on_project(
            self, groups, project_id, project_domain_id, project_parents):
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
            user_dn = self.user._id_to_dn(user_id)
            return [self.role._dn_to_id(a.role_dn)
                    for a in self.role.get_role_assignments
                    (self.project._id_to_dn(tenant_id))
                    if common_ldap.is_dn_equal(a.user_dn, user_dn)]

        def _get_roles_for_group_and_project(group_id, project_id):
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

    def list_project_ids_for_user(self, user_id, group_ids, hints,
                                  inherited=False):
        # TODO(henry-nash): The ldap driver does not support inherited
        # assignments, so the inherited parameter is unused.
        # See bug #1404273.
        user_dn = self.user._id_to_dn(user_id)
        associations = (self.role.list_project_roles_for_user
                        (user_dn, self.project.tree_dn))

        for group_id in group_ids:
            group_dn = self.group._id_to_dn(group_id)
            for group_role in self.role.list_project_roles_for_group(
                    group_dn, self.project.tree_dn):
                associations.append(group_role)

        return list(set(
            [self.project._dn_to_id(x.project_dn) for x in associations]))

    def list_role_ids_for_groups_on_domain(self, group_ids, domain_id):
        raise exception.NotImplemented()

    def list_project_ids_for_groups(self, group_ids, hints,
                                    inherited=False):
        raise exception.NotImplemented()

    def list_domain_ids_for_user(self, user_id, group_ids, hints):
        raise exception.NotImplemented()

    def list_domain_ids_for_groups(self, group_ids, inherited=False):
        raise exception.NotImplemented()

    def list_user_ids_for_project(self, tenant_id):
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
        user_dn = self.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        self.role.add_user(role_id, role_dn, user_dn, user_id, tenant_id)
        tenant_dn = self.project._id_to_dn(tenant_id)
        return UserRoleAssociation(role_dn=role_dn,
                                   user_dn=user_dn,
                                   tenant_dn=tenant_dn)

    def _add_role_to_group_and_project(self, group_id, tenant_id, role_id):
        group_dn = self.group._id_to_dn(group_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        self.role.add_user(role_id, role_dn, group_dn, group_id, tenant_id)
        tenant_dn = self.project._id_to_dn(tenant_id)
        return GroupRoleAssociation(group_dn=group_dn,
                                    role_dn=role_dn,
                                    tenant_dn=tenant_dn)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        return self.role.delete_user(role_dn,
                                     self.user._id_to_dn(user_id), role_id)

    def _remove_role_from_group_and_project(self, group_id, tenant_id,
                                            role_id):
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        return self.role.delete_user(role_dn,
                                     self.group._id_to_dn(group_id), role_id)

# Bulk actions on User From identity
    def delete_user_assignments(self, user_id):
        user_dn = self.user._id_to_dn(user_id)
        for ref in self.role.list_global_roles_for_user(user_dn):
            self.role.delete_user(ref.role_dn, ref.user_dn,
                                  self.role._dn_to_id(ref.role_dn))
        for ref in self.role.list_project_roles_for_user(user_dn,
                                                         self.project.tree_dn):
            self.role.delete_user(ref.role_dn, ref.user_dn,
                                  self.role._dn_to_id(ref.role_dn))

    def delete_group_assignments(self, group_id):
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

    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}
        role_ids = set(self._roles_from_role_dicts(
            metadata_ref.get('roles', []), inherited_to_projects))
        if role_id not in role_ids:
            actor_id = user_id or group_id
            target_id = domain_id or project_id
            raise exception.RoleAssignmentNotFound(role_id=role_id,
                                                   actor_id=actor_id,
                                                   target_id=target_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):

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
        except (exception.RoleNotFound, KeyError):
            actor_id = user_id or group_id
            target_id = domain_id or project_id
            raise exception.RoleAssignmentNotFound(role_id=role_id,
                                                   actor_id=actor_id,
                                                   target_id=target_id)

    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        return self._roles_from_role_dicts(metadata_ref.get('roles', []),
                                           inherited_to_projects)

    def list_role_assignments(self, role_id=None,
                              user_id=None, group_ids=None,
                              domain_id=None, project_ids=None,
                              inherited_to_projects=None):
        role_assignments = []

        # Since the LDAP backend does not support assignments to domains, if
        # the request is to filter by domain, then the answer is guaranteed
        # to be an empty list.
        if not domain_id:
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

                if role_id and assignment['role_id'] != role_id:
                    continue
                if user_id and assignment.get('user_id') != user_id:
                    continue
                if group_ids and assignment.get('group_id') not in group_ids:
                    continue
                if project_ids and assignment['project_id'] not in project_ids:
                    continue

                role_assignments.append(assignment)

        return role_assignments

    def delete_project_assignments(self, project_id):
        tenant_dn = self.project._id_to_dn(project_id)
        self.role.roles_delete_subtree_by_project(tenant_dn)

    def delete_role_assignments(self, role_id):
        self.role.roles_delete_subtree_by_role(role_id, self.project.tree_dn)


# TODO(termie): turn this into a data object and move logic to driver
class ProjectApi(common_ldap.ProjectLdapStructureMixin,
                 common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):

    model = models.Project

    def __init__(self, conf):
        super(ProjectApi, self).__init__(conf)
        self.member_attribute = (conf.ldap.project_member_attribute
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)

    def get_user_projects(self, user_dn, associations):
        """Returns the list of tenants to which a user has access."""
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
# NOTE(heny-nash): The RoleLdapStructureMixin class enables the sharing of the
# LDAP structure between here and the role backend LDAP, no methods are shared.
class RoleApi(ldap_role.RoleLdapStructureMixin, common_ldap.BaseLdap):

    def __init__(self, conf, user_api):
        super(RoleApi, self).__init__(conf)
        self.member_attribute = (conf.ldap.role_member_attribute
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self._user_api = user_api

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

    def roles_delete_subtree_by_role(self, role_id, tree_dn):
        self._delete_tree_nodes(tree_dn, ldap.SCOPE_SUBTREE, query_params={
            self.id_attr: role_id})

    def list_role_assignments(self, project_tree_dn):
        """List the role assignments linked to project_tree_dn attribute."""
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
