# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012-2013 OpenStack LLC
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

from keystone import assignment
from keystone import clean
from keystone.common import dependency
from keystone.common import ldap as common_ldap
from keystone.common import models
from keystone import config
from keystone import exception
from keystone.identity.backends import ldap as ldap_identity
from keystone.openstack.common import log as logging


CONF = config.CONF
LOG = logging.getLogger(__name__)

DEFAULT_DOMAIN = {
    'id': CONF.identity.default_domain_id,
    'name': 'Default',
    'enabled': True
}


@dependency.requires('identity_api')
class Assignment(assignment.Driver):
    def __init__(self):
        super(Assignment, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        #These are the only deep dependency from assignment back
        #to identity.  The assumption is that if you are using
        #LDAP for assignments, you are using it for Id as well.
        self.user = ldap_identity.UserApi(CONF)
        self.group = ldap_identity.GroupApi(CONF)

        self.project = ProjectApi(CONF)
        self.role = RoleApi(CONF)
        self._identity_api = None

    def get_project(self, tenant_id):
        return self._set_default_domain(self.project.get(tenant_id))

    def list_projects(self, domain_id=None):
        # We don't support multiple domains within this driver, so ignore
        # any domain passed.
        return self._set_default_domain(self.project.get_all())

    def get_project_by_name(self, tenant_name, domain_id):
        self._validate_default_domain_id(domain_id)
        return self._set_default_domain(self.project.get_by_name(tenant_name))

    def create_project(self, tenant_id, tenant):
        tenant = self._validate_default_domain(tenant)
        tenant['name'] = clean.project_name(tenant['name'])
        data = tenant.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4().hex)
        if 'description' in data and data['description'] in ['', None]:
            data.pop('description')
        return self._set_default_domain(self.project.create(data))

    def update_project(self, tenant_id, tenant):
        tenant = self._validate_default_domain(tenant)
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])
        return self._set_default_domain(self.project.update(tenant_id, tenant))

    def _get_metadata(self, user_id=None, tenant_id=None,
                      domain_id=None, group_id=None):

        def _get_roles_for_just_user_and_project(user_id, tenant_id):
            self.identity_api.get_user(user_id)
            self.get_project(tenant_id)
            return [self.role._dn_to_id(a.role_dn)
                    for a in self.role.get_role_assignments
                    (self.project._id_to_dn(tenant_id))
                    if self.user._dn_to_id(a.user_dn) == user_id]

        if domain_id is not None:
            msg = 'Domain metadata not supported by LDAP'
            raise exception.NotImplemented(message=msg)
        if tenant_id is None or user_id is None:
            return {}

        metadata_ref = _get_roles_for_just_user_and_project(user_id, tenant_id)
        if not metadata_ref:
            return {}
        return {'roles': [self._role_to_dict(r, False) for r in metadata_ref]}

    def get_role(self, role_id):
        return self.role.get(role_id)

    def list_roles(self):
        return self.role.get_all()

    def get_projects_for_user(self, user_id):
        self.identity_api.get_user(user_id)
        user_dn = self.user._id_to_dn(user_id)
        associations = (self.role.list_project_roles_for_user
                        (user_dn, self.project.tree_dn))
        return [p['id'] for p in
                self.project.get_user_projects(user_dn, associations)]

    def get_project_users(self, tenant_id):
        self.get_project(tenant_id)
        tenant_dn = self.project._id_to_dn(tenant_id)
        rolegrants = self.role.get_role_assignments(tenant_dn)
        users = [self.user.get_filtered(self.user._dn_to_id(user_id))
                 for user_id in
                 self.project.get_user_dns(tenant_id, rolegrants)]
        return self._set_default_domain(users)

    def _subrole_id_to_dn(self, role_id, tenant_id):
        if tenant_id is None:
            return self.role._id_to_dn(role_id)
        else:
            return '%s=%s,%s' % (self.role.id_attr,
                                 ldap.dn.escape_dn_chars(role_id),
                                 self.project._id_to_dn(tenant_id))

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.identity_api.get_user(user_id)
        self.get_project(tenant_id)
        self.get_role(role_id)
        user_dn = self.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        self.role.add_user(role_id, role_dn, user_dn, user_id, tenant_id)
        tenant_dn = self.project._id_to_dn(tenant_id)
        return UserRoleAssociation(
            role_dn=role_dn,
            user_dn=user_dn,
            tenant_dn=tenant_dn)

    def _create_metadata(self, user_id, tenant_id, metadata):
        return {}

    def create_role(self, role_id, role):
        try:
            self.get_role(role_id)
        except exception.NotFound:
            pass
        else:
            msg = 'Duplicate ID, %s.' % role_id
            raise exception.Conflict(type='role', details=msg)

        try:
            self.role.get_by_name(role['name'])
        except exception.NotFound:
            pass
        else:
            msg = 'Duplicate name, %s.' % role['name']
            raise exception.Conflict(type='role', details=msg)

        return self.role.create(role)

    def delete_role(self, role_id):
        return self.role.delete(role_id, self.project.tree_dn)

    def delete_project(self, tenant_id):
        if self.project.subtree_delete_enabled:
            self.project.deleteTree(id)
        else:
            tenant_dn = self.project._id_to_dn(tenant_id)
            self.role.roles_delete_subtree_by_project(tenant_dn)
            self.project.delete(tenant_id)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        return self.role.delete_user(role_dn,
                                     self.user._id_to_dn(user_id),
                                     self.project._id_to_dn(tenant_id),
                                     user_id, role_id)

    def update_role(self, role_id, role):
        self.get_role(role_id)
        self.role.update(role_id, role)

    def create_domain(self, domain_id, domain):
        if domain_id == CONF.identity.default_domain_id:
            msg = 'Duplicate ID, %s.' % domain_id
            raise exception.Conflict(type='domain', details=msg)
        raise exception.Forbidden('Domains are read-only against LDAP')

    def get_domain(self, domain_id):
        self._validate_default_domain_id(domain_id)
        return DEFAULT_DOMAIN

    def update_domain(self, domain_id, domain):
        self._validate_default_domain_id(domain_id)
        raise exception.Forbidden('Domains are read-only against LDAP')

    def delete_domain(self, domain_id):
        self._validate_default_domain_id(domain_id)
        raise exception.Forbidden('Domains are read-only against LDAP')

    def list_domains(self):
        return [assignment.DEFAULT_DOMAIN]

#Bulk actions on User From identity
    def delete_user(self, user_id):
        user_dn = self.user._id_to_dn(user_id)
        for ref in self.role.list_global_roles_for_user(user_dn):
            self.role.delete_user(ref.role_dn, ref.user_dn, ref.project_dn,
                                  user_id, self.role._dn_to_id(ref.role_dn))
        for ref in self.role.list_project_roles_for_user(user_dn,
                                                         self.project.tree_dn):
            self.role.delete_user(ref.role_dn, ref.user_dn, ref.project_dn,
                                  user_id, self.role._dn_to_id(ref.role_dn))

        user = self.user.get(user_id)
        if hasattr(user, 'tenant_id'):
            self.project.remove_user(user.tenant_id,
                                     self.user._id_to_dn(user_id))

    #LDAP assignments only supports LDAP identity.  Assignments under identity
    #are already deleted
    def delete_group(self, group_id):
        if not self.group.subtree_delete_enabled:
            # TODO(spzala): this is only placeholder for group and domain
            # role support which will be added under bug 1101287
            conn = self.group.get_connection()
            query = '(objectClass=%s)' % self.group.object_class
            dn = None
            dn = self.group._id_to_dn(id)
            if dn:
                try:
                    roles = conn.search_s(dn, ldap.SCOPE_ONELEVEL,
                                          query, ['%s' % '1.1'])
                    for role_dn, _ in roles:
                        conn.delete_s(role_dn)
                except ldap.NO_SUCH_OBJECT:
                    pass


# TODO(termie): turn this into a data object and move logic to driver
class ProjectApi(common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Groups'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'groupOfNames'
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_MEMBER_ATTRIBUTE = 'member'
    NotFound = exception.ProjectNotFound
    notfound_arg = 'project_id'  # NOTE(yorik-sar): while options_name = tenant
    options_name = 'tenant'
    attribute_options_names = {'name': 'name',
                               'description': 'desc',
                               'enabled': 'enabled',
                               'domain_id': 'domain_id'}
    immutable_attrs = ['name']
    model = models.Project

    def __init__(self, conf):
        super(ProjectApi, self).__init__(conf)
        self.member_attribute = (getattr(conf.ldap, 'tenant_member_attribute')
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
            #slower to get them one at a time, but a huge list could blow out
            #the connection.  This is the safer way
            projects.append(self.get(project_id))
        return projects

    def add_user(self, tenant_id, user_dn):
        conn = self.get_connection()
        try:
            conn.modify_s(
                self._id_to_dn(tenant_id),
                [(ldap.MOD_ADD,
                  self.member_attribute,
                  user_dn)])
        except ldap.TYPE_OR_VALUE_EXISTS:
            # As adding a user to a tenant is done implicitly in several
            # places, and is not part of the exposed API, it's easier for us to
            # just ignore this instead of raising exception.Conflict.
            pass

    def remove_user(self, tenant_id, user_dn, user_id):
        conn = self.get_connection()
        try:
            conn.modify_s(self._id_to_dn(tenant_id),
                          [(ldap.MOD_DELETE,
                            self.member_attribute,
                            user_dn)])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.NotFound(user_id)

    def get_user_dns(self, tenant_id, rolegrants, role_dn=None):
        tenant = self._ldap_get(tenant_id)
        res = set()
        if not role_dn:
            # Get users who have default tenant mapping
            for user_dn in tenant[1].get(self.member_attribute, []):
                if self.use_dumb_member and user_dn == self.dumb_member:
                    continue
                res.add(user_dn)

        # Get users who are explicitly mapped via a tenant
        for rolegrant in rolegrants:
            if role_dn is None or rolegrant.role_dn == role_dn:
                res.add(rolegrant.user_dn)
        return list(res)

    def update(self, id, values):
        old_obj = self.get(id)
        return super(ProjectApi, self).update(id, values, old_obj)


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

    def __init__(self, conf):
        super(RoleApi, self).__init__(conf)
        self.member_attribute = (getattr(conf.ldap, 'role_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)

    def get(self, id, filter=None):
        model = super(RoleApi, self).get(id, filter)
        return model

    def create(self, values):
        return super(RoleApi, self).create(values)

    def add_user(self, role_id, role_dn, user_dn, user_id, tenant_id=None):
        conn = self.get_connection()
        try:
            conn.modify_s(role_dn, [(ldap.MOD_ADD,
                                     self.member_attribute, user_dn)])
        except ldap.TYPE_OR_VALUE_EXISTS:
            msg = ('User %s already has role %s in tenant %s'
                   % (user_id, role_id, tenant_id))
            raise exception.Conflict(type='role grant', details=msg)
        except ldap.NO_SUCH_OBJECT:
            if tenant_id is None or self.get(role_id) is None:
                raise Exception(_("Role %s not found") % (role_id,))

            attrs = [('objectClass', [self.object_class]),
                     (self.member_attribute, [user_dn])]

            if self.use_dumb_member:
                attrs[1][1].append(self.dumb_member)
            try:
                conn.add_s(role_dn, attrs)
            except Exception as inst:
                    raise inst

    def delete_user(self, role_dn, user_dn, tenant_dn,
                    user_id, role_id):
        conn = self.get_connection()
        try:
            conn.modify_s(role_dn, [(ldap.MOD_DELETE,
                                     self.member_attribute, user_dn)])
        except ldap.NO_SUCH_OBJECT:
            if tenant_dn is None:
                raise exception.RoleNotFound(role_id=role_id)
            attrs = [('objectClass', [self.object_class]),
                     (self.member_attribute, [user_dn])]

            if self.use_dumb_member:
                attrs[1][1].append(self.dumb_member)
            try:
                conn.add_s(role_dn, attrs)
            except Exception as inst:
                raise inst
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.UserNotFound(user_id=user_id)

    def get_role_assignments(self, tenant_dn):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class

        try:
            roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
        except ldap.NO_SUCH_OBJECT:
            return []

        res = []
        for role_dn, attrs in roles:
            try:
                user_dns = attrs[self.member_attribute]
            except KeyError:
                continue
            for user_dn in user_dns:
                if self.use_dumb_member and user_dn == self.dumb_member:
                    continue
                res.append(UserRoleAssociation(
                    user_dn=user_dn,
                    role_dn=role_dn,
                    tenant_dn=tenant_dn))

        return res

    def list_global_roles_for_user(self, user_dn):
        roles = self.get_all('(%s=%s)' % (self.member_attribute, user_dn))
        return [UserRoleAssociation(
                role_dn=role.dn,
                user_dn=user_dn) for role in roles]

    def list_project_roles_for_user(self, user_dn, project_subtree):
        conn = self.get_connection()
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,
                                                user_dn)
        try:
            roles = conn.search_s(project_subtree,
                                  ldap.SCOPE_SUBTREE,
                                  query)
        except ldap.NO_SUCH_OBJECT:
            return []

        res = []
        for role_dn, _ in roles:
            #ldap.dn.dn2str returns an array, where the first
            #element is the first segment.
            #For a role assignment, this contains the role ID,
            #The remainder is the DN of the tenant.
            tenant = ldap.dn.str2dn(role_dn)
            tenant.pop(0)
            tenant_dn = ldap.dn.dn2str(tenant)
            res.append(UserRoleAssociation(
                user_dn=user_dn,
                role_dn=role_dn,
                tenant_dn=tenant_dn))
        return res

    def roles_delete_subtree_by_project(self, tenant_dn):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        try:
            roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            for role_dn, _ in roles:
                try:
                    conn.delete_s(role_dn)
                except Exception as inst:
                    raise inst
        except ldap.NO_SUCH_OBJECT:
            pass

    def update(self, role_id, role):
        try:
            old_name = self.get_by_name(role['name'])
            raise exception.Conflict('Cannot duplicate name %s' % old_name)
        except exception.NotFound:
            pass
        return super(RoleApi, self).update(role_id, role)

    def delete(self, id, tenant_dn):
        conn = self.get_connection()
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.id_attr, id)
        try:
            for role_dn, _ in conn.search_s(tenant_dn,
                                            ldap.SCOPE_SUBTREE,
                                            query):
                conn.delete_s(role_dn)
        except ldap.NO_SUCH_OBJECT:
            pass
        super(RoleApi, self).delete(id)
