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
from __future__ import absolute_import
import uuid

import ldap

from keystone import clean
from keystone.common import ldap as common_ldap
from keystone.common import logging
from keystone.common import models
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone import identity


CONF = config.CONF
LOG = logging.getLogger(__name__)

DEFAULT_DOMAIN = {
    'id': CONF.identity.default_domain_id,
    'name': 'Default',
    'enabled': True
}


class Identity(identity.Driver):
    def __init__(self):
        super(Identity, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        self.user = UserApi(CONF)
        self.group = GroupApi(CONF)

    def default_assignment_driver(self):
        return "keystone.assignment.backends.ldap.Assignment"

    # Identity interface

    def create_project(self, project_id, project):
        return self.assignment.create_project(project_id, project)

    def get_project(self, project_id):
        return self.assignment.get_project(project_id)

    def authenticate(self, user_id=None, password=None):
        try:
            user_ref = self._get_user(user_id)
        except exception.UserNotFound:
            raise AssertionError('Invalid user / password')
        if not user_id or not password:
            raise AssertionError('Invalid user / password')
        try:
            conn = self.user.get_connection(self.user._id_to_dn(user_id),
                                            password)
            if not conn:
                raise AssertionError('Invalid user / password')
        except Exception:
            raise AssertionError('Invalid user / password')
        return self.assignment._set_default_domain(
            identity.filter_user(user_ref))

    def _get_user(self, user_id):
        return self.user.get(user_id)

    def get_user(self, user_id):
        ref = identity.filter_user(self._get_user(user_id))
        return self.assignment._set_default_domain(ref)

    def list_users(self):
        return self.assignment._set_default_domain(self.user.get_all())

    def get_user_by_name(self, user_name, domain_id):
        self.assignment._validate_default_domain_id(domain_id)
        ref = identity.filter_user(self.user.get_by_name(user_name))
        return self.assignment._set_default_domain(ref)

    # CRUD
    def create_user(self, user_id, user):
        user = self.assignment._validate_default_domain(user)
        user_ref = self.user.create(user)
        tenant_id = user.get('tenant_id')
        if tenant_id is not None:
            self.assignment.add_user_to_project(tenant_id, user_id)
        return (self.assignment._set_default_domain
                (identity.filter_user(user_ref)))

    def update_user(self, user_id, user):
        user = self.assignment._validate_default_domain(user)
        if 'id' in user and user['id'] != user_id:
            raise exception.ValidationError('Cannot change user ID')
        old_obj = self.user.get(user_id)
        if 'name' in user and old_obj.get('name') != user['name']:
            raise exception.Conflict('Cannot change user name')

        if 'tenant_id' in user and \
                old_obj.get('tenant_id') != user['tenant_id']:
            if old_obj['tenant_id']:
                self.project.remove_user(old_obj['tenant_id'],
                                         self.user._id_to_dn(user_id),
                                         user_id)
            if user['tenant_id']:
                self.project.add_user(user['tenant_id'],
                                      self.user._id_to_dn(user_id),
                                      user_id)

        user = utils.hash_ldap_user_password(user)
        if self.user.enabled_mask:
            user['enabled_nomask'] = old_obj['enabled_nomask']
            self.user.mask_enabled_attribute(user)
        self.user.update(user_id, user, old_obj)
        return (self.assignment._set_default_domain
                (self.user.get_filtered(user_id)))

    def delete_user(self, user_id):
        self.assignment.delete_user(user_id)
        user_dn = self.user._id_to_dn(user_id)
        groups = self.group.list_user_groups(user_dn)
        for group in groups:
            self.group.remove_user(user_dn, group['id'], user_id)

        user = self.user.get(user_id)
        if hasattr(user, 'tenant_id'):
            self.project.remove_user(user.tenant_id,
                                     self.user._id_to_dn(user_id))
        self.user.delete(user_id)

    def create_group(self, group_id, group):
        group = self.assignment._validate_default_domain(group)
        group['name'] = clean.group_name(group['name'])
        return self.assignment._set_default_domain(self.group.create(group))

    def get_group(self, group_id):
        return self.assignment._set_default_domain(self.group.get(group_id))

    def update_group(self, group_id, group):
        group = self.assignment._validate_default_domain(group)
        if 'name' in group:
            group['name'] = clean.group_name(group['name'])
        return (self.assignment._set_default_domain
                (self.group.update(group_id, group)))

    def delete_group(self, group_id):
        return self.group.delete(group_id)

    def add_user_to_group(self, user_id, group_id):
        self.get_user(user_id)
        self.get_group(group_id)
        user_dn = self.user._id_to_dn(user_id)
        self.group.add_user(user_dn, group_id, user_id)

    def remove_user_from_group(self, user_id, group_id):
        self.get_user(user_id)
        self.get_group(group_id)
        user_dn = self.user._id_to_dn(user_id)
        self.group.remove_user(user_dn, group_id, user_id)

    def list_groups_for_user(self, user_id):
        self.get_user(user_id)
        user_dn = self.user._id_to_dn(user_id)
        return (self.assignment._set_default_domain
                (self.group.list_user_groups(user_dn)))

    def list_groups(self):
        return self.assignment._set_default_domain(self.group.get_all())

    def list_users_in_group(self, group_id):
        self.get_group(group_id)
        users = []
        for user_dn in self.group.list_group_users(group_id):
            user_id = self.user._dn_to_id(user_dn)
            try:
                users.append(self.user.get(user_id))
            except exception.UserNotFound:
                LOG.debug(_("Group member '%(user_dn)s' not found in"
                            " '%(group_id)s'. The user should be removed"
                            " from the group. The user will be ignored.") %
                          dict(user_dn=user_dn, group_id=group_id))
        return self.assignment._set_default_domain(users)

    def check_user_in_group(self, user_id, group_id):
        self.get_user(user_id)
        self.get_group(group_id)
        user_refs = self.list_users_in_group(group_id)
        found = False
        for x in user_refs:
            if x['id'] == user_id:
                found = True
                break
        return found


# TODO(termie): turn this into a data object and move logic to driver
class UserApi(common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Users'
    DEFAULT_STRUCTURAL_CLASSES = ['person']
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_OBJECTCLASS = 'inetOrgPerson'
    DEFAULT_ATTRIBUTE_IGNORE = ['tenant_id', 'tenants']
    NotFound = exception.UserNotFound
    options_name = 'user'
    attribute_mapping = {'password': 'userPassword',
                         'email': 'mail',
                         'name': 'sn',
                         'enabled': 'enabled',
                         'domain_id': 'domain_id'}

    model = models.User

    def __init__(self, conf):
        super(UserApi, self).__init__(conf)
        self.attribute_mapping['name'] = conf.ldap.user_name_attribute
        self.attribute_mapping['email'] = conf.ldap.user_mail_attribute
        self.attribute_mapping['password'] = conf.ldap.user_pass_attribute
        self.attribute_mapping['enabled'] = conf.ldap.user_enabled_attribute
        self.attribute_mapping['domain_id'] = (
            conf.ldap.user_domain_id_attribute)
        self.enabled_mask = conf.ldap.user_enabled_mask
        self.enabled_default = conf.ldap.user_enabled_default
        self.attribute_ignore = (getattr(conf.ldap, 'user_attribute_ignore')
                                 or self.DEFAULT_ATTRIBUTE_IGNORE)

    def _ldap_res_to_model(self, res):
        obj = super(UserApi, self)._ldap_res_to_model(res)
        if self.enabled_mask != 0:
            obj['enabled_nomask'] = obj['enabled']
            obj['enabled'] = ((obj['enabled'] & self.enabled_mask) !=
                              self.enabled_mask)
        return obj

    def mask_enabled_attribute(self, values):
        value = values['enabled']
        values.setdefault('enabled_nomask', self.enabled_default)
        if value != ((values['enabled_nomask'] & self.enabled_mask) !=
                     self.enabled_mask):
            values['enabled_nomask'] ^= self.enabled_mask
        values['enabled'] = values['enabled_nomask']
        del values['enabled_nomask']

    def create(self, values):
        self.affirm_unique(values)
        values = utils.hash_ldap_user_password(values)
        if self.enabled_mask:
            self.mask_enabled_attribute(values)
        values = super(UserApi, self).create(values)
        return values

    def check_password(self, user_id, password):
        user = self.get(user_id)
        return utils.check_password(password, user.password)

    def get_filtered(self, user_id):
        user = self.get(user_id)
        return identity.filter_user(user)


# TODO(termie): turn this into a data object and move logic to driver
class ProjectApi(common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Projects'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'groupOfNames'
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_MEMBER_ATTRIBUTE = 'member'
    DEFAULT_ATTRIBUTE_IGNORE = []
    NotFound = exception.ProjectNotFound
    notfound_arg = 'project_id'  # NOTE(yorik-sar): while options_name = tenant
    options_name = 'tenant'
    attribute_mapping = {'name': 'ou',
                         'description': 'description',
                         'tenantId': 'cn',
                         'enabled': 'enabled',
                         'domain_id': 'domain_id'}
    model = models.Project

    def __init__(self, conf):
        super(ProjectApi, self).__init__(conf)
        self.attribute_mapping['name'] = conf.ldap.tenant_name_attribute
        self.attribute_mapping['description'] = conf.ldap.tenant_desc_attribute
        self.attribute_mapping['enabled'] = conf.ldap.tenant_enabled_attribute
        self.attribute_mapping['domain_id'] = (
            conf.ldap.tenant_domain_id_attribute)
        self.member_attribute = (getattr(conf.ldap, 'tenant_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self.attribute_ignore = (getattr(conf.ldap, 'tenant_attribute_ignore')
                                 or self.DEFAULT_ATTRIBUTE_IGNORE)

    def create(self, values):
        self.affirm_unique(values)
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
        if old_obj['name'] != values['name']:
            msg = 'Changing Name not supported by LDAP'
            raise exception.NotImplemented(message=msg)
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
    DEFAULT_ATTRIBUTE_IGNORE = []
    NotFound = exception.RoleNotFound
    options_name = 'role'
    attribute_mapping = {'name': 'ou',
                         #'serviceId': 'service_id',
                         }
    model = models.Role

    def __init__(self, conf):
        super(RoleApi, self).__init__(conf)
        self.attribute_mapping['name'] = conf.ldap.role_name_attribute
        self.member_attribute = (getattr(conf.ldap, 'role_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self.attribute_ignore = (getattr(conf.ldap, 'role_attribute_ignore')
                                 or self.DEFAULT_ATTRIBUTE_IGNORE)

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
        if role['id'] != role_id:
            raise exception.ValidationError('Cannot change role ID')
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


class GroupApi(common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=UserGroups'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'groupOfNames'
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_MEMBER_ATTRIBUTE = 'member'
    DEFAULT_ATTRIBUTE_IGNORE = []
    NotFound = exception.GroupNotFound
    options_name = 'group'
    attribute_mapping = {'name': 'ou',
                         'description': 'description',
                         'groupId': 'cn',
                         'domain_id': 'domain_id'}
    model = models.Group

    def __init__(self, conf):
        super(GroupApi, self).__init__(conf)
        self.attribute_mapping['name'] = conf.ldap.group_name_attribute
        self.attribute_mapping['description'] = conf.ldap.group_desc_attribute
        self.attribute_mapping['domain_id'] = (
            conf.ldap.group_domain_id_attribute)
        self.member_attribute = (getattr(conf.ldap, 'group_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self.attribute_ignore = (getattr(conf.ldap, 'group_attribute_ignore')
                                 or self.DEFAULT_ATTRIBUTE_IGNORE)

    def create(self, values):
        self.affirm_unique(values)
        data = values.copy()
        if data.get('id') is None:
            data['id'] = uuid.uuid4().hex
        if 'description' in data and data['description'] in ['', None]:
            data.pop('description')
        return super(GroupApi, self).create(data)

    def delete(self, id):
        if self.subtree_delete_enabled:
            super(GroupApi, self).deleteTree(id)
        else:
            # TODO(spzala): this is only placeholder for group and domain
            # role support which will be added under bug 1101287

            conn = self.get_connection()
            query = '(objectClass=%s)' % self.object_class
            dn = None
            dn = self._id_to_dn(id)
            if dn:
                try:
                    roles = conn.search_s(dn, ldap.SCOPE_ONELEVEL,
                                          query, ['%s' % '1.1'])
                    for role_dn, _ in roles:
                        conn.delete_s(role_dn)
                except ldap.NO_SUCH_OBJECT:
                    pass

            super(GroupApi, self).delete(id)

    def update(self, id, values):
        old_obj = self.get(id)
        if old_obj['name'] != values['name']:
            msg = _('Changing Name not supported by LDAP')
            raise exception.NotImplemented(message=msg)
        return super(GroupApi, self).update(id, values, old_obj)

    def add_user(self, user_dn, group_id, user_id):
        conn = self.get_connection()
        try:
            conn.modify_s(
                self._id_to_dn(group_id),
                [(ldap.MOD_ADD,
                  self.member_attribute,
                  user_dn)])
        except ldap.TYPE_OR_VALUE_EXISTS:
            raise exception.Conflict(_(
                'User %(user_id)s is already a member of group %(group_id)s') %
                {'user_id': user_id, 'group_id': group_id})

    def remove_user(self, user_dn, group_id, user_id):
        conn = self.get_connection()
        try:
            conn.modify_s(
                self._id_to_dn(group_id),
                [(ldap.MOD_DELETE,
                  self.member_attribute,
                  user_dn)])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.UserNotFound(user_id=user_id)

    def list_user_groups(self, user_dn):
        """Return a list of groups for which the user is a member."""

        query = '(%s=%s)' % (self.member_attribute, user_dn)
        memberships = self.get_all(query)
        return memberships

    def list_group_users(self, group_id):
        """Return a list of user dns which are members of a group."""
        query = '(objectClass=%s)' % self.object_class
        conn = self.get_connection()
        group_dn = self._id_to_dn(group_id)
        try:
            attrs = conn.search_s(group_dn,
                                  ldap.SCOPE_BASE,
                                  query, ['%s' % self.member_attribute])
        except ldap.NO_SUCH_OBJECT:
            return []
        users = []
        for dn, member in attrs:
            user_dns = member[self.member_attribute]
            for user_dn in user_dns:
                if self.use_dumb_member and user_dn == self.dumb_member:
                    continue
                users.append(user_dn)
        return users
