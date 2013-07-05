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

import uuid

import ldap
from ldap import filter as ldap_filter

from keystone import clean
from keystone.common import ldap as common_ldap
from keystone.common.ldap import fakeldap
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
        self.project = ProjectApi(CONF)
        self.role = RoleApi(CONF)
        self.group = GroupApi(CONF)

    def _validate_domain(self, ref):
        """Validate that either the default domain or nothing is specified.

        Also removes the domain from the ref so that LDAP doesn't have to
        persist the attribute.

        """
        ref = ref.copy()
        domain_id = ref.pop('domain_id', CONF.identity.default_domain_id)
        self._validate_domain_id(domain_id)
        return ref

    def _validate_domain_id(self, domain_id):
        """Validate that the domain ID specified belongs to the default domain.

        """
        if domain_id != CONF.identity.default_domain_id:
            raise exception.DomainNotFound(domain_id=domain_id)

    def _set_default_domain(self, ref):
        """Overrides any domain reference with the default domain."""
        if isinstance(ref, dict):
            ref = ref.copy()
            ref['domain_id'] = CONF.identity.default_domain_id
            return ref
        elif isinstance(ref, list):
            return [self._set_default_domain(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    # Identity interface
    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate based on a user, tenant and password.

        Expects the user object to have a password field and the tenant to be
        in the list of tenants on the user.
        """
        tenant_ref = None
        metadata_ref = {}

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

        if tenant_id is not None:
            if tenant_id not in self.get_projects_for_user(user_id):
                raise AssertionError('Invalid tenant')

            try:
                tenant_ref = self.get_project(tenant_id)
                # TODO(termie): this should probably be made into a
                #               get roles call
                metadata_ref = self.get_metadata(user_id, tenant_id)
            except exception.ProjectNotFound:
                tenant_ref = None
                metadata_ref = {}
            except exception.MetadataNotFound:
                metadata_ref = {}

        user_ref = self._set_default_domain(identity.filter_user(user_ref))
        return (user_ref, tenant_ref, metadata_ref)

    def get_project(self, tenant_id):
        return self._set_default_domain(self.project.get(tenant_id))

    def list_projects(self):
        return self._set_default_domain(self.project.get_all())

    def get_project_by_name(self, tenant_name, domain_id):
        self._validate_domain_id(domain_id)
        return self._set_default_domain(self.project.get_by_name(tenant_name))

    def _get_user(self, user_id):
        return self.user.get(user_id)

    def get_user(self, user_id):
        ref = identity.filter_user(self._get_user(user_id))
        return self._set_default_domain(ref)

    def list_users(self):
        return self._set_default_domain(self.user.get_all())

    def get_user_by_name(self, user_name, domain_id):
        self._validate_domain_id(domain_id)
        ref = identity.filter_user(self.user.get_by_name(user_name))
        return self._set_default_domain(ref)

    def get_metadata(self, user_id=None, tenant_id=None,
                     domain_id=None, group_id=None):

        def _get_roles_for_just_user_and_project(user_id, tenant_id):
            self.get_user(user_id)
            self.get_project(tenant_id)
            return [a.role_id
                    for a in self.role.get_role_assignments(tenant_id)
                    if a.user_id == user_id]
        if domain_id is not None:
            msg = 'Domain metadata not supported by LDAP'
            raise exception.NotImplemented(message=msg)
        if not self.get_project(tenant_id) or not self.get_user(user_id):
            return {}

        metadata_ref = _get_roles_for_just_user_and_project(user_id, tenant_id)
        if not metadata_ref:
            return {}
        return {'roles': metadata_ref}

    def get_role(self, role_id):
        return self.role.get(role_id)

    def list_roles(self):
        return self.role.get_all()

    def get_projects_for_user(self, user_id):
        self.get_user(user_id)
        return [p['id'] for p in self.project.get_user_projects(user_id)]

    def get_project_users(self, tenant_id):
        self.get_project(tenant_id)
        return self._set_default_domain(self.project.get_users(tenant_id))

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.get_user(user_id)
        self.get_project(tenant_id)
        self.get_role(role_id)
        self.role.add_user(role_id, user_id, tenant_id)

    # CRUD
    def create_user(self, user_id, user):
        user = self._validate_domain(user)
        user['name'] = clean.user_name(user['name'])
        user_ref = self.user.create(user)
        return self._set_default_domain(identity.filter_user(user_ref))

    def update_user(self, user_id, user):
        user = self._validate_domain(user)
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        return self._set_default_domain(self.user.update(user_id, user))

    def create_project(self, tenant_id, tenant):
        tenant = self._validate_domain(tenant)
        tenant['name'] = clean.project_name(tenant['name'])
        data = tenant.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4().hex)
        if 'description' in data and data['description'] in ['', None]:
            data.pop('description')
        return self._set_default_domain(self.project.create(data))

    def update_project(self, tenant_id, tenant):
        tenant = self._validate_domain(tenant)
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])
        return self._set_default_domain(self.project.update(tenant_id, tenant))

    def create_metadata(self, user_id, tenant_id, metadata):
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
        return self.role.delete(role_id)

    def delete_project(self, tenant_id):
        return self.project.delete(tenant_id)

    def delete_user(self, user_id):
        return self.user.delete(user_id)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        return self.role.delete_user(role_id, user_id, tenant_id)

    def update_role(self, role_id, role):
        self.get_role(role_id)
        self.role.update(role_id, role)

    def create_group(self, group_id, group):
        group = self._validate_domain(group)
        group['name'] = clean.group_name(group['name'])
        return self._set_default_domain(self.group.create(group))

    def get_group(self, group_id):
        return self._set_default_domain(self.group.get(group_id))

    def update_group(self, group_id, group):
        group = self._validate_domain(group)
        if 'name' in group:
            group['name'] = clean.group_name(group['name'])
        return self._set_default_domain(self.group.update(group_id, group))

    def delete_group(self, group_id):
        return self.group.delete(group_id)

    def add_user_to_group(self, user_id, group_id):
        self.get_user(user_id)
        self.get_group(group_id)
        self.group.add_user(user_id, group_id)

    def remove_user_from_group(self, user_id, group_id):
        self.get_user(user_id)
        self.get_group(group_id)
        self.group.remove_user(user_id, group_id)

    def list_groups_for_user(self, user_id):
        self.get_user(user_id)
        return self._set_default_domain(self.group.list_user_groups(user_id))

    def list_groups(self):
        return self._set_default_domain(self.group.get_all())

    def list_users_in_group(self, group_id):
        self.get_group(group_id)
        return self._set_default_domain(self.group.list_group_users(group_id))

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

    def create_domain(self, domain_id, domain):
        if domain_id == CONF.identity.default_domain_id:
            msg = 'Duplicate ID, %s.' % domain_id
            raise exception.Conflict(type='domain', details=msg)
        raise exception.Forbidden('Domains are read-only against LDAP')

    def get_domain(self, domain_id):
        self._validate_domain_id(domain_id)
        return DEFAULT_DOMAIN

    def update_domain(self, domain_id, domain):
        self._validate_domain_id(domain_id)
        raise exception.Forbidden('Domains are read-only against LDAP')

    def delete_domain(self, domain_id):
        self._validate_domain_id(domain_id)
        raise exception.Forbidden('Domains are read-only against LDAP')

    def list_domains(self):
        return [DEFAULT_DOMAIN]


# TODO(termie): remove this and move cross-api calls into driver
class ApiShim(object):
    """Quick singleton-y shim to get around recursive dependencies.

    NOTE(termie): this should be removed and the cross-api code
    should be moved into the driver itself.
    """

    _role = None
    _project = None
    _user = None
    _group = None
    _domain = None

    def __init__(self, conf):
        self.conf = conf

    @property
    def role(self):
        if not self._role:
            self._role = RoleApi(self.conf)
        return self._role

    @property
    def project(self):
        if not self._project:
            self._project = ProjectApi(self.conf)
        return self._project

    @property
    def user(self):
        if not self._user:
            self._user = UserApi(self.conf)
        return self._user

    @property
    def group(self):
        if not self._group:
            self._group = GroupApi(self.conf)
        return self._group


# TODO(termie): remove this and move cross-api calls into driver
class ApiShimMixin(object):
    """Mixin to share some ApiShim code. Remove me."""

    @property
    def role_api(self):
        return self.api.role

    @property
    def project_api(self):
        return self.api.project

    @property
    def user_api(self):
        return self.api.user

    @property
    def group_api(self):
        return self.api.group

    @property
    def domain_api(self):
        return self.api.domain


# TODO(termie): turn this into a data object and move logic to driver
class UserApi(common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap, ApiShimMixin):
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
        self.api = ApiShim(conf)

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
        tenant_id = values.get('tenant_id')
        if tenant_id is not None:
            self.project_api.add_user(values['tenant_id'], values['id'])
        return values

    def update(self, id, values):
        if 'id' in values and values['id'] != id:
            raise exception.ValidationError('Cannot change user ID')
        old_obj = self.get(id)
        if 'name' in values and old_obj.get('name') != values['name']:
            raise exception.Conflict('Cannot change user name')

        if 'tenant_id' in values and \
                old_obj.get('tenant_id') != values['tenant_id']:
            if old_obj['tenant_id']:
                self.project_api.remove_user(old_obj['tenant_id'], id)
            if values['tenant_id']:
                self.project_api.add_user(values['tenant_id'], id)

        values = utils.hash_ldap_user_password(values)
        if self.enabled_mask:
            values['enabled_nomask'] = old_obj['enabled_nomask']
            self.mask_enabled_attribute(values)
        super(UserApi, self).update(id, values, old_obj)
        return self.get(id)

    def delete(self, id):
        user = self.get(id)
        if hasattr(user, 'tenant_id'):
            self.project_api.remove_user(user.tenant_id, id)

        super(UserApi, self).delete(id)

        for ref in self.role_api.list_global_roles_for_user(id):
            self.role_api.delete_user(ref.role_id, ref.user_id, ref.project_id)

        for ref in self.role_api.list_project_roles_for_user(id):
            self.role_api.delete_user(ref.role_id, ref.user_id, ref.project_id)

    def check_password(self, user_id, password):
        user = self.get(user_id)
        return utils.check_password(password, user.password)


# TODO(termie): turn this into a data object and move logic to driver
class ProjectApi(common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap,
                 ApiShimMixin):
    DEFAULT_OU = 'ou=Groups'
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
        self.api = ApiShim(conf)
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

    def get_user_projects(self, user_id):
        """Returns list of tenants a user has access to
        """
        associations = self.role_api.list_project_roles_for_user(user_id)
        project_ids = set()
        for assoc in associations:
            project_ids.add(assoc.project_id)
        projects = []
        for project_id in project_ids:
            #slower to get them one at a time, but a huge list could blow out
            #the connection.  This is the safer way
            projects.append(self.get(project_id))
        return projects

    def get_role_assignments(self, tenant_id):
        return self.role_api.get_role_assignments(tenant_id)

    def add_user(self, tenant_id, user_id):
        conn = self.get_connection()
        try:
            conn.modify_s(
                self._id_to_dn(tenant_id),
                [(ldap.MOD_ADD,
                  self.member_attribute,
                  self.user_api._id_to_dn(user_id))])
        except ldap.TYPE_OR_VALUE_EXISTS:
            # As adding a user to a tenant is done implicitly in several
            # places, and is not part of the exposed API, it's easier for us to
            # just ignore this instead of raising exception.Conflict.
            pass

    def remove_user(self, tenant_id, user_id):
        conn = self.get_connection()
        try:
            conn.modify_s(self._id_to_dn(tenant_id),
                          [(ldap.MOD_DELETE,
                            self.member_attribute,
                            self.user_api._id_to_dn(user_id))])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.NotFound(user_id)

    def get_users(self, tenant_id, role_id=None):
        tenant = self._ldap_get(tenant_id)
        res = set()
        if not role_id:
            # Get users who have default tenant mapping
            for user_dn in tenant[1].get(self.member_attribute, []):
                if self.use_dumb_member and user_dn == self.dumb_member:
                    continue
                res.add(self.user_api.get(self.user_api._dn_to_id(user_dn)))

        # Get users who are explicitly mapped via a tenant
        rolegrants = self.role_api.get_role_assignments(tenant_id)
        for rolegrant in rolegrants:
            if role_id is None or rolegrant.role_id == role_id:
                res.add(self.user_api.get(rolegrant.user_id))
        return list(res)

    def delete(self, id):
        if self.subtree_delete_enabled:
            super(ProjectApi, self).deleteTree(id)
        else:
            self.role_api.roles_delete_subtree_by_project(id)
            super(ProjectApi, self).delete(id)

    def update(self, id, values):
        old_obj = self.get(id)
        if old_obj['name'] != values['name']:
            msg = 'Changing Name not supported by LDAP'
            raise exception.NotImplemented(message=msg)
        return super(ProjectApi, self).update(id, values, old_obj)


class UserRoleAssociation(object):
    """Role Grant model."""

    def __init__(self, user_id=None, role_id=None, tenant_id=None,
                 *args, **kw):
        self.user_id = str(user_id)
        self.role_id = role_id
        self.project_id = str(tenant_id)


class GroupRoleAssociation(object):
    """Role Grant model."""

    def __init__(self, group_id=None, role_id=None, tenant_id=None,
                 *args, **kw):
        self.group_id = str(group_id)
        self.role_id = role_id
        self.project_id = str(tenant_id)


# TODO(termie): turn this into a data object and move logic to driver
class RoleApi(common_ldap.BaseLdap, ApiShimMixin):
    DEFAULT_OU = 'ou=Roles'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'organizationalRole'
    DEFAULT_MEMBER_ATTRIBUTE = 'roleOccupant'
    DEFAULT_ATTRIBUTE_IGNORE = []
    NotFound = exception.RoleNotFound
    options_name = 'role'
    attribute_mapping = {'name': 'cn',
                         #'serviceId': 'service_id',
                         }
    model = models.Role

    def __init__(self, conf):
        super(RoleApi, self).__init__(conf)
        self.api = ApiShim(conf)
        self.attribute_mapping['name'] = conf.ldap.role_name_attribute
        self.member_attribute = (getattr(conf.ldap, 'role_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self.attribute_ignore = (getattr(conf.ldap, 'role_attribute_ignore')
                                 or self.DEFAULT_ATTRIBUTE_IGNORE)

    def _subrole_id_to_dn(self, role_id, tenant_id):
        if tenant_id is None:
            return self._id_to_dn(role_id)
        else:
            return '%s=%s,%s' % (self.id_attr,
                                 ldap.dn.escape_dn_chars(role_id),
                                 self.project_api._id_to_dn(tenant_id))

    def get(self, id, filter=None):
        model = super(RoleApi, self).get(id, filter)
        return model

    def create(self, values):
        #values['id'] = values['name']
        #delattr(values, 'name')
        return super(RoleApi, self).create(values)

    def add_user(self, role_id, user_id, tenant_id=None):
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.get_connection()
        user_dn = self.user_api._id_to_dn(user_id)
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

        return UserRoleAssociation(
            role_id=role_id,
            user_id=user_id,
            tenant_id=tenant_id)

    def delete_user(self, role_id, user_id, tenant_id):
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.get_connection()
        user_dn = self.user_api._id_to_dn(user_id)
        try:
            conn.modify_s(role_dn, [(ldap.MOD_DELETE,
                                     self.member_attribute, user_dn)])
        except ldap.NO_SUCH_OBJECT:
            if tenant_id is None or self.get(role_id) is None:
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

    def get_role_assignments(self, tenant_id):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        tenant_dn = self.project_api._id_to_dn(tenant_id)

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
                user_id = self.user_api._dn_to_id(user_dn)
                role_id = self._dn_to_id(role_dn)
                res.append(UserRoleAssociation(
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))

        return res

    def list_global_roles_for_user(self, user_id):
        user_dn = self.user_api._id_to_dn(user_id)
        roles = self.get_all('(%s=%s)' % (self.member_attribute, user_dn))
        return [UserRoleAssociation(
                role_id=role.id,
                user_id=user_id) for role in roles]

    def list_project_roles_for_user(self, user_id, tenant_id=None):
        conn = self.get_connection()
        user_dn = self.user_api._id_to_dn(user_id)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,
                                                user_dn)
        if tenant_id is not None:
            tenant_dn = self.project_api._id_to_dn(tenant_id)
            try:
                roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            except ldap.NO_SUCH_OBJECT:
                return []

            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                res.append(UserRoleAssociation(
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        else:
            try:
                roles = conn.search_s(self.project_api.tree_dn,
                                      ldap.SCOPE_SUBTREE,
                                      query)
            except ldap.NO_SUCH_OBJECT:
                return []

            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                tenant_id = ldap.dn.str2dn(role_dn)[1][0][1]
                res.append(UserRoleAssociation(
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def roles_delete_subtree_by_project(self, tenant_id):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        tenant_dn = self.project_api._id_to_dn(tenant_id)
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

    def delete(self, id):
        conn = self.get_connection()
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.id_attr, id)
        tenant_dn = self.project_api.tree_dn
        try:
            for role_dn, _ in conn.search_s(tenant_dn,
                                            ldap.SCOPE_SUBTREE,
                                            query):
                conn.delete_s(role_dn)
        except ldap.NO_SUCH_OBJECT:
            pass
        super(RoleApi, self).delete(id)

# TODO (spzala) - this is only placeholder for group and domain role support
# which will be added under bug 1101287
    def roles_delete_subtree_by_type(self, id, type):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        dn = None
        if type == 'Group':
            dn = self.group_api._id_to_dn(id)
        if type == 'Domain':
            dn = self.domain_api._id_to_dn(id)
        if dn:
            try:
                roles = conn.search_s(dn, ldap.SCOPE_ONELEVEL,
                                      query, ['%s' % '1.1'])
                for role_dn, _ in roles:
                    try:
                        conn.delete_s(role_dn)
                    except:
                        raise Exception
            except ldap.NO_SUCH_OBJECT:
                pass


class GroupApi(common_ldap.BaseLdap, ApiShimMixin):
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
        self.api = ApiShim(conf)
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
            self.role_api.roles_delete_subtree_by_type(id, 'Group')
            super(GroupApi, self).delete(id)

    def update(self, id, values):
        old_obj = self.get(id)
        if old_obj['name'] != values['name']:
            msg = _('Changing Name not supported by LDAP')
            raise exception.NotImplemented(message=msg)
        return super(GroupApi, self).update(id, values, old_obj)

    def add_user(self, user_id, group_id):
        conn = self.get_connection()
        try:
            conn.modify_s(
                self._id_to_dn(group_id),
                [(ldap.MOD_ADD,
                  self.member_attribute,
                  self.user_api._id_to_dn(user_id))])
        except ldap.TYPE_OR_VALUE_EXISTS:
            msg = _('User %s is already a member of group %s'
                    % (user_id, group_id))
            raise exception.Conflict(msg)

    def remove_user(self, user_id, group_id):
        conn = self.get_connection()
        try:
            conn.modify_s(
                self._id_to_dn(group_id),
                [(ldap.MOD_DELETE,
                  self.member_attribute,
                  self.user_api._id_to_dn(user_id))])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.UserNotFound(user_id=user_id)

    def list_user_groups(self, user_id):
        """Returns a list of groups a user has access to"""
        user_dn = self.user_api._id_to_dn(user_id)
        query = '(%s=%s)' % (self.member_attribute, user_dn)
        memberships = self.get_all(query)
        return memberships

    def list_group_users(self, group_id):
        """Returns a list of users that belong to a group"""
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
                try:
                    user_id = self.user_api._dn_to_id(user_dn)
                    users.append(self.user_api.get(user_id))
                except exception.UserNotFound:
                    LOG.debug(_("Group member '%(user_dn)s' not found in"
                                " '%(group_dn)s'. The user should be removed"
                                " from the group. The user will be ignored.") %
                              dict(user_dn=user_dn, group_dn=group_dn))
        return users
