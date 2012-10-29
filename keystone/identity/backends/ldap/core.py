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
from keystone.common import models
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone import identity


CONF = config.CONF


class Identity(identity.Driver):
    def __init__(self):
        super(Identity, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        self.user = UserApi(CONF)
        self.tenant = TenantApi(CONF)
        self.role = RoleApi(CONF)

    def get_connection(self, user=None, password=None):
        if self.LDAP_URL.startswith('fake://'):
            conn = fakeldap.FakeLdap(self.LDAP_URL)
        else:
            conn = common_ldap.LdapWrapper(self.LDAP_URL)
        if user is None:
            user = self.LDAP_USER
        if password is None:
            password = self.LDAP_PASSWORD
        conn.simple_bind_s(user, password)
        return conn

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

        try:
            conn = self.user.get_connection(self.user._id_to_dn(user_id),
                                            password)
            if not conn:
                raise AssertionError('Invalid user / password')
        except Exception:
            raise AssertionError('Invalid user / password')

        if tenant_id is not None:
            if tenant_id not in self.get_tenants_for_user(user_id):
                raise AssertionError('Invalid tenant')

            try:
                tenant_ref = self.get_tenant(tenant_id)
                # TODO(termie): this should probably be made into a
                #               get roles call
                metadata_ref = self.get_metadata(user_id, tenant_id)
            except exception.TenantNotFound:
                tenant_ref = None
                metadata_ref = {}
            except exception.MetadataNotFound:
                metadata_ref = {}

        return (identity.filter_user(user_ref), tenant_ref, metadata_ref)

    def get_tenant(self, tenant_id):
        try:
            return self.tenant.get(tenant_id)
        except exception.NotFound:
            raise exception.TenantNotFound(tenant_id=tenant_id)

    def get_tenants(self):
        return self.tenant.get_all()

    def get_tenant_by_name(self, tenant_name):
        try:
            return self.tenant.get_by_name(tenant_name)
        except exception.NotFound:
            raise exception.TenantNotFound(tenant_id=tenant_name)

    def _get_user(self, user_id):
        try:
            return self.user.get(user_id)
        except exception.NotFound:
            raise exception.UserNotFound(user_id=user_id)

    def get_user(self, user_id):
        return identity.filter_user(self._get_user(user_id))

    def list_users(self):
        return self.user.get_all()

    def get_user_by_name(self, user_name):
        try:
            return identity.filter_user(self.user.get_by_name(user_name))
        except exception.NotFound:
            raise exception.UserNotFound(user_id=user_name)

    def get_metadata(self, user_id, tenant_id):
        if not self.get_tenant(tenant_id) or not self.get_user(user_id):
            return {}

        metadata_ref = self.get_roles_for_user_and_tenant(user_id, tenant_id)
        if not metadata_ref:
            return {}
        return {'roles': metadata_ref}

    def get_role(self, role_id):
        try:
            return self.role.get(role_id)
        except exception.NotFound:
            raise exception.RoleNotFound(role_id=role_id)

    def list_roles(self):
        return self.role.get_all()

    # These should probably be part of the high-level API
    # When this happens, then change TenantAPI.add_user to not ignore
    # ldap.TYPE_OR_VALUE_EXISTS
    def add_user_to_tenant(self, tenant_id, user_id):
        self.get_tenant(tenant_id)
        self.get_user(user_id)
        return self.tenant.add_user(tenant_id, user_id)

    def get_tenants_for_user(self, user_id):
        self.get_user(user_id)
        tenant_list = []
        for tenant in self.tenant.get_user_tenants(user_id):
            tenant_list.append(tenant['id'])
        return tenant_list

    def get_tenant_users(self, tenant_id):
        self.get_tenant(tenant_id)
        user_list = []
        for user in self.tenant.get_users(tenant_id):
            user_list.append(user)
        return user_list

    def get_roles_for_user_and_tenant(self, user_id, tenant_id):
        self.get_user(user_id)
        self.get_tenant(tenant_id)
        assignments = self.role.get_role_assignments(tenant_id)
        roles = []
        for assignment in assignments:
            if assignment.user_id == user_id:
                roles.append(assignment.role_id)
        return roles

    def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
        self.get_user(user_id)
        self.get_tenant(tenant_id)
        self.get_role(role_id)
        self.role.add_user(role_id, user_id, tenant_id)

    # CRUD
    def create_user(self, user_id, user):
        user['name'] = clean.user_name(user['name'])
        return identity.filter_user(self.user.create(user))

    def update_user(self, user_id, user):
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        return self.user.update(user_id, user)

    def create_tenant(self, tenant_id, tenant):
        tenant['name'] = clean.tenant_name(tenant['name'])
        data = tenant.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4().hex)
        return self.tenant.create(tenant)

    def update_tenant(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant['name'] = clean.tenant_name(tenant['name'])
        return self.tenant.update(tenant_id, tenant)

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
        try:
            return self.role.delete(role_id)
        except ldap.NO_SUCH_OBJECT:
            raise exception.RoleNotFound(role_id=role_id)

    def delete_tenant(self, tenant_id):
        try:
            return self.tenant.delete(tenant_id)
        except ldap.NO_SUCH_OBJECT:
            raise exception.TenantNotFound(tenant_id=tenant_id)

    def delete_user(self, user_id):
        try:
            return self.user.delete(user_id)
        except ldap.NO_SUCH_OBJECT:
            raise exception.UserNotFound(user_id=user_id)

    def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
        return self.role.delete_user(role_id, user_id, tenant_id)

    def remove_user_from_tenant(self, tenant_id, user_id):
        self.get_user(user_id)
        self.get_tenant(tenant_id)
        return self.tenant.remove_user(tenant_id, user_id)

    def update_role(self, role_id, role):
        self.get_role(role_id)
        self.role.update(role_id, role)


# TODO(termie): remove this and move cross-api calls into driver
class ApiShim(object):
    """Quick singleton-y shim to get around recursive dependencies.

    NOTE(termie): this should be removed and the cross-api code
    should be moved into the driver itself.
    """

    _role = None
    _tenant = None
    _user = None

    def __init__(self, conf):
        self.conf = conf

    @property
    def role(self):
        if not self._role:
            self._role = RoleApi(self.conf)
        return self._role

    @property
    def tenant(self):
        if not self._tenant:
            self._tenant = TenantApi(self.conf)
        return self._tenant

    @property
    def user(self):
        if not self._user:
            self._user = UserApi(self.conf)
        return self._user


# TODO(termie): remove this and move cross-api calls into driver
class ApiShimMixin(object):
    """Mixin to share some ApiShim code. Remove me."""

    @property
    def role_api(self):
        return self.api.role

    @property
    def tenant_api(self):
        return self.api.tenant

    @property
    def user_api(self):
        return self.api.user


# TODO(termie): turn this into a data object and move logic to driver
class UserApi(common_ldap.BaseLdap, ApiShimMixin):
    DEFAULT_OU = 'ou=Users'
    DEFAULT_STRUCTURAL_CLASSES = ['person']
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_OBJECTCLASS = 'inetOrgPerson'
    DEFAULT_ATTRIBUTE_IGNORE = ['tenant_id', 'tenants']
    options_name = 'user'
    attribute_mapping = {'password': 'userPassword',
                         'email': 'mail',
                         'name': 'sn',
                         'enabled': 'enabled'}

    model = models.User

    def __init__(self, conf):
        super(UserApi, self).__init__(conf)
        self.attribute_mapping['name'] = conf.ldap.user_name_attribute
        self.attribute_mapping['email'] = conf.ldap.user_mail_attribute
        self.attribute_mapping['password'] = conf.ldap.user_pass_attribute
        self.attribute_mapping['enabled'] = conf.ldap.user_enabled_attribute
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

    def get(self, id, filter=None):
        """Replaces exception.NotFound with exception.UserNotFound."""
        try:
            return super(UserApi, self).get(id, filter)
        except exception.NotFound:
            raise exception.UserNotFound(user_id=id)

    def get_by_name(self, name, filter=None):
        query = ('(%s=%s)' % (self.attribute_mapping['name'],
                              ldap_filter.escape_filter_chars(name)))
        users = self.get_all(query)
        try:
            return users[0]
        except IndexError:
            raise exception.UserNotFound(user_id=name)

    def create(self, values):
        self.affirm_unique(values)
        values = utils.hash_ldap_user_password(values)
        if self.enabled_mask:
            self.mask_enabled_attribute(values)
        values = super(UserApi, self).create(values)
        tenant_id = values.get('tenant_id')
        if tenant_id is not None:
            self.tenant_api.add_user(values['tenant_id'], values['id'])
        return values

    def update(self, id, values):
        if values['id'] != id:
            raise exception.ValidationError('Cannot change user ID')
        try:
            old_obj = self.get(id)
        except exception.NotFound:
            raise exception.UserNotFound(user_id=id)
        if old_obj.get('name') != values['name']:
            raise exception.Conflict('Cannot change user name')
        try:
            new_tenant = values['tenant_id']
        except KeyError:
            pass
        else:
            if old_obj.get('tenant_id') != new_tenant:
                if old_obj['tenant_id']:
                    self.tenant_api.remove_user(old_obj['tenant_id'], id)
                if new_tenant:
                    self.tenant_api.add_user(new_tenant, id)

        values = utils.hash_ldap_user_password(values)
        if self.enabled_mask:
            values['enabled_nomask'] = old_obj['enabled_nomask']
            self.mask_enabled_attribute(values)
        super(UserApi, self).update(id, values, old_obj)

    def delete(self, id):
        user = self.get(id)
        if hasattr(user, 'tenant_id'):
            self.tenant_api.remove_user(user.tenant_id, id)

        super(UserApi, self).delete(id)

        for ref in self.role_api.list_global_roles_for_user(id):
            self.role_api.rolegrant_delete(ref.id)

        for ref in self.role_api.list_tenant_roles_for_user(id):
            self.role_api.rolegrant_delete(ref.id)

    def get_by_email(self, email):
        query = ('(%s=%s)' % (self.attribute_mapping['mail'],
                              ldap_filter.escape_filter_chars(email)))
        users = self.get_all(query)
        try:
            return users[0]
        except IndexError:
            return None

    def user_roles_by_tenant(self, user_id, tenant_id):
        return self.role_api.list_tenant_roles_for_user(user_id, tenant_id)

    def get_by_tenant(self, user_id, tenant_id):
        user_dn = self._id_to_dn(user_id)
        user = self.get(user_id)
        tenant = self.tenant_api._ldap_get(tenant_id,
                                           '(member=%s)' % (user_dn,))
        if tenant is not None:
            return user
        else:
            if self.role_api.list_tenant_roles_for_user(user_id, tenant_id):
                return user
        return None

    def user_role_add(self, values):
        return self.role_api.add_user(values.role_id, values.user_id,
                                      values.tenant_id)

    def users_get_page(self, marker, limit):
        return self.get_page(marker, limit)

    def users_get_page_markers(self, marker, limit):
        return self.get_page_markers(marker, limit)

    def users_get_by_tenant_get_page(self, tenant_id, role_id, marker, limit):
        return self._get_page(marker,
                              limit,
                              self.tenant_api.get_users(tenant_id, role_id))

    def users_get_by_tenant_get_page_markers(self, tenant_id, role_id, marker,
                                             limit):
        return self._get_page_markers(
            marker, limit, self.tenant_api.get_users(tenant_id, role_id))

    def check_password(self, user_id, password):
        user = self.get(user_id)
        return utils.check_password(password, user.password)


# TODO(termie): turn this into a data object and move logic to driver
class TenantApi(common_ldap.BaseLdap, ApiShimMixin):
    DEFAULT_OU = 'ou=Groups'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'groupOfNames'
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_MEMBER_ATTRIBUTE = 'member'
    DEFAULT_ATTRIBUTE_IGNORE = []
    options_name = 'tenant'
    attribute_mapping = {'name': 'ou',
                         'description': 'desc',
                         'tenantId': 'cn',
                         'enabled': 'enabled'}
    model = models.Tenant

    def __init__(self, conf):
        super(TenantApi, self).__init__(conf)
        self.api = ApiShim(conf)
        self.attribute_mapping['name'] = conf.ldap.tenant_name_attribute
        self.attribute_mapping['description'] = conf.ldap.tenant_desc_attribute
        self.attribute_mapping['enabled'] = conf.ldap.tenant_enabled_attribute
        self.member_attribute = (getattr(conf.ldap, 'tenant_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self.attribute_ignore = (getattr(conf.ldap, 'tenant_attribute_ignore')
                                 or self.DEFAULT_ATTRIBUTE_IGNORE)

    def get(self, id, filter=None):
        """Replaces exception.NotFound with exception.TenantNotFound."""
        try:
            return super(TenantApi, self).get(id, filter)
        except exception.NotFound:
            raise exception.TenantNotFound(tenant_id=id)

    def get_by_name(self, name, filter=None):  # pylint: disable=W0221,W0613
        search_filter = ('(%s=%s)'
                         % (self.attribute_mapping['name'],
                            ldap_filter.escape_filter_chars(name)))
        tenants = self.get_all(search_filter)
        try:
            return tenants[0]
        except IndexError:
            raise exception.TenantNotFound(tenant_id=name)

    def create(self, values):
        self.affirm_unique(values)
        data = values.copy()
        if data.get('id') is None:
            data['id'] = uuid.uuid4().hex
        return super(TenantApi, self).create(data)

    def get_user_tenants(self, user_id):
        """Returns list of tenants a user has access to

        Always includes default tenants.
        """
        user_dn = self.user_api._id_to_dn(user_id)
        query = '(%s=%s)' % (self.member_attribute, user_dn)
        memberships = self.get_all(query)
        return memberships

    def list_for_user_get_page(self, user, marker, limit):
        return self._get_page(marker, limit, self.get_user_tenants(user['id']))

    def list_for_user_get_page_markers(self, user, marker, limit):
        return self._get_page_markers(
            marker, limit, self.get_user_tenants(user['id']))

    def is_empty(self, id):
        tenant = self._ldap_get(id)
        members = tenant[1].get(self.member_attribute, [])
        if self.use_dumb_member:
            empty = members == [self.dumb_member]
        else:
            empty = len(members) == 0
        return empty and len(self.role_api.get_role_assignments(id)) == 0

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
            super(TenantApi, self).deleteTree(id)
        else:
            self.role_api.roles_delete_subtree_by_tenant(id)
            super(TenantApi, self).delete(id)

    def update(self, id, values):
        try:
            old_obj = self.get(id)
        except exception.NotFound:
            raise exception.TenantNotFound(tenant_id=id)
        if old_obj['name'] != values['name']:
            msg = 'Changing Name not supported by LDAP'
            raise exception.NotImplemented(message=msg)
        super(TenantApi, self).update(id, values, old_obj)


class UserRoleAssociation(object):
    """Role Grant model."""

    def __init__(self, user_id=None, role_id=None, tenant_id=None,
                 *args, **kw):
        self.user_id = str(user_id)
        self.role_id = role_id
        self.tenant_id = str(tenant_id)


# TODO(termie): turn this into a data object and move logic to driver
class RoleApi(common_ldap.BaseLdap, ApiShimMixin):
    DEFAULT_OU = 'ou=Roles'
    DEFAULT_STRUCTURAL_CLASSES = []
    options_name = 'role'
    DEFAULT_OBJECTCLASS = 'organizationalRole'
    DEFAULT_MEMBER_ATTRIBUTE = 'roleOccupant'
    DEFAULT_ATTRIBUTE_IGNORE = []
    attribute_mapping = {'name': 'cn',
                         #'serviceId': 'service_id',
                         }
    model = models.Tenant

    def __init__(self, conf):
        super(RoleApi, self).__init__(conf)
        self.api = ApiShim(conf)
        self.attribute_mapping['name'] = conf.ldap.role_name_attribute
        self.member_attribute = (getattr(conf.ldap, 'role_member_attribute')
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)
        self.attribute_ignore = (getattr(conf.ldap, 'role_attribute_ignore')
                                 or self.DEFAULT_ATTRIBUTE_IGNORE)

    @staticmethod
    def _create_ref(role_id, tenant_id, user_id):
        role_id = '' if role_id is None else str(role_id)
        tenant_id = '' if tenant_id is None else str(tenant_id)
        user_id = '' if user_id is None else str(user_id)
        return '%d-%d-%s%s%s' % (len(role_id),
                                 len(tenant_id),
                                 role_id,
                                 tenant_id,
                                 user_id)

    @staticmethod
    def _explode_ref(rolegrant):
        a = rolegrant.split('-', 2)
        len_role = int(a[0])
        len_tenant = int(a[1])
        role_id = a[2][:len_role]
        role_id = None if len(role_id) == 0 else str(role_id)
        tenant_id = a[2][len_role:len_tenant + len_role]
        tenant_id = None if len(tenant_id) == 0 else str(tenant_id)
        user_id = a[2][len_tenant + len_role:]
        user_id = None if len(user_id) == 0 else str(user_id)
        return role_id, tenant_id, user_id

    def _subrole_id_to_dn(self, role_id, tenant_id):
        if tenant_id is None:
            return self._id_to_dn(role_id)
        else:
            return 'cn=%s,%s' % (ldap.dn.escape_dn_chars(role_id),
                                 self.tenant_api._id_to_dn(tenant_id))

    def get(self, id, filter=None):
        model = super(RoleApi, self).get(id, filter)
        return model

    def create(self, values):
        #values['id'] = values['name']
        #delattr(values, 'name')

        return super(RoleApi, self).create(values)

    # pylint: disable=W0221
    def get_by_name(self, name, filter=None):
        roles = self.get_all('(%s=%s)' %
                             (self.attribute_mapping['name'],
                              ldap_filter.escape_filter_chars(name)))
        try:
            return roles[0]
        except IndexError:
            raise exception.RoleNotFound(role_id=name)

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
                raise Exception("Role %s not found" % (role_id,))

            attrs = [('objectClass', [self.object_class]),
                     (self.member_attribute, [user_dn])]

            if self.use_dumb_member:
                attrs[1][1].append(self.dumb_member)
            try:
                conn.add_s(role_dn, attrs)
            except Exception as inst:
                    raise inst

        return UserRoleAssociation(
            id=self._create_ref(role_id, tenant_id, user_id),
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
                raise exception.RoleNotFound(role_id=roll_id)
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

    def get_by_service(self, service_id):
        roles = self.get_all('(service_id=%s)' %
                             ldap_filter.escape_filter_chars(service_id))
        try:
            res = []
            for role in roles:
                res.append(role)
            return res
        except IndexError:
            return None

    def get_role_assignments(self, tenant_id):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        tenant_dn = self.tenant_api._id_to_dn(tenant_id)

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
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))

        return res

    def list_global_roles_for_user(self, user_id):
        user_dn = self.user_api._id_to_dn(user_id)
        roles = self.get_all('(%s=%s)' % (self.member_attribute, user_dn))
        return [UserRoleAssociation(
                id=self._create_ref(role.id, None, user_id),
                role_id=role.id,
                user_id=user_id) for role in roles]

    def list_tenant_roles_for_user(self, user_id, tenant_id=None):
        conn = self.get_connection()
        user_dn = self.user_api._id_to_dn(user_id)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,
                                                user_dn)
        if tenant_id is not None:
            tenant_dn = self.tenant_api._id_to_dn(tenant_id)
            try:
                roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            except ldap.NO_SUCH_OBJECT:
                return []

            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                res.append(UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        else:
            try:
                roles = conn.search_s(self.tenant_api.tree_dn,
                                      ldap.SCOPE_SUBTREE,
                                      query)
            except ldap.NO_SUCH_OBJECT:
                return []

            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                tenant_id = ldap.dn.str2dn(role_dn)[1][0][1]
                res.append(UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def rolegrant_get(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.user_api._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,
                                                user_dn)
        conn = self.get_connection()
        try:
            res = conn.search_s(role_dn, ldap.SCOPE_BASE, query)
        except ldap.NO_SUCH_OBJECT:
            return None
        if len(res) == 0:
            return None
        return UserRoleAssociation(id=id,
                                   role_id=role_id,
                                   tenant_id=tenant_id,
                                   user_id=user_id)

    def rolegrant_delete(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.user_api._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.get_connection()
        try:
            conn.modify_s(role_dn, [(ldap.MOD_DELETE, '', [user_dn])])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.Error("No such user in role")

    def rolegrant_get_page(self, marker, limit, user_id, tenant_id):
        all_roles = []
        if tenant_id is None:
            all_roles += self.list_global_roles_for_user(user_id)
        else:
            for tenant in self.tenant_api.get_all():
                all_roles += self.list_tenant_roles_for_user(user_id,
                                                             tenant['id'])
        return self._get_page(marker, limit, all_roles)

    def rolegrant_get_page_markers(self, user_id, tenant_id, marker, limit):
        all_roles = []
        if tenant_id is None:
            all_roles = self.list_global_roles_for_user(user_id)
        else:
            for tenant in self.tenant_api.get_all():
                all_roles += self.list_tenant_roles_for_user(user_id,
                                                             tenant['id'])
        return self._get_page_markers(marker, limit, all_roles)

    def get_by_service_get_page(self, service_id, marker, limit):
        all_roles = self.get_by_service(service_id)
        return self._get_page(marker, limit, all_roles)

    def get_by_service_get_page_markers(self, service_id, marker, limit):
        all_roles = self.get_by_service(service_id)
        return self._get_page_markers(marker, limit, all_roles)

    def rolegrant_list_by_role(self, id):
        role_dn = self._id_to_dn(id)
        try:
            roles = self.get_all('(%s=%s)' % (self.member_attribute, role_dn))
        except ldap.NO_SUCH_OBJECT:
            return []

        res = []
        for role_dn, attrs in roles:
            try:
                user_dns = attrs[self.member_attribute]
                tenant_dns = attrs['tenant']
            except KeyError:
                continue

            for user_dn in user_dns:
                if self.use_dumb_member and user_dn == self.dumb_member:
                    continue
                user_id = self.user_api._dn_to_id(user_dn)
                tenant_id = None
                if tenant_dns is not None:
                    for tenant_dn in tenant_dns:
                        tenant_id = self.tenant_api._dn_to_id(tenant_dn)
                role_id = self._dn_to_id(role_dn)
                res.append(UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def roles_delete_subtree_by_tenant(self, tenant_id):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        tenant_dn = self.tenant_api._id_to_dn(tenant_id)
        try:
            roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            for role_dn, _ in roles:
                try:
                    conn.delete_s(role_dn)
                except Exception as inst:
                    raise inst
        except ldap.NO_SUCH_OBJECT:
            pass

    def rolegrant_get_by_ids(self, user_id, role_id, tenant_id):
        conn = self.get_connection()
        user_dn = self.user_api._id_to_dn(user_id)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,
                                                user_dn)

        if tenant_id is not None:
            tenant_dn = self.tenant_api._id_to_dn(tenant_id)
            try:
                roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            except ldap.NO_SUCH_OBJECT:
                return None

            if len(roles) == 0:
                return None

            for role_dn, _ in roles:
                ldap_role_id = self._dn_to_id(role_dn)
                if role_id == ldap_role_id:
                    res = UserRoleAssociation(
                        id=self._create_ref(role_id, tenant_id, user_id),
                        user_id=user_id,
                        role_id=role_id,
                        tenant_id=tenant_id)
                    return res
        else:
            try:
                roles = self.get_all('(%s=%s)' % (self.member_attribute,
                                                  user_dn))
            except ldap.NO_SUCH_OBJECT:
                return None

            if len(roles) == 0:
                return None

            for role in roles:
                if role.id == role_id:
                    return UserRoleAssociation(
                        id=self._create_ref(role.id, None, user_id),
                        role_id=role.id,
                        user_id=user_id)
        return None

    def update(self, role_id, role):
        if role['id'] != role_id:
            raise exception.ValidationError('Cannot change role ID')
        try:
            old_name = self.get_by_name(role['name'])
            raise exception.Conflict('Cannot duplicate name %s' % role['name'])
        except exception.NotFound:
            pass
        try:
            super(RoleApi, self).update(role_id, role)
        except exception.NotFound:
            raise exception.RoleNotFound(role_id=role_id)

    def delete(self, id):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        tenant_dn = self.tenant_api.tree_dn
        try:
            for role_dn, _ in conn.search_s(tenant_dn,
                                            ldap.SCOPE_SUBTREE,
                                            query):
                conn.delete_s(role_dn)
        except ldap.NO_SUCH_OBJECT:
            pass
        super(RoleApi, self).delete(id)
