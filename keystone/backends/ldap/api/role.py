import ldap

from keystone.backends.api import BaseTenantAPI
from keystone.common import exception

from keystone import models
from .base import  BaseLdapAPI


# pylint: disable=W0212, W0223
class RoleAPI(BaseLdapAPI, BaseTenantAPI):
    DEFAULT_TREE_DN = 'ou=Groups,dc=example,dc=com'
    DEFAULT_STRUCTURAL_CLASSES = ['groupOfNames']
    options_name = 'role'
    object_class = 'keystoneRole'
    model = models.Role
    attribute_mapping = {'description': 'desc', 'serviceId': 'service_id'}

    @staticmethod
    def _create_ref(role_id, tenant_id, user_id):
        role_id = '' if role_id is None else str(role_id)
        tenant_id = '' if tenant_id is None else str(tenant_id)
        user_id = '' if user_id is None else str(user_id)
        return '%d-%d-%s%s%s' % (len(role_id), len(tenant_id),
                                 role_id, tenant_id, user_id)

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
            return "cn=%s,%s" % (ldap.dn.escape_dn_chars(role_id),
                                 self.api.tenant._id_to_dn(tenant_id))

    def get(self, id, filter=None):
        model = super(RoleAPI, self).get(id, filter)
        if model:
            model['name'] = model['id']
        return model

    def create(self, values):
        values['id'] = values['name']
        delattr(values, 'name')

        return super(RoleAPI, self).create(values)

    # pylint: disable=W0221
    def get_by_name(self, name, filter=None):
        return self.get(name, filter)

    def add_user(self, role_id, user_id, tenant_id=None):
        user = self.api.user.get(user_id)
        if user is None:
            raise exception.NotFound("User %s not found" % (user_id,))
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.api.get_connection()
        user_dn = self.api.user._id_to_dn(user_id)
        try:
            conn.modify_s(role_dn, [(ldap.MOD_ADD, 'member', user_dn)])
        except ldap.TYPE_OR_VALUE_EXISTS:
            raise exception.Duplicate(
                "User %s already has role %s in tenant %s" % (user_id,
                    role_id, tenant_id))
        except ldap.NO_SUCH_OBJECT:
            if tenant_id is None or self.get(role_id) is None:
                raise exception.NotFound("Role %s not found" % (role_id,))
            attrs = [
                ('objectClass', ['keystoneTenantRole', 'groupOfNames']),
                ('member', [user_dn]),
                ('keystoneRole', self._id_to_dn(role_id)),
            ]
            if self.use_dumb_member:
                attrs[1][1].append(self.DUMB_MEMBER_DN)
            conn.add_s(role_dn, attrs)
        return models.UserRoleAssociation(
            id=self._create_ref(role_id, tenant_id, user_id),
            role_id=role_id, user_id=user_id, tenant_id=tenant_id)

    def get_by_service(self, service_id):
        roles = self.get_all('(service_id=%s)' % \
                    (ldap.filter.escape_filter_chars(service_id),))
        try:
            res = []
            for role in roles:
                res.append(role)
            return res
        except IndexError:
            return None

    def get_role_assignments(self, tenant_id):
        conn = self.api.get_connection()
        query = '(objectClass=keystoneTenantRole)'
        tenant_dn = self.api.tenant._id_to_dn(tenant_id)
        try:
            roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
        except ldap.NO_SUCH_OBJECT:
            return []
        res = []
        for role_dn, attrs in roles:
            try:
                user_dns = attrs['member']
            except KeyError:
                continue
            for user_dn in user_dns:
                if self.use_dumb_member and user_dn == self.DUMB_MEMBER_DN:
                    continue
                user_id = self.api.user._dn_to_id(user_dn)
                role_id = self._dn_to_id(role_dn)
                res.append(models.UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def list_global_roles_for_user(self, user_id):
        user_dn = self.api.user._id_to_dn(user_id)
        roles = self.get_all('(member=%s)' % (user_dn,))
        return [models.UserRoleAssociation(
                    id=self._create_ref(role.id, None, user_id),
                    role_id=role.id,
                    user_id=user_id) for role in roles]

    def list_tenant_roles_for_user(self, user_id, tenant_id=None):
        conn = self.api.get_connection()
        user_dn = self.api.user._id_to_dn(user_id)
        query = '(&(objectClass=keystoneTenantRole)(member=%s))' % (user_dn,)
        if tenant_id is not None:
            tenant_dn = self.api.tenant._id_to_dn(tenant_id)
            try:
                roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            except ldap.NO_SUCH_OBJECT:
                return []
            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                res.append(models.UserRoleAssociation(
                       id=self._create_ref(role_id, tenant_id, user_id),
                       user_id=user_id,
                       role_id=role_id,
                       tenant_id=tenant_id))
            return res
        else:
            try:
                roles = conn.search_s(self.api.tenant.tree_dn,
                                        ldap.SCOPE_SUBTREE, query)
            except ldap.NO_SUCH_OBJECT:
                return []
            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                tenant_id = ldap.dn.str2dn(role_dn)[1][0][1]
                res.append(models.UserRoleAssociation(
                       id=self._create_ref(role_id, tenant_id, user_id),
                       user_id=user_id,
                       role_id=role_id,
                       tenant_id=tenant_id))
            return res

    def rolegrant_get(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.api.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        query = '(&(objectClass=keystoneTenantRole)(member=%s))' % (user_dn,)
        conn = self.api.get_connection()
        try:
            res = conn.search_s(role_dn, ldap.SCOPE_BASE, query)
        except ldap.NO_SUCH_OBJECT:
            return None
        if len(res) == 0:
            return None
        return models.UserRoleAssociation(id=id, role_id=role_id,
                                tenant_id=tenant_id, user_id=user_id)

    def rolegrant_delete(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.api.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.api.get_connection()
        try:
            conn.modify_s(role_dn, [(ldap.MOD_DELETE, 'member', [user_dn])])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.NotFound("No such user in role")

    def rolegrant_get_page(self, marker, limit, user_id, tenant_id):
        all_roles = []
        if tenant_id is None:
            all_roles += self.list_global_roles_for_user(user_id)
        else:
            for tenant in self.api.tenant.get_all():
                all_roles += self.list_tenant_roles_for_user(user_id,
                                                                    tenant.id)
        return self._get_page(marker, limit, all_roles)

    def rolegrant_get_page_markers(self, user_id, tenant_id, marker, limit):
        all_roles = []
        if tenant_id is None:
            all_roles = self.list_global_roles_for_user(user_id)
        else:
            for tenant in self.api.tenant.get_all():
                all_roles += self.list_tenant_roles_for_user(user_id,
                                                                    tenant.id)
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
            roles = self.get_all('(keystoneRole=%s)' % (role_dn,))
        except ldap.NO_SUCH_OBJECT:
            return []
        res = []
        for role_dn, attrs in roles:
            try:
                user_dns = attrs['member']
                tenant_dns = attrs['tenant']
            except KeyError:
                continue
            for user_dn in user_dns:
                if self.use_dumb_member and user_dn == self.DUMB_MEMBER_DN:
                    continue
                user_id = self.api.user._dn_to_id(user_dn)
                tenant_id = None
                if tenant_dns is not None:
                    for tenant_dn in tenant_dns:
                        tenant_id = self.api.tenant._dn_to_id(tenant_dn)
                role_id = self._dn_to_id(role_dn)
                res.append(models.UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def rolegrant_get_by_ids(self, user_id, role_id, tenant_id):
        conn = self.api.get_connection()
        user_dn = self.api.user._id_to_dn(user_id)
        query = '(&(objectClass=keystoneTenantRole)(member=%s))' % (user_dn,)
        if tenant_id is not None:
            tenant_dn = self.api.tenant._id_to_dn(tenant_id)
            try:
                roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            except ldap.NO_SUCH_OBJECT:
                return None
            if len(roles) == 0:
                return None
            for role_dn, _ in roles:
                ldap_role_id = self._dn_to_id(role_dn)
                if role_id == ldap_role_id:
                    res = models.UserRoleAssociation(
                           id=self._create_ref(role_id, tenant_id, user_id),
                           user_id=user_id,
                           role_id=role_id,
                           tenant_id=tenant_id)
                    return res
        else:
            try:
                roles = self.get_all('(member=%s)' % (user_dn,))
            except ldap.NO_SUCH_OBJECT:
                return None
            if len(roles) == 0:
                return None
            for role in roles:
                if role.id == role_id:
                    return models.UserRoleAssociation(
                                id=self._create_ref(role.id, None, user_id),
                                role_id=role.id,
                                user_id=user_id)
        return None
