import ldap

from keystone.backends.api import BaseTenantAPI
from keystone.common import exception

from .. import models
from .base import  BaseLdapAPI


class RoleAPI(BaseLdapAPI, BaseTenantAPI):
    DEFAULT_TREE_DN = 'ou=Groups,dc=example,dc=com'
    options_name = 'role_tree_dn'
    object_class = 'keystoneRole'
    model = models.Role
    attribute_mapping = {'desc': 'description'}

    @staticmethod
    def _create_ref(role_id, tenant_id, user_id):
        role_id = '' if role_id is None else str(role_id)
        tenant_id = '' if tenant_id is None else str(tenant_id)
        user_id = '' if user_id is None else str(user_id)
        return '%d-%d-%s%s%s' % (len(role_id), len(tenant_id),
                                 role_id, tenant_id, user_id)

    @staticmethod
    def _explode_ref(role_ref):
        a = role_ref.split('-', 2)
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
                ('objectClass', 'keystoneTenantRole'),
                ('member', user_dn),
                ('role', self._id_to_dn(role_id)),
            ]
            conn.add_s(role_dn, attrs)
        return models.UserRoleAssociation(
            id=self._create_ref(role_id, tenant_id, user_id),
            role_id=role_id, user_id=user_id, tenant_id=tenant_id)

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
                user_id = ldap.dn.str2dn(user_dn)[0][0][1]
                role_id = ldap.dn.str2dn(role_dn)[0][0][1]
                res.append(models.UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def ref_get_all_global_roles(self, user_id):
        user_dn = self.api.user._id_to_dn(user_id)
        roles = self.get_all('(member=%s)' % (user_dn,))
        return [models.UserRoleAssociation(
                    id=self._create_ref(role.id, None, user_id),
                    role_id=role.id,
                    user_id=user_id) for role in roles]

    def ref_get_all_tenant_roles(self, user_id, tenant_id):
        conn = self.api.get_connection()
        user_dn = self.api.user._id_to_dn(user_id)
        tenant_dn = self.api.tenant._id_to_dn(tenant_id)
        query = '(&(objectClass=keystoneTenantRole)(member=%s))' % (user_dn,)
        try:
            roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
        except ldap.NO_SUCH_OBJECT:
            return []
        res = []
        for role_dn, _ in roles:
            role_id = ldap.dn.str2dn(role_dn)[0][0][1]
            res.append(models.UserRoleAssociation(
                   id=self._create_ref(role_id, tenant_id, user_id),
                   user_id=user_id,
                   role_id=role_id,
                   tenant_id=tenant_id))
        return res

    def ref_get(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.api.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        query = '(&(objectClass=keystoneTenantRole)(member=%s))' % (user_dn,)
        try:
            res = search_s(role_dn, ldap.SCOPE_BASE, query)
        except ldap.NO_SUCH_OBJECT:
            return None
        if len(res) == 0:
            return None
        return models.UserRoleAssociation(id=id, role_id=role_id,
                                tenant_id=tenant_id, user_id=user_id)

    def ref_delete(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.api.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.api.get_connection()
        try:
            conn.modify_s(role_dn, [(ldap.MOD_DELETE, 'member', [user_dn])])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.NotFound("No such user in role")

    def ref_get_page(self, marker, limit, user_id):
        all_roles = self.ref_get_all_global_roles(user_id)
        for tenant in self.api.tenant.get_all():
            all_roles += self.ref_get_all_tenant_roles(user_id, tenant.id)
        return self._get_page(marker, limit, all_roles)

    def ref_get_page_markers(self, user_id, marker, limit):
        all_roles = self.ref_get_all_global_roles(user_id)
        for tenant in self.api.tenant.get_all():
            all_roles += self.ref_get_all_tenant_roles(user_id, tenant.id)
        return self._get_page_markers(marker, limit, all_roles)
