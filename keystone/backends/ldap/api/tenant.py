import ldap
import uuid

from keystone.backends.api import BaseTenantAPI
from keystone.backends.sqlalchemy.api.tenant import TenantAPI as SQLTenantAPI

from keystone import models
from .base import  BaseLdapAPI, add_redirects


class TenantAPI(BaseLdapAPI, BaseTenantAPI):  # pylint: disable=W0223
    DEFAULT_TREE_DN = 'ou=Groups,dc=example,dc=com'
    DEFAULT_STRUCTURAL_CLASSES = ['groupOfNames']
    options_name = 'tenant'
    object_class = 'keystoneTenant'
    model = models.Tenant
    attribute_mapping = {'description': 'desc', 'enabled': 'keystoneEnabled',
                         'name': 'keystoneName'}

    def get_by_name(self, name, filter=None):  # pylint: disable=W0221,W0613
        tenants = self.get_all('(keystoneName=%s)' % \
                            (ldap.filter.escape_filter_chars(name),))
        try:
            return tenants[0]
        except IndexError:
            return None

    def create(self, values):
        data = values.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4())
        return super(TenantAPI, self).create(data)

    def get_user_tenants(self, user_id, include_roles=True):
        """Returns list of tenants a user has access to

        Always includes default tenants.
        Adds role assignments if 'include_roles' is True.
        """
        user_dn = self.api.user._id_to_dn(user_id)  # pylint: disable=W0212
        query = '(member=%s)' % (user_dn,)
        memberships = self.get_all(query)
        if include_roles:
            roles = self.api.role.list_tenant_roles_for_user(user_id)
            for role in roles:
                exists = False
                for tenant in memberships:
                    if tenant['id'] == role.tenant_id:
                        exists = True
                        break
                if not exists:
                    memberships.append(self.get(role.tenant_id))
        return memberships

    def list_for_user_get_page(self, user, marker, limit):
        return self._get_page(marker, limit, self.get_user_tenants(user.id))

    def list_for_user_get_page_markers(self, user, marker, limit):
        return self._get_page_markers(marker, limit,
                        self.get_user_tenants(user.id))

    def is_empty(self, id):
        tenant = self._ldap_get(id)
        members = tenant[1].get('member', [])
        if self.use_dumb_member:
            empty = members == [self.DUMB_MEMBER_DN]
        else:
            empty = len(members) == 0
        return empty and len(self.api.role.get_role_assignments(id)) == 0

    def get_role_assignments(self, tenant_id):
        return self.api.role.get_role_assignments(tenant_id)

    def add_user(self, tenant_id, user_id):
        conn = self.api.get_connection()
        conn.modify_s(self._id_to_dn(tenant_id),
            [(ldap.MOD_ADD, 'member',
              self.api.user._id_to_dn(user_id))])  # pylint: disable=W0212

    def remove_user(self, tenant_id, user_id):
        conn = self.api.get_connection()
        conn.modify_s(self._id_to_dn(tenant_id),
            [(ldap.MOD_DELETE, 'member',
              self.api.user._id_to_dn(user_id))])  # pylint: disable=W0212

    def get_users(self, tenant_id, role_id=None):
        tenant = self._ldap_get(tenant_id)
        res = []
        if not role_id:
            # Get users who have default tenant mapping
            for user_dn in tenant[1].get('member', []):
                if self.use_dumb_member and user_dn == self.DUMB_MEMBER_DN:
                    continue
                #pylint: disable=W0212
                res.append(self.api.user.get(self.api.user._dn_to_id(user_dn)))
        rolegrants = self.api.role.get_role_assignments(tenant_id)
        # Get users who are explicitly mapped via a tenant
        for rolegrant in rolegrants:
            if role_id is None or rolegrant.role_id == role_id:
                res.append(self.api.user.get(rolegrant.user_id))
        return res

    add_redirects(locals(), SQLTenantAPI, ['get_all_endpoints'])

    def delete(self, id):
        if not self.is_empty(id):
            raise fault.ForbiddenFault("You may not delete a tenant that "
                                       "contains users")
        super(TenantAPI, self).delete(id)
