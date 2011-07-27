import ldap

from keystone import utils
from keystone.backends.api import BaseUserAPI
from keystone.backends.sqlalchemy.api.user import UserAPI as SQLUserAPI

from .. import models
from .base import BaseLdapAPI, add_redirects

class UserAPI(BaseLdapAPI, BaseUserAPI):
    DEFAULT_TREE_DN = 'ou=Users,dc=example,dc=com'
    options_name = 'user_tree_dn'
    object_class = 'keystoneUser'
    model = models.User
    attribute_mapping = { 'password': 'userPassword', 'email': 'mail' }
    attribute_ignore = ['tenant_id']
    
    def __check_and_use_hashed_password(self, values):
        if type(values) is dict and 'password' in values.keys():
            values['password'] = utils.get_hashed_password(values['password'])
        elif type(values) is models.User:
            values.password = utils.get_hashed_password(values.password)

    def _ldap_res_to_model(self, res):
        obj = super(UserAPI, self)._ldap_res_to_model(res)
        tenants = self.api.tenant.get_user_tenants(obj.id)
        if len(tenants) > 0:
            obj.tenant_id = tenants[0].id
        return obj

    def create(self, values):
        self.__check_and_use_hashed_password(values)
        super(UserAPI, self).create(values)
        if values['tenant_id'] is not None:
            self.api.tenant.add_user(values['tenant_id'], values['id'])

    def update(self, id, values):
        old_obj = self.get(id)
        try:
            new_tenant = values['tenant_id']
        except KeyError:
            pass
        else:
            if old_obj.tenant_id != new_tenant:
                self.api.tenant.remove_user(old_obj.tenant_id, id)
                self.api.tenant.add_user(new_tenant, id)
        super(UserAPI, self).update(id, values, old_obj)

    def get_by_email(self, email):
        users = self.get_all('(mail=%s)' % \
                            (ldap.filter.escape_filter_chars(email),))
        try:
            return users[0]
        except IndexError:
            return None

    def user_roles_by_tenant(self, user_id, tenant_id):
        return self.api.role.ref_get_all_tenant_roles(user_id, tenant_id)

    def get_by_tenant(self, id, tenant_id):
        user_dn = self._id_to_dn(id)
        user = self.get(id)
        tenant = self.api.tenant._ldap_get(tenant_id,
                                           '(member=%s)' % (user_dn,))
        if tenant is not None:
            return user
        else:
            return None

    def delete_tenant_user(self, id, tenant_id):
        self.api.tenant.remove_user(tenant_id, id)
        self.delete(id)

    def user_role_add(self, values):
        return self.api.role.add_user(values.role_id, values.user_id,
                                      values.tenant_id)

    def user_get_update(self, id):
        return self.get(id)

    def users_get_page(self, marker, limit):
        return self.get_page(marker, limit)

    def users_get_page_markers(self, marker, limit):
        return self.get_page_markers(marker, limit)

    def users_get_by_tenant_get_page(self, tenant_id, marker, limit):
        return self._get_page(marker, limit, 
                self.api.tenant.get_users(tenant_id))

    def users_get_by_tenant_get_page_markers(self, tenant_id, marker, limit):
        return self._get_page_markers(marker, limit,
                self.api.tenant.get_users(tenant_id))

    add_redirects(locals(), SQLUserAPI, [])
