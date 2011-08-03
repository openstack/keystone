import ldap

from .. import fakeldap
from .tenant import TenantAPI
from .user import UserAPI
from .role import RoleAPI


class API(object):
    apis = ['tenant', 'user', 'role']

    def __init__(self, options):
        self.LDAP_URL = options['ldap_url']
        self.LDAP_USER = options['ldap_user']
        self.LDAP_PASSWORD = options['ldap_password']
        self.tenant = TenantAPI(self, options)
        self.user = UserAPI(self, options)
        self.role = RoleAPI(self, options)

    def get_connection(self):
        if self.LDAP_URL.startswith('fake://'):
            conn = fakeldap.initialize(self.LDAP_URL)
        else:
            conn = ldap.initialize(self.LDAP_URL)
        conn.simple_bind_s(self.LDAP_USER, self.LDAP_PASSWORD)
        return conn
