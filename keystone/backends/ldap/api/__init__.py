import ldap
import logging

from .. import fakeldap
from .tenant import TenantAPI
from .user import UserAPI
from .role import RoleAPI

LOG = logging.getLogger('keystone.backends.ldap.api')


def py2ldap(val):
    if isinstance(val, str):
        return val
    elif isinstance(val, bool):
        return 'TRUE' if val else 'FALSE'
    else:
        return str(val)

LDAP_VALUES = {
    'TRUE': True,
    'FALSE': False,
}


def ldap2py(val):
    try:
        return LDAP_VALUES[val]
    except KeyError:
        pass
    try:
        return int(val)
    except ValueError:
        pass
    return val


def safe_iter(attrs):
    if attrs is None:
        return
    elif isinstance(attrs, list):
        for e in attrs:
            yield e
    else:
        yield attrs


class LDAPWrapper(object):
    def __init__(self, url):
        LOG.debug("LDAP init: url=%s", url)
        self.conn = ldap.initialize(url)

    def simple_bind_s(self, user, password):
        LOG.debug("LDAP bind: dn=%s", user)
        return self.conn.simple_bind_s(user, password)

    def add_s(self, dn, attrs):
        ldap_attrs = [(typ, map(py2ldap, safe_iter(values)))
                      for typ, values in attrs]
        if LOG.isEnabledFor(logging.DEBUG):
            sane_attrs = [(typ, values if typ != 'userPassword' else ['****'])
                          for typ, values in ldap_attrs]
            LOG.debug("LDAP add: dn=%s, attrs=%s", dn, sane_attrs)
        return self.conn.add_s(dn, ldap_attrs)

    def search_s(self, dn, scope, query):
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("LDAP search: dn=%s, scope=%s, query=%s", dn,
                        fakeldap.scope_names[scope], query)
        res = self.conn.search_s(dn, scope, query)
        return [(dn, dict([(typ, map(ldap2py, values))
                           for typ, values in attrs.iteritems()]))
                for dn, attrs in res]

    def modify_s(self, dn, modlist):
        ldap_modlist = [(op, typ, None if values is None else
                         map(py2ldap, safe_iter(values)))
                        for op, typ, values in modlist]
        if LOG.isEnabledFor(logging.DEBUG):
            sane_modlist = [(op, typ, values if typ != 'userPassword'
                            else ['****']) for op, typ, values in ldap_modlist]
            LOG.debug("LDAP modify: dn=%s, modlist=%s", dn, sane_modlist)
        return self.conn.modify_s(dn, ldap_modlist)

    def delete_s(self, dn):
        LOG.debug("LDAP delete: dn=%s", dn)
        return self.conn.delete_s(dn)


class API(object):
    apis = ['tenant', 'user', 'role']

    def __init__(self, conf):
        self.LDAP_URL = conf.ldap_url
        self.LDAP_USER = conf.ldap_user
        self.LDAP_PASSWORD = conf.ldap_password
        self.tenant = TenantAPI(self, conf)
        self.user = UserAPI(self, conf)
        self.role = RoleAPI(self, conf)

    def get_connection(self, user=None, password=None):
        if self.LDAP_URL.startswith('fake://'):
            conn = fakeldap.initialize(self.LDAP_URL)
        else:
            conn = LDAPWrapper(self.LDAP_URL)
        if user is None:
            user = self.LDAP_USER
        if password is None:
            password = self.LDAP_PASSWORD
        conn.simple_bind_s(user, password)
        return conn
