# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Fake LDAP server for test harness.

This class does very little error checking, and knows nothing about ldap
class definitions.  It implements the minimum emulation of the python ldap
library to work with nova.

"""

import re
import shelve

import ldap
from oslo_config import cfg
from oslo_log import log
import six
from six import moves

from keystone.common.ldap import core
from keystone import exception


SCOPE_NAMES = {
    ldap.SCOPE_BASE: 'SCOPE_BASE',
    ldap.SCOPE_ONELEVEL: 'SCOPE_ONELEVEL',
    ldap.SCOPE_SUBTREE: 'SCOPE_SUBTREE',
}

# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366991(v=vs.85).aspx  # noqa
CONTROL_TREEDELETE = '1.2.840.113556.1.4.805'

LOG = log.getLogger(__name__)
CONF = cfg.CONF


def _internal_attr(attr_name, value_or_values):
    def normalize_value(value):
        return core.utf8_decode(value)

    def normalize_dn(dn):
        # Capitalize the attribute names as an LDAP server might.

        # NOTE(blk-u): Special case for this tested value, used with
        # test_user_id_comma. The call to str2dn here isn't always correct
        # here, because `dn` is escaped for an LDAP filter. str2dn() normally
        # works only because there's no special characters in `dn`.
        if dn == 'cn=Doe\\5c, John,ou=Users,cn=example,cn=com':
            return 'CN=Doe\\, John,OU=Users,CN=example,CN=com'

        # NOTE(blk-u): Another special case for this tested value. When a
        # roleOccupant has an escaped comma, it gets converted to \2C.
        if dn == 'cn=Doe\\, John,ou=Users,cn=example,cn=com':
            return 'CN=Doe\\2C John,OU=Users,CN=example,CN=com'

        dn = ldap.dn.str2dn(core.utf8_encode(dn))
        norm = []
        for part in dn:
            name, val, i = part[0]
            name = core.utf8_decode(name)
            name = name.upper()
            name = core.utf8_encode(name)
            norm.append([(name, val, i)])
        return core.utf8_decode(ldap.dn.dn2str(norm))

    if attr_name in ('member', 'roleOccupant'):
        attr_fn = normalize_dn
    else:
        attr_fn = normalize_value

    if isinstance(value_or_values, list):
        return [attr_fn(x) for x in value_or_values]
    return [attr_fn(value_or_values)]


def _match_query(query, attrs, attrs_checked):
    """Match an ldap query to an attribute dictionary.

    The characters &, |, and ! are supported in the query. No syntax checking
    is performed, so malformed queries will not work correctly.
    """
    # cut off the parentheses
    inner = query[1:-1]
    if inner.startswith(('&', '|')):
        if inner[0] == '&':
            matchfn = all
        else:
            matchfn = any
        # cut off the & or |
        groups = _paren_groups(inner[1:])
        return matchfn(_match_query(group, attrs, attrs_checked)
                       for group in groups)
    if inner.startswith('!'):
        # cut off the ! and the nested parentheses
        return not _match_query(query[2:-1], attrs, attrs_checked)

    (k, _sep, v) = inner.partition('=')
    attrs_checked.add(k.lower())
    return _match(k, v, attrs)


def _paren_groups(source):
    """Split a string into parenthesized groups."""
    count = 0
    start = 0
    result = []
    for pos in moves.range(len(source)):
        if source[pos] == '(':
            if count == 0:
                start = pos
            count += 1
        if source[pos] == ')':
            count -= 1
            if count == 0:
                result.append(source[start:pos + 1])
    return result


def _match(key, value, attrs):
    """Match a given key and value against an attribute list."""

    def match_with_wildcards(norm_val, val_list):
        # Case insensitive checking with wildcards
        if norm_val.startswith('*'):
            if norm_val.endswith('*'):
                # Is the string anywhere in the target?
                for x in val_list:
                    if norm_val[1:-1] in x:
                        return True
            else:
                # Is the string at the end of the target?
                for x in val_list:
                    if (norm_val[1:] ==
                            x[len(x) - len(norm_val) + 1:]):
                        return True
        elif norm_val.endswith('*'):
            # Is the string at the start of the target?
            for x in val_list:
                if norm_val[:-1] == x[:len(norm_val) - 1]:
                    return True
        else:
            # Is the string an exact match?
            for x in val_list:
                if check_value == x:
                    return True
        return False

    if key not in attrs:
        return False
    # This is a pure wild card search, so the answer must be yes!
    if value == '*':
        return True
    if key == 'serviceId':
        # for serviceId, the backend is returning a list of numbers
        # make sure we convert them to strings first before comparing
        # them
        str_sids = [six.text_type(x) for x in attrs[key]]
        return six.text_type(value) in str_sids
    if key != 'objectclass':
        check_value = _internal_attr(key, value)[0].lower()
        norm_values = list(
            _internal_attr(key, x)[0].lower() for x in attrs[key])
        return match_with_wildcards(check_value, norm_values)
    # it is an objectclass check, so check subclasses
    values = _subs(value)
    for v in values:
        if v in attrs[key]:
            return True
    return False


def _subs(value):
    """Returns a list of subclass strings.

    The strings represent the ldap objectclass plus any subclasses that
    inherit from it. Fakeldap doesn't know about the ldap object structure,
    so subclasses need to be defined manually in the dictionary below.

    """
    subs = {'groupOfNames': ['keystoneTenant',
                             'keystoneRole',
                             'keystoneTenantRole']}
    if value in subs:
        return [value] + subs[value]
    return [value]


server_fail = False


class FakeShelve(dict):

    def sync(self):
        pass


FakeShelves = {}


class FakeLdap(core.LDAPHandler):
    """Emulate the python-ldap API.

    The python-ldap API requires all strings to be UTF-8 encoded. This
    is assured by the caller of this interface
    (i.e. KeystoneLDAPHandler).

    However, internally this emulation MUST process and store strings
    in a canonical form which permits operations on
    characters. Encoded strings do not provide the ability to operate
    on characters. Therefore this emulation accepts UTF-8 encoded
    strings, decodes them to unicode for operations internal to this
    emulation, and encodes them back to UTF-8 when returning values
    from the emulation.

    """

    __prefix = 'ldap:'

    def __init__(self, conn=None):
        super(FakeLdap, self).__init__(conn=conn)
        self._ldap_options = {ldap.OPT_DEREF: ldap.DEREF_NEVER}

    def connect(self, url, page_size=0, alias_dereferencing=None,
                use_tls=False, tls_cacertfile=None, tls_cacertdir=None,
                tls_req_cert='demand', chase_referrals=None, debug_level=None,
                use_pool=None, pool_size=None, pool_retry_max=None,
                pool_retry_delay=None, pool_conn_timeout=None,
                pool_conn_lifetime=None):
        if url.startswith('fake://memory'):
            if url not in FakeShelves:
                FakeShelves[url] = FakeShelve()
            self.db = FakeShelves[url]
        else:
            self.db = shelve.open(url[7:])

        using_ldaps = url.lower().startswith("ldaps")

        if use_tls and using_ldaps:
            raise AssertionError('Invalid TLS / LDAPS combination')

        if use_tls:
            if tls_cacertfile:
                ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, tls_cacertfile)
            elif tls_cacertdir:
                ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, tls_cacertdir)
            if tls_req_cert in list(core.LDAP_TLS_CERTS.values()):
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, tls_req_cert)
            else:
                raise ValueError("invalid TLS_REQUIRE_CERT tls_req_cert=%s",
                                 tls_req_cert)

        if alias_dereferencing is not None:
            self.set_option(ldap.OPT_DEREF, alias_dereferencing)
        self.page_size = page_size

        self.use_pool = use_pool
        self.pool_size = pool_size
        self.pool_retry_max = pool_retry_max
        self.pool_retry_delay = pool_retry_delay
        self.pool_conn_timeout = pool_conn_timeout
        self.pool_conn_lifetime = pool_conn_lifetime

    def dn(self, dn):
        return core.utf8_decode(dn)

    def _dn_to_id_attr(self, dn):
        return core.utf8_decode(ldap.dn.str2dn(core.utf8_encode(dn))[0][0][0])

    def _dn_to_id_value(self, dn):
        return core.utf8_decode(ldap.dn.str2dn(core.utf8_encode(dn))[0][0][1])

    def key(self, dn):
        return '%s%s' % (self.__prefix, self.dn(dn))

    def simple_bind_s(self, who='', cred='',
                      serverctrls=None, clientctrls=None):
        """This method is ignored, but provided for compatibility."""
        if server_fail:
            raise ldap.SERVER_DOWN
        whos = ['cn=Admin', CONF.ldap.user]
        if who in whos and cred in ['password', CONF.ldap.password]:
            return

        try:
            attrs = self.db[self.key(who)]
        except KeyError:
            LOG.debug('bind fail: who=%s not found', core.utf8_decode(who))
            raise ldap.NO_SUCH_OBJECT

        db_password = None
        try:
            db_password = attrs['userPassword'][0]
        except (KeyError, IndexError):
            LOG.debug('bind fail: password for who=%s not found',
                      core.utf8_decode(who))
            raise ldap.INAPPROPRIATE_AUTH

        if cred != db_password:
            LOG.debug('bind fail: password for who=%s does not match',
                      core.utf8_decode(who))
            raise ldap.INVALID_CREDENTIALS

    def unbind_s(self):
        """This method is ignored, but provided for compatibility."""
        if server_fail:
            raise ldap.SERVER_DOWN

    def add_s(self, dn, modlist):
        """Add an object with the specified attributes at dn."""
        if server_fail:
            raise ldap.SERVER_DOWN

        id_attr_in_modlist = False
        id_attr = self._dn_to_id_attr(dn)
        id_value = self._dn_to_id_value(dn)

        # The LDAP API raises a TypeError if attr name is None.
        for k, dummy_v in modlist:
            if k is None:
                raise TypeError('must be string, not None. modlist=%s' %
                                modlist)

            if k == id_attr:
                for val in dummy_v:
                    if core.utf8_decode(val) == id_value:
                        id_attr_in_modlist = True

        if not id_attr_in_modlist:
            LOG.debug('id_attribute=%(attr)s missing, attributes=%(attrs)s' %
                      {'attr': id_attr, 'attrs': modlist})
            raise ldap.NAMING_VIOLATION
        key = self.key(dn)
        LOG.debug('add item: dn=%(dn)s, attrs=%(attrs)s', {
            'dn': core.utf8_decode(dn), 'attrs': modlist})
        if key in self.db:
            LOG.debug('add item failed: dn=%s is already in store.',
                      core.utf8_decode(dn))
            raise ldap.ALREADY_EXISTS(dn)

        self.db[key] = {k: _internal_attr(k, v) for k, v in modlist}
        self.db.sync()

    def delete_s(self, dn):
        """Remove the ldap object at specified dn."""
        return self.delete_ext_s(dn, serverctrls=[])

    def _getChildren(self, dn):
        return [k for k, v in self.db.items()
                if re.match('%s.*,%s' % (
                            re.escape(self.__prefix),
                            re.escape(self.dn(dn))), k)]

    def delete_ext_s(self, dn, serverctrls, clientctrls=None):
        """Remove the ldap object at specified dn."""
        if server_fail:
            raise ldap.SERVER_DOWN

        try:
            if CONTROL_TREEDELETE in [c.controlType for c in serverctrls]:
                LOG.debug('FakeLdap subtree_delete item: dn=%s',
                          core.utf8_decode(dn))
                children = self._getChildren(dn)
                for c in children:
                    del self.db[c]

            key = self.key(dn)
            LOG.debug('FakeLdap delete item: dn=%s', core.utf8_decode(dn))
            del self.db[key]
        except KeyError:
            LOG.debug('delete item failed: dn=%s not found.',
                      core.utf8_decode(dn))
            raise ldap.NO_SUCH_OBJECT
        self.db.sync()

    def modify_s(self, dn, modlist):
        """Modify the object at dn using the attribute list.

        :param dn: an LDAP DN
        :param modlist: a list of tuples in the following form:
                      ([MOD_ADD | MOD_DELETE | MOD_REPACE], attribute, value)
        """
        if server_fail:
            raise ldap.SERVER_DOWN

        key = self.key(dn)
        LOG.debug('modify item: dn=%(dn)s attrs=%(attrs)s', {
            'dn': core.utf8_decode(dn), 'attrs': modlist})
        try:
            entry = self.db[key]
        except KeyError:
            LOG.debug('modify item failed: dn=%s not found.',
                      core.utf8_decode(dn))
            raise ldap.NO_SUCH_OBJECT

        for cmd, k, v in modlist:
            values = entry.setdefault(k, [])
            if cmd == ldap.MOD_ADD:
                v = _internal_attr(k, v)
                for x in v:
                    if x in values:
                        raise ldap.TYPE_OR_VALUE_EXISTS
                values += v
            elif cmd == ldap.MOD_REPLACE:
                values[:] = _internal_attr(k, v)
            elif cmd == ldap.MOD_DELETE:
                if v is None:
                    if not values:
                        LOG.debug('modify item failed: '
                                  'item has no attribute "%s" to delete', k)
                        raise ldap.NO_SUCH_ATTRIBUTE
                    values[:] = []
                else:
                    for val in _internal_attr(k, v):
                        try:
                            values.remove(val)
                        except ValueError:
                            LOG.debug('modify item failed: '
                                      'item has no attribute "%(k)s" with '
                                      'value "%(v)s" to delete', {
                                          'k': k, 'v': val})
                            raise ldap.NO_SUCH_ATTRIBUTE
            else:
                LOG.debug('modify item failed: unknown command %s', cmd)
                raise NotImplementedError('modify_s action %s not'
                                          ' implemented' % cmd)
        self.db[key] = entry
        self.db.sync()

    def search_s(self, base, scope,
                 filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        """Search for all matching objects under base using the query.

        Args:
        base -- dn to search under
        scope -- search scope (base, subtree, onelevel)
        filterstr -- filter objects by
        attrlist -- attrs to return. Returns all attrs if not specified

        """
        if server_fail:
            raise ldap.SERVER_DOWN

        if (not filterstr) and (scope != ldap.SCOPE_BASE):
            raise AssertionError('Search without filter on onelevel or '
                                 'subtree scope')

        if scope == ldap.SCOPE_BASE:
            try:
                item_dict = self.db[self.key(base)]
            except KeyError:
                LOG.debug('search fail: dn not found for SCOPE_BASE')
                raise ldap.NO_SUCH_OBJECT
            results = [(base, item_dict)]
        elif scope == ldap.SCOPE_SUBTREE:
            # FIXME - LDAP search with SUBTREE scope must return the base
            # entry, but the code below does _not_.  Unfortunately, there are
            # several tests that depend on this broken behavior, and fail
            # when the base entry is returned in the search results.  The
            # fix is easy here, just initialize results as above for
            # the SCOPE_BASE case.
            # https://bugs.launchpad.net/keystone/+bug/1368772
            try:
                item_dict = self.db[self.key(base)]
            except KeyError:
                LOG.debug('search fail: dn not found for SCOPE_SUBTREE')
                raise ldap.NO_SUCH_OBJECT
            results = [(base, item_dict)]
            extraresults = [(k[len(self.__prefix):], v)
                            for k, v in self.db.items()
                            if re.match('%s.*,%s' %
                                        (re.escape(self.__prefix),
                                         re.escape(self.dn(base))), k)]
            results.extend(extraresults)
        elif scope == ldap.SCOPE_ONELEVEL:

            def get_entries():
                base_dn = ldap.dn.str2dn(core.utf8_encode(base))
                base_len = len(base_dn)

                for k, v in self.db.items():
                    if not k.startswith(self.__prefix):
                        continue
                    k_dn_str = k[len(self.__prefix):]
                    k_dn = ldap.dn.str2dn(core.utf8_encode(k_dn_str))
                    if len(k_dn) != base_len + 1:
                        continue
                    if k_dn[-base_len:] != base_dn:
                        continue
                    yield (k_dn_str, v)

            results = list(get_entries())

        else:
            # openldap client/server raises PROTOCOL_ERROR for unexpected scope
            raise ldap.PROTOCOL_ERROR

        objects = []
        for dn, attrs in results:
            # filter the objects by filterstr
            id_attr, id_val, _ = ldap.dn.str2dn(core.utf8_encode(dn))[0][0]
            id_attr = core.utf8_decode(id_attr)
            id_val = core.utf8_decode(id_val)
            match_attrs = attrs.copy()
            match_attrs[id_attr] = [id_val]
            attrs_checked = set()
            if not filterstr or _match_query(filterstr, match_attrs,
                                             attrs_checked):
                if (filterstr and
                        (scope != ldap.SCOPE_BASE) and
                        ('objectclass' not in attrs_checked)):
                    raise AssertionError('No objectClass in search filter')
                # filter the attributes by attrlist
                attrs = {k: v for k, v in attrs.items()
                         if not attrlist or k in attrlist}
                objects.append((dn, attrs))

        return objects

    def set_option(self, option, invalue):
        self._ldap_options[option] = invalue

    def get_option(self, option):
        value = self._ldap_options.get(option, None)
        return value

    def search_ext(self, base, scope,
                   filterstr='(objectClass=*)', attrlist=None, attrsonly=0,
                   serverctrls=None, clientctrls=None,
                   timeout=-1, sizelimit=0):
        raise exception.NotImplemented()

    def result3(self, msgid=ldap.RES_ANY, all=1, timeout=None,
                resp_ctrl_classes=None):
        raise exception.NotImplemented()


class FakeLdapPool(FakeLdap):
    """Emulate the python-ldap API with pooled connections.

    This class is used as connector class in PooledLDAPHandler.

    """

    def __init__(self, uri, retry_max=None, retry_delay=None, conn=None):
        super(FakeLdapPool, self).__init__(conn=conn)
        self.url = uri
        self.connected = None
        self.conn = self
        self._connection_time = 5  # any number greater than 0

    def get_lifetime(self):
        return self._connection_time

    def simple_bind_s(self, who=None, cred=None,
                      serverctrls=None, clientctrls=None):
        if self.url.startswith('fakepool://memory'):
            if self.url not in FakeShelves:
                FakeShelves[self.url] = FakeShelve()
            self.db = FakeShelves[self.url]
        else:
            self.db = shelve.open(self.url[11:])

        if not who:
            who = 'cn=Admin'
        if not cred:
            cred = 'password'

        super(FakeLdapPool, self).simple_bind_s(who=who, cred=cred,
                                                serverctrls=serverctrls,
                                                clientctrls=clientctrls)

    def unbind_ext_s(self):
        """Added to extend FakeLdap as connector class."""
        pass


class FakeLdapNoSubtreeDelete(FakeLdap):
    """FakeLdap subclass that does not support subtree delete

    Same as FakeLdap except delete will throw the LDAP error
    ldap.NOT_ALLOWED_ON_NONLEAF if there is an attempt to delete
    an entry that has children.
    """

    def delete_ext_s(self, dn, serverctrls, clientctrls=None):
        """Remove the ldap object at specified dn."""
        if server_fail:
            raise ldap.SERVER_DOWN

        try:
            children = self._getChildren(dn)
            if children:
                raise ldap.NOT_ALLOWED_ON_NONLEAF

        except KeyError:
            LOG.debug('delete item failed: dn=%s not found.',
                      core.utf8_decode(dn))
            raise ldap.NO_SUCH_OBJECT
        super(FakeLdapNoSubtreeDelete, self).delete_ext_s(dn,
                                                          serverctrls,
                                                          clientctrls)
