# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.common import utils
from keystone.openstack.common import log as logging


SCOPE_NAMES = {
    ldap.SCOPE_BASE: 'SCOPE_BASE',
    ldap.SCOPE_ONELEVEL: 'SCOPE_ONELEVEL',
    ldap.SCOPE_SUBTREE: 'SCOPE_SUBTREE',
}


LOG = logging.getLogger(__name__)


def _process_attr(attr_name, value_or_values):
    attr_fn = lambda x: x

    def normalize_dn(dn):
        # Capitalize the attribute names as an LDAP server might.
        dn = ldap.dn.str2dn(dn)
        norm = []
        for part in dn:
            name, val, i = part[0]
            name = name.upper()
            norm.append([(name, val, i)])
        return ldap.dn.dn2str(norm)

    if attr_name in ('member', 'roleOccupant'):
        attr_fn = normalize_dn

    if isinstance(value_or_values, list):
        return [attr_fn(x) for x in value_or_values]
    return [attr_fn(value_or_values)]


def _match_query(query, attrs):
    """Match an ldap query to an attribute dictionary.

    The characters &, |, and ! are supported in the query. No syntax checking
    is performed, so malformed queries will not work correctly.
    """
    # cut off the parentheses
    inner = query[1:-1]
    if inner.startswith(('&', '|')):
        # cut off the & or |
        groups = _paren_groups(inner[1:])
        return all(_match_query(group, attrs) for group in groups)
    if inner.startswith('!'):
        # cut off the ! and the nested parentheses
        return not _match_query(query[2:-1], attrs)

    (k, _sep, v) = inner.partition('=')
    return _match(k, v, attrs)


def _paren_groups(source):
    """Split a string into parenthesized groups."""
    count = 0
    start = 0
    result = []
    for pos in xrange(len(source)):
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
    if key not in attrs:
        return False
    # This is a wild card search. Implemented as all or nothing for now.
    if value == '*':
        return True
    if key == 'serviceId':
        # for serviceId, the backend is returning a list of numbers
        # make sure we convert them to strings first before comparing
        # them
        str_sids = [str(x) for x in attrs[key]]
        return str(value) in str_sids
    if key != 'objectclass':
        return _process_attr(key, value)[0] in attrs[key]
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


class FakeLdap(object):
    """Fake LDAP connection."""

    __prefix = 'ldap:'

    def __init__(self, url, *args, **kwargs):
        LOG.debug(_('FakeLdap initialize url=%s'), url)
        if url.startswith('fake://memory'):
            if url not in FakeShelves:
                FakeShelves[url] = FakeShelve()
            self.db = FakeShelves[url]
        else:
            self.db = shelve.open(url[7:])

    def simple_bind_s(self, dn, password):
        """This method is ignored, but provided for compatibility."""
        if server_fail:
            raise ldap.SERVER_DOWN
        LOG.debug(_('FakeLdap bind dn=%s'), dn)
        if dn == 'cn=Admin' and password == 'password':
            return

        try:
            attrs = self.db['%s%s' % (self.__prefix, dn)]
        except KeyError:
            LOG.debug(_('FakeLdap bind fail: dn=%s not found'), dn)
            raise ldap.NO_SUCH_OBJECT

        db_password = None
        try:
            db_password = attrs['userPassword'][0]
        except (KeyError, IndexError):
            LOG.debug(_('FakeLdap bind fail: password for dn=%s not found'),
                      dn)
            raise ldap.INAPPROPRIATE_AUTH

        if not utils.ldap_check_password(password, db_password):
            LOG.debug(_('FakeLdap bind fail: password for dn=%s does'
                      ' not match'), dn)
            raise ldap.INVALID_CREDENTIALS

    def unbind_s(self):
        """This method is ignored, but provided for compatibility."""
        if server_fail:
            raise ldap.SERVER_DOWN

    def add_s(self, dn, attrs):
        """Add an object with the specified attributes at dn."""
        if server_fail:
            raise ldap.SERVER_DOWN

        # The LDAP API raises a TypeError if attr name is None.
        for k, dummy_v in attrs:
            if k is None:
                raise TypeError('must be string, not None. attrs=%s' % attrs)

        key = '%s%s' % (self.__prefix, dn)
        LOG.debug(_('FakeLdap add item: dn=%(dn)s, attrs=%(attrs)s'), {
            'dn': dn, 'attrs': attrs})
        if key in self.db:
            LOG.debug(_('FakeLdap add item failed: dn=%s is'
                      ' already in store.'), dn)
            raise ldap.ALREADY_EXISTS(dn)

        self.db[key] = dict([(k, _process_attr(k, v))
                             for k, v in attrs])
        self.db.sync()

    def delete_s(self, dn):
        """Remove the ldap object at specified dn."""
        if server_fail:
            raise ldap.SERVER_DOWN

        key = '%s%s' % (self.__prefix, dn)
        LOG.debug(_('FakeLdap delete item: dn=%s'), dn)
        try:
            del self.db[key]
        except KeyError:
            LOG.debug(_('FakeLdap delete item failed: dn=%s not found.'), dn)
            raise ldap.NO_SUCH_OBJECT
        self.db.sync()

    def delete_ext_s(self, dn, serverctrls):
        """Remove the ldap object at specified dn."""
        if server_fail:
            raise ldap.SERVER_DOWN

        key = '%s%s' % (self.__prefix, dn)
        LOG.debug(_('FakeLdap delete item: dn=%s'), dn)
        try:
            del self.db[key]
        except KeyError:
            LOG.debug(_('FakeLdap delete item failed: dn=%s not found.'), dn)
            raise ldap.NO_SUCH_OBJECT
        self.db.sync()

    def modify_s(self, dn, attrs):
        """Modify the object at dn using the attribute list.

        :param dn: an LDAP DN
        :param attrs: a list of tuples in the following form:
                      ([MOD_ADD | MOD_DELETE | MOD_REPACE], attribute, value)
        """
        if server_fail:
            raise ldap.SERVER_DOWN

        key = '%s%s' % (self.__prefix, dn)
        LOG.debug(_('FakeLdap modify item: dn=%(dn)s attrs=%(attrs)s'), {
            'dn': dn, 'attrs': attrs})
        try:
            entry = self.db[key]
        except KeyError:
            LOG.debug(_('FakeLdap modify item failed: dn=%s not found.'), dn)
            raise ldap.NO_SUCH_OBJECT

        for cmd, k, v in attrs:
            values = entry.setdefault(k, [])
            if cmd == ldap.MOD_ADD:
                v = _process_attr(k, v)
                for x in v:
                    if x in values:
                        raise ldap.TYPE_OR_VALUE_EXISTS
                values += v
            elif cmd == ldap.MOD_REPLACE:
                values[:] = _process_attr(k, v)
            elif cmd == ldap.MOD_DELETE:
                if v is None:
                    if len(values) == 0:
                        LOG.debug(_('FakeLdap modify item failed: '
                                  'item has no attribute "%s" to delete'), k)
                        raise ldap.NO_SUCH_ATTRIBUTE
                    values[:] = []
                else:
                    for val in _process_attr(k, v):
                        try:
                            values.remove(val)
                        except ValueError:
                            LOG.debug(_('FakeLdap modify item failed: '
                                      'item has no attribute "%(k)s" with '
                                      'value "%(v)s" to delete'), {
                                          'k': k, 'v': val})
                            raise ldap.NO_SUCH_ATTRIBUTE
            else:
                LOG.debug(_('FakeLdap modify item failed: unknown'
                          ' command %s'), cmd)
                raise NotImplementedError(_('modify_s action %s not'
                                            ' implemented') % cmd)
        self.db[key] = entry
        self.db.sync()

    def search_s(self, dn, scope, query=None, fields=None):
        """Search for all matching objects under dn using the query.

        Args:
        dn -- dn to search under
        scope -- only SCOPE_BASE and SCOPE_SUBTREE are supported
        query -- query to filter objects by
        fields -- fields to return. Returns all fields if not specified

        """
        if server_fail:
            raise ldap.SERVER_DOWN

        LOG.debug(
            _('FakeLdap search at dn=%(dn)s scope=%(scope)s query=%(query)s'),
            {'dn': dn, 'scope': SCOPE_NAMES.get(scope, scope), 'query': query})
        if scope == ldap.SCOPE_BASE:
            try:
                item_dict = self.db['%s%s' % (self.__prefix, dn)]
            except KeyError:
                LOG.debug(_('FakeLdap search fail: dn not found for'
                            ' SCOPE_BASE'))
                raise ldap.NO_SUCH_OBJECT
            results = [(dn, item_dict)]
        elif scope == ldap.SCOPE_SUBTREE:
            results = [(k[len(self.__prefix):], v)
                       for k, v in self.db.iteritems()
                       if re.match('%s.*,%s' % (self.__prefix, dn), k)]
        elif scope == ldap.SCOPE_ONELEVEL:
            results = [(k[len(self.__prefix):], v)
                       for k, v in self.db.iteritems()
                       if re.match('%s\w+=[^,]+,%s' % (self.__prefix, dn), k)]
        else:
            LOG.debug('FakeLdap search fail: unknown scope %s', scope)
            raise NotImplementedError(_('Search scope %s not implemented.')
                                      % scope)

        objects = []
        for dn, attrs in results:
            # filter the objects by query
            id_attr, id_val = dn.partition(',')[0].split('=', 1)
            match_attrs = attrs.copy()
            match_attrs[id_attr] = [id_val]
            if not query or _match_query(query, match_attrs):
                # filter the attributes by fields
                attrs = dict([(k, v) for k, v in attrs.iteritems()
                              if not fields or k in fields])
                objects.append((dn, attrs))

        LOG.debug('FakeLdap search result: %s', objects)
        return objects
