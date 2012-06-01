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

import ldap

from keystone import exception
from keystone.common import logging
from keystone.common.ldap import fakeldap


LOG = logging.getLogger(__name__)


LDAP_VALUES = {'TRUE': True, 'FALSE': False}


def py2ldap(val):
    if isinstance(val, str):
        return val
    elif isinstance(val, bool):
        return 'TRUE' if val else 'FALSE'
    else:
        return str(val)


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


class BaseLdap(object):
    DEFAULT_SUFFIX = "dc=example,dc=com"
    DEFAULT_OU = None
    DEFAULT_STRUCTURAL_CLASSES = None
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_OBJECTCLASS = None
    DUMB_MEMBER_DN = 'cn=dumb,dc=nonexistent'
    options_name = None
    model = None
    attribute_mapping = {}
    attribute_ignore = []
    model = None
    tree_dn = None

    def __init__(self,  conf):
        self.LDAP_URL = conf.ldap.url
        self.LDAP_USER = conf.ldap.user
        self.LDAP_PASSWORD = conf.ldap.password

        if self.options_name is not None:
            self.suffix = conf.ldap.suffix
            if self.suffix is None:
                self.suffix = self.DEFAULT_SUFFIX
            dn = '%s_tree_dn' % self.options_name
            self.tree_dn = (getattr(conf.ldap, dn)
                            or '%s,%s' % (self.suffix, self.DEFAULT_OU))

            idatt = '%s_id_attribute' % self.options_name
            self.id_attr = getattr(conf.ldap, idatt) or self.DEFAULT_ID_ATTR

            objclass = '%s_objectclass' % self.options_name
            self.object_class = (getattr(conf.ldap, objclass)
                                 or self.DEFAULT_OBJECTCLASS)

            self.structural_classes = self.DEFAULT_STRUCTURAL_CLASSES
        self.use_dumb_member = getattr(conf.ldap, 'use_dumb_member') or True

    def get_connection(self, user=None, password=None):
        if self.LDAP_URL.startswith('fake://'):
            conn = fakeldap.FakeLdap(self.LDAP_URL)
        else:
            conn = LdapWrapper(self.LDAP_URL)

        if user is None:
            user = self.LDAP_USER

        if password is None:
            password = self.LDAP_PASSWORD

        conn.simple_bind_s(user, password)
        return conn

    def _id_to_dn(self, id):
        return '%s=%s,%s' % (self.id_attr,
                             ldap.dn.escape_dn_chars(str(id)),
                             self.tree_dn)

    @staticmethod
    def _dn_to_id(dn):
        return ldap.dn.str2dn(dn)[0][0][1]

    def _ldap_res_to_model(self, res):
        obj = self.model(id=self._dn_to_id(res[0]))
        for k in obj.known_keys:
            if k in self.attribute_ignore:
                continue

            try:
                v = res[1][self.attribute_mapping.get(k, k)]
            except KeyError:
                pass
            else:
                try:
                    obj[k] = v[0]
                except IndexError:
                    obj[k] = None

        return obj

    def affirm_unique(self, values):
        if values['name'] is not None:
            entity = self.get_by_name(values['name'])
            if entity is not None:
                raise exception.Conflict(type=self.options_name,
                                         details='Duplicate name, %s.' %
                                                 values['name'])

        if values['id'] is not None:
            entity = self.get(values['id'])
            if entity is not None:
                raise exception.Conflict(type=self.options_name,
                                         details='Duplicate ID, %s.' %
                                                 values['id'])

    def create(self, values):
        conn = self.get_connection()
        object_classes = self.structural_classes + [self.object_class]
        attrs = [('objectClass', object_classes)]
        for k, v in values.iteritems():
            if k == 'id' or k in self.attribute_ignore:
                continue
            if v is not None:
                attr_type = self.attribute_mapping.get(k, k)
                attrs.append((attr_type, [v]))

        if 'groupOfNames' in object_classes and self.use_dumb_member:
            attrs.append(('member', [self.DUMB_MEMBER_DN]))

        conn.add_s(self._id_to_dn(values['id']), attrs)
        return values

    def _ldap_get(self, id, filter=None):
        conn = self.get_connection()
        query = '(objectClass=%s)' % self.object_class
        if filter is not None:
            query = '(&%s%s)' % (filter, query)

        try:
            res = conn.search_s(self._id_to_dn(id), ldap.SCOPE_BASE, query)
        except ldap.NO_SUCH_OBJECT:
            return None

        try:
            return res[0]
        except IndexError:
            return None

    def _ldap_get_all(self, filter=None):
        conn = self.get_connection()
        query = '(objectClass=%s)' % (self.object_class,)
        if filter is not None:
            query = '(&%s%s)' % (filter, query)
        try:
            return conn.search_s(self.tree_dn, ldap.SCOPE_ONELEVEL, query)
        except ldap.NO_SUCH_OBJECT:
            return []

    def get(self, id, filter=None):
        res = self._ldap_get(id, filter)
        if res is None:
            return None
        else:
            return self._ldap_res_to_model(res)

    def get_all(self, filter=None):
        return [self._ldap_res_to_model(x)
                for x in self._ldap_get_all(filter)]

    def get_page(self, marker, limit):
        return self._get_page(marker, limit, self.get_all())

    def get_page_markers(self, marker, limit):
        return self._get_page_markers(marker, limit, self.get_all())

    @staticmethod
    def _get_page(marker, limit, lst, key=lambda x: x.id):
        lst.sort(key=key)
        if not marker:
            return lst[:limit]
        else:
            return [x for x in lst if key(x) > marker][:limit]

    @staticmethod
    def _get_page_markers(marker, limit, lst, key=lambda x: x.id):
        if len(lst) < limit:
            return (None, None)

        lst.sort(key=key)
        if marker is None:
            if len(lst) <= limit + 1:
                nxt = None
            else:
                nxt = key(lst[limit])
            return (None, nxt)

        i = 0
        for i, item in enumerate(lst):
            k = key(item)
            if k >= marker:
                break

        if i <= limit:
            prv = None
        else:
            prv = key(lst[i - limit])

        if i + limit >= len(lst) - 1:
            nxt = None
        else:
            nxt = key(lst[i + limit])

        return (prv, nxt)

    def update(self, id, values, old_obj=None):
        if old_obj is None:
            old_obj = self.get(id)

        modlist = []
        for k, v in values.iteritems():
            if k == 'id' or k in self.attribute_ignore:
                continue
            if v is None:
                if old_obj[k] is not None:
                    modlist.append((ldap.MOD_DELETE,
                                    self.attribute_mapping.get(k, k),
                                    None))
            elif old_obj[k] != v:
                if old_obj[k] is None:
                    op = ldap.MOD_ADD
                else:
                    op = ldap.MOD_REPLACE
                modlist.append((op, self.attribute_mapping.get(k, k), [v]))

        conn = self.get_connection()
        conn.modify_s(self._id_to_dn(id), modlist)

    def delete(self, id):
        conn = self.get_connection()
        conn.delete_s(self._id_to_dn(id))


class LdapWrapper(object):
    def __init__(self, url):
        LOG.debug("LDAP init: url=%s", url)
        self.conn = ldap.initialize(url)

    def simple_bind_s(self, user, password):
        LOG.debug("LDAP bind: dn=%s", user)
        return self.conn.simple_bind_s(user, password)

    def add_s(self, dn, attrs):
        ldap_attrs = [(kind, [py2ldap(x) for x in safe_iter(values)])
                      for kind, values in attrs]
        if LOG.isEnabledFor(logging.DEBUG):
            sane_attrs = [(kind, values
                           if kind != 'userPassword'
                           else ['****'])
                          for kind, values in ldap_attrs]
            LOG.debug('LDAP add: dn=%s, attrs=%s', dn, sane_attrs)
        return self.conn.add_s(dn, ldap_attrs)

    def search_s(self, dn, scope, query):
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug('LDAP search: dn=%s, scope=%s, query=%s',
                      dn,
                      scope,
                      query)
        res = self.conn.search_s(dn, scope, query)

        o = []
        for dn, attrs in res:
            o.append((dn, dict((kind, [ldap2py(x) for x in values])
                               for kind, values in attrs.iteritems())))

        return o

    def modify_s(self, dn, modlist):
        ldap_modlist = [
            (op, kind, (None if values is None
                        else [py2ldap(x) for x in safe_iter(values)]))
            for op, kind, values in modlist]

        if LOG.isEnabledFor(logging.DEBUG):
            sane_modlist = [(op, kind, (values if kind != 'userPassword'
                                        else ['****']))
                            for op, kind, values in ldap_modlist]
            LOG.debug("LDAP modify: dn=%s, modlist=%s", dn, sane_modlist)

        return self.conn.modify_s(dn, ldap_modlist)

    def delete_s(self, dn):
        LOG.debug("LDAP delete: dn=%s", dn)
        return self.conn.delete_s(dn)
