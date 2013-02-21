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

from keystone.common.ldap import fakeldap
from keystone.common import logging
from keystone import exception


LOG = logging.getLogger(__name__)


LDAP_VALUES = {'TRUE': True, 'FALSE': False}
CONTROL_TREEDELETE = '1.2.840.113556.1.4.805'
LDAP_SCOPES = {'one': ldap.SCOPE_ONELEVEL,
               'sub': ldap.SCOPE_SUBTREE}


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


def ldap_scope(scope):
    try:
        return LDAP_SCOPES[scope]
    except KeyError:
        raise ValueError(_('Invalid LDAP scope: %s. Choose one of: ' % scope) +
                         ', '.join(LDAP_SCOPES.keys()))


class BaseLdap(object):
    DEFAULT_SUFFIX = "dc=example,dc=com"
    DEFAULT_OU = None
    DEFAULT_STRUCTURAL_CLASSES = None
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_OBJECTCLASS = None
    DEFAULT_FILTER = None
    DUMB_MEMBER_DN = 'cn=dumb,dc=nonexistent'
    options_name = None
    model = None
    attribute_mapping = {}
    attribute_ignore = []
    tree_dn = None

    def __init__(self, conf):
        self.LDAP_URL = conf.ldap.url
        self.LDAP_USER = conf.ldap.user
        self.LDAP_PASSWORD = conf.ldap.password
        self.LDAP_SCOPE = ldap_scope(conf.ldap.query_scope)

        if self.options_name is not None:
            self.suffix = conf.ldap.suffix
            if self.suffix is None:
                self.suffix = self.DEFAULT_SUFFIX
            dn = '%s_tree_dn' % self.options_name
            self.tree_dn = (getattr(conf.ldap, dn)
                            or '%s,%s' % (self.DEFAULT_OU, self.suffix))

            idatt = '%s_id_attribute' % self.options_name
            self.id_attr = getattr(conf.ldap, idatt) or self.DEFAULT_ID_ATTR

            objclass = '%s_objectclass' % self.options_name
            self.object_class = (getattr(conf.ldap, objclass)
                                 or self.DEFAULT_OBJECTCLASS)

            filter = '%s_filter' % self.options_name
            self.filter = getattr(conf.ldap, filter) or self.DEFAULT_FILTER

            allow_create = '%s_allow_create' % self.options_name
            self.allow_create = getattr(conf.ldap, allow_create)

            allow_update = '%s_allow_update' % self.options_name
            self.allow_update = getattr(conf.ldap, allow_update)

            allow_delete = '%s_allow_delete' % self.options_name
            self.allow_delete = getattr(conf.ldap, allow_delete)

            self.structural_classes = self.DEFAULT_STRUCTURAL_CLASSES
        self.use_dumb_member = getattr(conf.ldap, 'use_dumb_member')
        self.dumb_member = (getattr(conf.ldap, 'dumb_member') or
                            self.DUMB_MEMBER_DN)

        self.subtree_delete_enabled = getattr(conf.ldap,
                                              'allow_subtree_delete')

    def get_connection(self, user=None, password=None):
        if self.LDAP_URL.startswith('fake://'):
            conn = fakeldap.FakeLdap(self.LDAP_URL)
        else:
            conn = LdapWrapper(self.LDAP_URL)

        if user is None:
            user = self.LDAP_USER

        if password is None:
            password = self.LDAP_PASSWORD

        # not all LDAP servers require authentication, so we don't bind
        # if we don't have any user/pass
        if user and password:
            conn.simple_bind_s(user, password)

        return conn

    def _id_to_dn_string(self, id):
        return '%s=%s,%s' % (self.id_attr,
                             ldap.dn.escape_dn_chars(str(id)),
                             self.tree_dn)

    def _id_to_dn(self, id):
        if self.LDAP_SCOPE == ldap.SCOPE_ONELEVEL:
            return self._id_to_dn_string(id)
        conn = self.get_connection()
        search_result = conn.search_s(
            self.tree_dn, self.LDAP_SCOPE,
            '(&(%(id_attr)s=%(id)s)(objectclass=%(objclass)s))' %
            {'id_attr': self.id_attr,
             'id': ldap.filter.escape_filter_chars(str(id)),
             'objclass': self.object_class})
        if search_result:
            dn, attrs = search_result[0]
            return dn
        else:
            return self._id_to_dn_string(id)

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
        if values.get('name') is not None:
            try:
                self.get_by_name(values['name'])
            except exception.NotFound:
                pass
            else:
                raise exception.Conflict(type=self.options_name,
                                         details=_('Duplicate name, %s.') %
                                         values['name'])

        if values.get('id') is not None:
            try:
                self.get(values['id'])
            except exception.NotFound:
                pass
            else:
                raise exception.Conflict(type=self.options_name,
                                         details=_('Duplicate ID, %s.') %
                                         values['id'])

    def create(self, values):
        if not self.allow_create:
            action = _('LDAP %s create') % self.options_name
            raise exception.ForbiddenAction(action=action)

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
            attrs.append(('member', [self.dumb_member]))

        conn.add_s(self._id_to_dn(values['id']), attrs)
        return values

    def _ldap_get(self, id, filter=None):
        conn = self.get_connection()
        query = ('(&(%(id_attr)s=%(id)s)'
                 '%(filter)s'
                 '(objectClass=%(object_class)s))'
                 % {'id_attr': self.id_attr,
                    'id': ldap.filter.escape_filter_chars(str(id)),
                    'filter': (filter or self.filter or ''),
                    'object_class': self.object_class})
        try:
            res = conn.search_s(self.tree_dn, self.LDAP_SCOPE, query,
                                self.attribute_mapping.values())
        except ldap.NO_SUCH_OBJECT:
            return None
        try:
            return res[0]
        except IndexError:
            return None

    def _ldap_get_all(self, filter=None):
        conn = self.get_connection()
        query = '(&%s(objectClass=%s))' % (filter or self.filter or '',
                                           self.object_class)
        try:
            return conn.search_s(self.tree_dn,
                                 self.LDAP_SCOPE,
                                 query,
                                 self.attribute_mapping.values())
        except ldap.NO_SUCH_OBJECT:
            return []

    def get(self, id, filter=None):
        res = self._ldap_get(id, filter)
        if res is None:
            raise exception.NotFound(target=id)
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
        if not self.allow_update:
            action = _('LDAP %s update') % self.options_name
            raise exception.ForbiddenAction(action=action)

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

        if modlist:
            conn = self.get_connection()
            conn.modify_s(self._id_to_dn(id), modlist)

    def delete(self, id):
        if not self.allow_delete:
            action = _('LDAP %s delete') % self.options_name
            raise exception.ForbiddenAction(action=action)

        conn = self.get_connection()
        conn.delete_s(self._id_to_dn(id))

    def deleteTree(self, id):
        conn = self.get_connection()
        tree_delete_control = ldap.controls.LDAPControl(CONTROL_TREEDELETE,
                                                        0,
                                                        None)
        conn.delete_ext_s(self._id_to_dn(id),
                          serverctrls=[tree_delete_control])


class LdapWrapper(object):
    def __init__(self, url):
        LOG.debug(_("LDAP init: url=%s"), url)
        self.conn = ldap.initialize(url)

    def simple_bind_s(self, user, password):
        LOG.debug(_("LDAP bind: dn=%s"), user)
        return self.conn.simple_bind_s(user, password)

    def add_s(self, dn, attrs):
        ldap_attrs = [(kind, [py2ldap(x) for x in safe_iter(values)])
                      for kind, values in attrs]
        if LOG.isEnabledFor(logging.DEBUG):
            sane_attrs = [(kind, values
                           if kind != 'userPassword'
                           else ['****'])
                          for kind, values in ldap_attrs]
            LOG.debug(_('LDAP add: dn=%s, attrs=%s'), dn, sane_attrs)
        return self.conn.add_s(dn, ldap_attrs)

    def search_s(self, dn, scope, query, attrlist=None):
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(_('LDAP search: dn=%s, scope=%s, query=%s, attrs=%s'),
                      dn,
                      scope,
                      query,
                      attrlist)
        res = self.conn.search_s(dn, scope, query, attrlist)

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
            LOG.debug(_("LDAP modify: dn=%s, modlist=%s"), dn, sane_modlist)

        return self.conn.modify_s(dn, ldap_modlist)

    def delete_s(self, dn):
        LOG.debug(_("LDAP delete: dn=%s"), dn)
        return self.conn.delete_s(dn)

    def delete_ext_s(self, dn, serverctrls):
        LOG.debug(_("LDAP delete_ext: dn=%s, serverctrls=%s"), dn, serverctrls)
        return self.conn.delete_ext_s(dn, serverctrls)


class EnabledEmuMixIn(BaseLdap):
    """Emulates boolean 'enabled' attribute if turned on.

    Creates groupOfNames holding all enabled objects of this class, all missing
    objects are considered disabled.

    Options:

    * $name_enabled_emulation - boolean, on/off
    * $name_enabled_emulation_dn - DN of that groupOfNames, default is
      cn=enabled_$name,$tree_dn

    Where $name is self.options_name ('user' or 'tenant'), $tree_dn is
    self.tree_dn.
    """

    def __init__(self, conf):
        super(EnabledEmuMixIn, self).__init__(conf)
        enabled_emulation = '%s_enabled_emulation' % self.options_name
        self.enabled_emulation = getattr(conf.ldap, enabled_emulation)

        enabled_emulation_dn = '%s_enabled_emulation_dn' % self.options_name
        self.enabled_emulation_dn = getattr(conf.ldap, enabled_emulation_dn)
        if not self.enabled_emulation_dn:
            self.enabled_emulation_dn = ('cn=enabled_%ss,%s' %
                                         (self.options_name, self.tree_dn))

    def _get_enabled(self, object_id):
        conn = self.get_connection()
        dn = self._id_to_dn(object_id)
        query = '(member=%s)' % dn
        try:
            enabled_value = conn.search_s(self.enabled_emulation_dn,
                                          ldap.SCOPE_BASE,
                                          query)
        except ldap.NO_SUCH_OBJECT:
            return False
        else:
            return bool(enabled_value)

    def _add_enabled(self, object_id):
        conn = self.get_connection()
        modlist = [(ldap.MOD_ADD,
                    'member',
                    [self._id_to_dn(object_id)])]
        try:
            conn.modify_s(self.enabled_emulation_dn, modlist)
        except ldap.NO_SUCH_OBJECT:
            attr_list = [('objectClass', ['groupOfNames']),
                         ('member',
                         [self._id_to_dn(object_id)])]
            if self.use_dumb_member:
                attr_list[1][1].append(self.dumb_member)
            conn.add_s(self.enabled_emulation_dn, attr_list)

    def _remove_enabled(self, object_id):
        conn = self.get_connection()
        modlist = [(ldap.MOD_DELETE,
                    'member',
                    [self._id_to_dn(object_id)])]
        try:
            conn.modify_s(self.enabled_emulation_dn, modlist)
        except (ldap.NO_SUCH_OBJECT, ldap.NO_SUCH_ATTRIBUTE):
            pass

    def create(self, values):
        if self.enabled_emulation:
            enabled_value = values.pop('enabled', True)
            ref = super(EnabledEmuMixIn, self).create(values)
            if 'enabled' not in self.attribute_ignore:
                if enabled_value:
                    self._add_enabled(ref['id'])
                ref['enabled'] = enabled_value
            return ref
        else:
            return super(EnabledEmuMixIn, self).create(values)

    def get(self, object_id, filter=None):
        ref = super(EnabledEmuMixIn, self).get(object_id, filter)
        if 'enabled' not in self.attribute_ignore and self.enabled_emulation:
            ref['enabled'] = self._get_enabled(object_id)
        return ref

    def get_all(self, filter=None):
        if 'enabled' not in self.attribute_ignore and self.enabled_emulation:
            # had to copy BaseLdap.get_all here to filter by DN
            tenant_list = [self._ldap_res_to_model(x)
                           for x in self._ldap_get_all(filter)
                           if x[0] != self.enabled_emulation_dn]
            for tenant_ref in tenant_list:
                tenant_ref['enabled'] = self._get_enabled(tenant_ref['id'])
            return tenant_list
        else:
            return super(EnabledEmuMixIn, self).get_all(filter)

    def update(self, object_id, values, old_obj=None):
        if 'enabled' not in self.attribute_ignore and self.enabled_emulation:
            data = values.copy()
            enabled_value = data.pop('enabled', None)
            super(EnabledEmuMixIn, self).update(object_id, data, old_obj)
            if enabled_value is not None:
                if enabled_value:
                    self._add_enabled(object_id)
                else:
                    self._remove_enabled(object_id)
        else:
            super(EnabledEmuMixIn, self).update(object_id, values, old_obj)

    def delete(self, object_id):
        if self.enabled_emulation:
            self._remove_enabled(object_id)
        super(EnabledEmuMixIn, self).delete(object_id)
