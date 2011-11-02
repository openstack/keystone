import ast
import ldap
from itertools import izip, count


def _get_redirect(cls, method):
    def inner(self, *args):
        return getattr(cls(), method)(*args)
    return inner


def add_redirects(loc, cls, methods):
    for method in methods:
        loc[method] = _get_redirect(cls, method)


class BaseLdapAPI(object):
    DEFAULT_TREE_DN = None
    DEFAULT_STRUCTURAL_CLASSES = None
    DEFAULT_ID_ATTR = 'cn'
    DUMB_MEMBER_DN = 'cn=dumb,dc=nonexistent'
    options_name = None
    object_class = 'top'
    model = None
    attribute_mapping = {}
    attribute_ignore = []

    def __init__(self, api, options):
        self.api = api
        if self.options_name is not None:
            self.tree_dn = options.get('%s_tree_dn' % (self.options_name,),
                                        self.DEFAULT_TREE_DN)
            try:
                lst = options['%s_structural_classes' % (self.options_name,)]
            except KeyError:
                self.structural_classes = self.DEFAULT_STRUCTURAL_CLASSES
            else:
                self.structural_classes = ast.literal_eval(lst)
            self.id_attr = options.get('%s_id_attr' % (self.options_name,),
                                        self.DEFAULT_ID_ATTR)
        self.use_dumb_member = options.get('use_dumb_member', True)

    def _id_to_dn(self, id):
        return '%s=%s,%s' % (self.id_attr, ldap.dn.escape_dn_chars(str(id)),
                                self.tree_dn)

    def _dn_to_id(self, dn):
        return ldap.dn.str2dn(dn)[0][0][1]

    def _ldap_res_to_model(self, res):
        obj = self.model(id=self._dn_to_id(res[0]))
        obj['name'] = obj['id']
        for k in obj:
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

    def create(self, values):
        conn = self.api.get_connection()
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
        return self.model(values)

    def _ldap_get(self, id, filter=None):
        conn = self.api.get_connection()
        query = '(objectClass=%s)' % (self.object_class,)
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
        conn = self.api.get_connection()
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
        return map(self._ldap_res_to_model, self._ldap_get_all(filter))

    def get_page(self, marker, limit):
        return self._get_page(marker, limit, self.get_all())

    def get_page_markers(self, marker, limit):
        return self._get_page_markers(marker, limit, self.get_all())

    def _get_page(self, marker, limit, lst, key=lambda e: e.id):
        lst.sort(key=key)
        if not marker:
            return lst[:limit]
        else:
            return filter(lambda e: key(e) > marker, lst)[:limit]

    def _get_page_markers(self, marker, limit, lst, key=lambda e: e.id):
        if len(lst) < limit:
            return (None, None)
        lst.sort(key=key)
        if marker is None:
            if len(lst) <= limit + 1:
                nxt = None
            else:
                nxt = key(lst[limit])
            return (None, nxt)
        for i, item in izip(count(), lst):
            k = key(item)
            if k >= marker:
                exact = k == marker
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
                         self.attribute_mapping.get(k, k), None))
            else:
                if old_obj[k] != v:
                    if old_obj[k] is None:
                        op = ldap.MOD_ADD
                    else:
                        op = ldap.MOD_REPLACE
                    modlist.append((op, self.attribute_mapping.get(k, k), [v]))
        conn = self.api.get_connection()
        conn.modify_s(self._id_to_dn(id), modlist)

    def delete(self, id):
        conn = self.api.get_connection()
        conn.delete_s(self._id_to_dn(id))
