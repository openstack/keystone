# -*- coding: utf-8 -*-
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

import os
import tempfile
import uuid

import fixtures
import ldap.dn
import mock
from oslo_config import cfg
from testtools import matchers

from keystone.common import driver_hints
from keystone.common import ldap as ks_ldap
from keystone.common.ldap import core as common_ldap_core
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import fakeldap


CONF = cfg.CONF


class DnCompareTest(unit.BaseTestCase):
    """Tests for the DN comparison functions in keystone.common.ldap.core."""

    def test_prep(self):
        # prep_case_insensitive returns the string with spaces at the front and
        # end if it's already lowercase and no insignificant characters.
        value = 'lowercase value'
        self.assertEqual(value, ks_ldap.prep_case_insensitive(value))

    def test_prep_lowercase(self):
        # prep_case_insensitive returns the string with spaces at the front and
        # end and lowercases the value.
        value = 'UPPERCASE VALUE'
        exp_value = value.lower()
        self.assertEqual(exp_value, ks_ldap.prep_case_insensitive(value))

    def test_prep_insignificant(self):
        # prep_case_insensitive remove insignificant spaces.
        value = 'before   after'
        exp_value = 'before after'
        self.assertEqual(exp_value, ks_ldap.prep_case_insensitive(value))

    def test_prep_insignificant_pre_post(self):
        # prep_case_insensitive remove insignificant spaces.
        value = '   value   '
        exp_value = 'value'
        self.assertEqual(exp_value, ks_ldap.prep_case_insensitive(value))

    def test_ava_equal_same(self):
        # is_ava_value_equal returns True if the two values are the same.
        value = 'val1'
        self.assertTrue(ks_ldap.is_ava_value_equal('cn', value, value))

    def test_ava_equal_complex(self):
        # is_ava_value_equal returns True if the two values are the same using
        # a value that's got different capitalization and insignificant chars.
        val1 = 'before   after'
        val2 = '  BEFORE  afTer '
        self.assertTrue(ks_ldap.is_ava_value_equal('cn', val1, val2))

    def test_ava_different(self):
        # is_ava_value_equal returns False if the values aren't the same.
        self.assertFalse(ks_ldap.is_ava_value_equal('cn', 'val1', 'val2'))

    def test_rdn_same(self):
        # is_rdn_equal returns True if the two values are the same.
        rdn = ldap.dn.str2dn('cn=val1')[0]
        self.assertTrue(ks_ldap.is_rdn_equal(rdn, rdn))

    def test_rdn_diff_length(self):
        # is_rdn_equal returns False if the RDNs have a different number of
        # AVAs.
        rdn1 = ldap.dn.str2dn('cn=cn1')[0]
        rdn2 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        self.assertFalse(ks_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_multi_ava_same_order(self):
        # is_rdn_equal returns True if the RDNs have the same number of AVAs
        # and the values are the same.
        rdn1 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        rdn2 = ldap.dn.str2dn('cn=CN1+ou=OU1')[0]
        self.assertTrue(ks_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_multi_ava_diff_order(self):
        # is_rdn_equal returns True if the RDNs have the same number of AVAs
        # and the values are the same, even if in a different order
        rdn1 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        rdn2 = ldap.dn.str2dn('ou=OU1+cn=CN1')[0]
        self.assertTrue(ks_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_multi_ava_diff_type(self):
        # is_rdn_equal returns False if the RDNs have the same number of AVAs
        # and the attribute types are different.
        rdn1 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        rdn2 = ldap.dn.str2dn('cn=cn1+sn=sn1')[0]
        self.assertFalse(ks_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_attr_type_case_diff(self):
        # is_rdn_equal returns True for same RDNs even when attr type case is
        # different.
        rdn1 = ldap.dn.str2dn('cn=cn1')[0]
        rdn2 = ldap.dn.str2dn('CN=cn1')[0]
        self.assertTrue(ks_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_attr_type_alias(self):
        # is_rdn_equal returns False for same RDNs even when attr type alias is
        # used. Note that this is a limitation since an LDAP server should
        # consider them equal.
        rdn1 = ldap.dn.str2dn('cn=cn1')[0]
        rdn2 = ldap.dn.str2dn('2.5.4.3=cn1')[0]
        self.assertFalse(ks_ldap.is_rdn_equal(rdn1, rdn2))

    def test_dn_same(self):
        # is_dn_equal returns True if the DNs are the same.
        dn = 'cn=Babs Jansen,ou=OpenStack'
        self.assertTrue(ks_ldap.is_dn_equal(dn, dn))

    def test_dn_equal_unicode(self):
        # is_dn_equal can accept unicode
        dn = u'cn=fäké,ou=OpenStack'
        self.assertTrue(ks_ldap.is_dn_equal(dn, dn))

    def test_dn_diff_length(self):
        # is_dn_equal returns False if the DNs don't have the same number of
        # RDNs
        dn1 = 'cn=Babs Jansen,ou=OpenStack'
        dn2 = 'cn=Babs Jansen,ou=OpenStack,dc=example.com'
        self.assertFalse(ks_ldap.is_dn_equal(dn1, dn2))

    def test_dn_equal_rdns(self):
        # is_dn_equal returns True if the DNs have the same number of RDNs
        # and each RDN is the same.
        dn1 = 'cn=Babs Jansen,ou=OpenStack+cn=OpenSource'
        dn2 = 'CN=Babs Jansen,cn=OpenSource+ou=OpenStack'
        self.assertTrue(ks_ldap.is_dn_equal(dn1, dn2))

    def test_dn_parsed_dns(self):
        # is_dn_equal can also accept parsed DNs.
        dn_str1 = ldap.dn.str2dn('cn=Babs Jansen,ou=OpenStack+cn=OpenSource')
        dn_str2 = ldap.dn.str2dn('CN=Babs Jansen,cn=OpenSource+ou=OpenStack')
        self.assertTrue(ks_ldap.is_dn_equal(dn_str1, dn_str2))

    def test_startswith_under_child(self):
        # dn_startswith returns True if descendant_dn is a child of dn.
        child = 'cn=Babs Jansen,ou=OpenStack'
        parent = 'ou=OpenStack'
        self.assertTrue(ks_ldap.dn_startswith(child, parent))

    def test_startswith_parent(self):
        # dn_startswith returns False if descendant_dn is a parent of dn.
        child = 'cn=Babs Jansen,ou=OpenStack'
        parent = 'ou=OpenStack'
        self.assertFalse(ks_ldap.dn_startswith(parent, child))

    def test_startswith_same(self):
        # dn_startswith returns False if DNs are the same.
        dn = 'cn=Babs Jansen,ou=OpenStack'
        self.assertFalse(ks_ldap.dn_startswith(dn, dn))

    def test_startswith_not_parent(self):
        # dn_startswith returns False if descendant_dn is not under the dn
        child = 'cn=Babs Jansen,ou=OpenStack'
        parent = 'dc=example.com'
        self.assertFalse(ks_ldap.dn_startswith(child, parent))

    def test_startswith_descendant(self):
        # dn_startswith returns True if descendant_dn is a descendant of dn.
        descendant = 'cn=Babs Jansen,ou=Keystone,ou=OpenStack,dc=example.com'
        dn = 'ou=OpenStack,dc=example.com'
        self.assertTrue(ks_ldap.dn_startswith(descendant, dn))

        descendant = 'uid=12345,ou=Users,dc=example,dc=com'
        dn = 'ou=Users,dc=example,dc=com'
        self.assertTrue(ks_ldap.dn_startswith(descendant, dn))

    def test_startswith_parsed_dns(self):
        # dn_startswith also accepts parsed DNs.
        descendant = ldap.dn.str2dn('cn=Babs Jansen,ou=OpenStack')
        dn = ldap.dn.str2dn('ou=OpenStack')
        self.assertTrue(ks_ldap.dn_startswith(descendant, dn))

    def test_startswith_unicode(self):
        # dn_startswith accepts unicode.
        child = u'cn=cn=fäké,ou=OpenStäck'
        parent = 'ou=OpenStäck'
        self.assertTrue(ks_ldap.dn_startswith(child, parent))


class LDAPDeleteTreeTest(unit.TestCase):

    def setUp(self):
        super(LDAPDeleteTreeTest, self).setUp()

        ks_ldap.register_handler('fake://',
                                 fakeldap.FakeLdapNoSubtreeDelete)
        self.load_backends()
        self.load_fixtures(default_fixtures)

        self.addCleanup(self.clear_database)
        self.addCleanup(common_ldap_core._HANDLERS.clear)

    def clear_database(self):
        for shelf in fakeldap.FakeShelves:
            fakeldap.FakeShelves[shelf].clear()

    def config_overrides(self):
        super(LDAPDeleteTreeTest, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(LDAPDeleteTreeTest, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def test_deleteTree(self):
        """Test manually deleting a tree.

        Few LDAP servers support CONTROL_DELETETREE.  This test
        exercises the alternate code paths in BaseLdap.deleteTree.

        """
        conn = self.identity_api.user.get_connection()
        id_attr = self.identity_api.user.id_attr
        objclass = self.identity_api.user.object_class.lower()
        tree_dn = self.identity_api.user.tree_dn

        def create_entry(name, parent_dn=None):
            if not parent_dn:
                parent_dn = tree_dn
            dn = '%s=%s,%s' % (id_attr, name, parent_dn)
            attrs = [('objectclass', [objclass, 'ldapsubentry']),
                     (id_attr, [name])]
            conn.add_s(dn, attrs)
            return dn

        # create 3 entries like this:
        # cn=base
        # cn=child,cn=base
        # cn=grandchild,cn=child,cn=base
        # then attempt to deleteTree(cn=base)
        base_id = 'base'
        base_dn = create_entry(base_id)
        child_dn = create_entry('child', base_dn)
        grandchild_dn = create_entry('grandchild', child_dn)

        # verify that the three entries were created
        scope = ldap.SCOPE_SUBTREE
        filt = '(|(objectclass=*)(objectclass=ldapsubentry))'
        entries = conn.search_s(base_dn, scope, filt,
                                attrlist=common_ldap_core.DN_ONLY)
        self.assertThat(entries, matchers.HasLength(3))
        sort_ents = sorted([e[0] for e in entries], key=len, reverse=True)
        self.assertEqual([grandchild_dn, child_dn, base_dn], sort_ents)

        # verify that a non-leaf node can't be deleted directly by the
        # LDAP server
        self.assertRaises(ldap.NOT_ALLOWED_ON_NONLEAF,
                          conn.delete_s, base_dn)
        self.assertRaises(ldap.NOT_ALLOWED_ON_NONLEAF,
                          conn.delete_s, child_dn)

        # call our deleteTree implementation
        self.identity_api.user.deleteTree(base_id)
        self.assertRaises(ldap.NO_SUCH_OBJECT,
                          conn.search_s, base_dn, ldap.SCOPE_BASE)
        self.assertRaises(ldap.NO_SUCH_OBJECT,
                          conn.search_s, child_dn, ldap.SCOPE_BASE)
        self.assertRaises(ldap.NO_SUCH_OBJECT,
                          conn.search_s, grandchild_dn, ldap.SCOPE_BASE)


class SslTlsTest(unit.TestCase):
    """Tests for the SSL/TLS functionality in keystone.common.ldap.core."""

    @mock.patch.object(ks_ldap.core.KeystoneLDAPHandler, 'simple_bind_s')
    @mock.patch.object(ldap.ldapobject.LDAPObject, 'start_tls_s')
    def _init_ldap_connection(self, config, mock_ldap_one, mock_ldap_two):
        # Attempt to connect to initialize python-ldap.
        base_ldap = ks_ldap.BaseLdap(config)
        base_ldap.get_connection()

    def test_certfile_trust_tls(self):
        # We need this to actually exist, so we create a tempfile.
        (handle, certfile) = tempfile.mkstemp()
        self.addCleanup(os.unlink, certfile)
        self.addCleanup(os.close, handle)
        self.config_fixture.config(group='ldap',
                                   url='ldap://localhost',
                                   use_tls=True,
                                   tls_cacertfile=certfile)

        self._init_ldap_connection(CONF)

        # Ensure the cert trust option is set.
        self.assertEqual(certfile, ldap.get_option(ldap.OPT_X_TLS_CACERTFILE))

    def test_certdir_trust_tls(self):
        # We need this to actually exist, so we create a tempdir.
        certdir = self.useFixture(fixtures.TempDir()).path
        self.config_fixture.config(group='ldap',
                                   url='ldap://localhost',
                                   use_tls=True,
                                   tls_cacertdir=certdir)

        self._init_ldap_connection(CONF)

        # Ensure the cert trust option is set.
        self.assertEqual(certdir, ldap.get_option(ldap.OPT_X_TLS_CACERTDIR))

    def test_certfile_trust_ldaps(self):
        # We need this to actually exist, so we create a tempfile.
        (handle, certfile) = tempfile.mkstemp()
        self.addCleanup(os.unlink, certfile)
        self.addCleanup(os.close, handle)
        self.config_fixture.config(group='ldap',
                                   url='ldaps://localhost',
                                   use_tls=False,
                                   tls_cacertfile=certfile)

        self._init_ldap_connection(CONF)

        # Ensure the cert trust option is set.
        self.assertEqual(certfile, ldap.get_option(ldap.OPT_X_TLS_CACERTFILE))

    def test_certdir_trust_ldaps(self):
        # We need this to actually exist, so we create a tempdir.
        certdir = self.useFixture(fixtures.TempDir()).path
        self.config_fixture.config(group='ldap',
                                   url='ldaps://localhost',
                                   use_tls=False,
                                   tls_cacertdir=certdir)

        self._init_ldap_connection(CONF)

        # Ensure the cert trust option is set.
        self.assertEqual(certdir, ldap.get_option(ldap.OPT_X_TLS_CACERTDIR))


class LDAPPagedResultsTest(unit.TestCase):
    """Tests the paged results functionality in keystone.common.ldap.core."""

    def setUp(self):
        super(LDAPPagedResultsTest, self).setUp()
        self.clear_database()

        ks_ldap.register_handler('fake://', fakeldap.FakeLdap)
        self.addCleanup(common_ldap_core._HANDLERS.clear)

        self.load_backends()
        self.load_fixtures(default_fixtures)

    def clear_database(self):
        for shelf in fakeldap.FakeShelves:
            fakeldap.FakeShelves[shelf].clear()

    def config_overrides(self):
        super(LDAPPagedResultsTest, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(LDAPPagedResultsTest, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    @mock.patch.object(fakeldap.FakeLdap, 'search_ext')
    @mock.patch.object(fakeldap.FakeLdap, 'result3')
    def test_paged_results_control_api(self, mock_result3, mock_search_ext):
        mock_result3.return_value = ('', [], 1, [])

        self.config_fixture.config(group='ldap',
                                   page_size=1)

        conn = self.identity_api.user.get_connection()
        conn._paged_search_s('dc=example,dc=test',
                             ldap.SCOPE_SUBTREE,
                             'objectclass=*')


class CommonLdapTestCase(unit.BaseTestCase):
    """These test cases call functions in keystone.common.ldap."""

    def test_binary_attribute_values(self):
        result = [(
            'cn=junk,dc=example,dc=com',
            {
                'cn': ['junk'],
                'sn': [uuid.uuid4().hex],
                'mail': [uuid.uuid4().hex],
                'binary_attr': ['\x00\xFF\x00\xFF']
            }
        ), ]
        py_result = ks_ldap.convert_ldap_result(result)
        # The attribute containing the binary value should
        # not be present in the converted result.
        self.assertNotIn('binary_attr', py_result[0][1])

    def test_utf8_conversion(self):
        value_unicode = u'fäké1'
        value_utf8 = value_unicode.encode('utf-8')

        result_utf8 = ks_ldap.utf8_encode(value_unicode)
        self.assertEqual(value_utf8, result_utf8)

        result_utf8 = ks_ldap.utf8_encode(value_utf8)
        self.assertEqual(value_utf8, result_utf8)

        result_unicode = ks_ldap.utf8_decode(value_utf8)
        self.assertEqual(value_unicode, result_unicode)

        result_unicode = ks_ldap.utf8_decode(value_unicode)
        self.assertEqual(value_unicode, result_unicode)

        self.assertRaises(TypeError,
                          ks_ldap.utf8_encode,
                          100)

        result_unicode = ks_ldap.utf8_decode(100)
        self.assertEqual(u'100', result_unicode)

    def test_user_id_begins_with_0(self):
        user_id = '0123456'
        result = [(
            'cn=dummy,dc=example,dc=com',
            {
                'user_id': [user_id],
                'enabled': ['TRUE']
            }
        ), ]
        py_result = ks_ldap.convert_ldap_result(result)
        # The user id should be 0123456, and the enabled
        # flag should be True
        self.assertIs(py_result[0][1]['enabled'][0], True)
        self.assertEqual(user_id, py_result[0][1]['user_id'][0])

    def test_user_id_begins_with_0_and_enabled_bit_mask(self):
        user_id = '0123456'
        bitmask = '225'
        expected_bitmask = 225
        result = [(
            'cn=dummy,dc=example,dc=com',
            {
                'user_id': [user_id],
                'enabled': [bitmask]
            }
        ), ]
        py_result = ks_ldap.convert_ldap_result(result)
        # The user id should be 0123456, and the enabled
        # flag should be 225
        self.assertEqual(expected_bitmask, py_result[0][1]['enabled'][0])
        self.assertEqual(user_id, py_result[0][1]['user_id'][0])

    def test_user_id_and_bitmask_begins_with_0(self):
        user_id = '0123456'
        bitmask = '0225'
        expected_bitmask = 225
        result = [(
            'cn=dummy,dc=example,dc=com',
            {
                'user_id': [user_id],
                'enabled': [bitmask]
            }
        ), ]
        py_result = ks_ldap.convert_ldap_result(result)
        # The user id should be 0123456, and the enabled
        # flag should be 225, the 0 is dropped.
        self.assertEqual(expected_bitmask, py_result[0][1]['enabled'][0])
        self.assertEqual(user_id, py_result[0][1]['user_id'][0])

    def test_user_id_and_user_name_with_boolean_string(self):
        boolean_strings = ['TRUE', 'FALSE', 'true', 'false', 'True', 'False',
                           'TrUe' 'FaLse']
        for user_name in boolean_strings:
            user_id = uuid.uuid4().hex
            result = [(
                'cn=dummy,dc=example,dc=com',
                {
                    'user_id': [user_id],
                    'user_name': [user_name]
                }
            ), ]
            py_result = ks_ldap.convert_ldap_result(result)
            # The user name should still be a string value.
            self.assertEqual(user_name, py_result[0][1]['user_name'][0])


class LDAPFilterQueryCompositionTest(unit.TestCase):
    """These test cases test LDAP filter generation."""

    def setUp(self):
        super(LDAPFilterQueryCompositionTest, self).setUp()

        self.base_ldap = ks_ldap.BaseLdap(self.config_fixture.conf)

        # The tests need an attribute mapping to use.
        self.attribute_name = uuid.uuid4().hex
        self.filter_attribute_name = uuid.uuid4().hex
        self.base_ldap.attribute_mapping = {
            self.attribute_name: self.filter_attribute_name
        }

    def test_return_query_with_no_hints(self):
        hints = driver_hints.Hints()
        # NOTE: doesn't have to be a real query, we just need to make sure the
        # same string is returned if there are no hints.
        query = uuid.uuid4().hex
        self.assertEqual(query,
                         self.base_ldap.filter_query(hints=hints, query=query))

        # make sure the default query is an empty string
        self.assertEqual('', self.base_ldap.filter_query(hints=hints))

    def test_filter_with_empty_query_and_hints_set(self):
        hints = driver_hints.Hints()
        username = uuid.uuid4().hex
        hints.add_filter(name=self.attribute_name,
                         value=username,
                         comparator='equals',
                         case_sensitive=False)
        expected_ldap_filter = '(&(%s=%s))' % (
            self.filter_attribute_name, username)
        self.assertEqual(expected_ldap_filter,
                         self.base_ldap.filter_query(hints=hints))

    def test_filter_with_both_query_and_hints_set(self):
        hints = driver_hints.Hints()
        # NOTE: doesn't have to be a real query, we just need to make sure the
        # filter string is concatenated correctly
        query = uuid.uuid4().hex
        username = uuid.uuid4().hex
        expected_result = '(&%(query)s(%(user_name_attr)s=%(username)s))' % (
            {'query': query,
             'user_name_attr': self.filter_attribute_name,
             'username': username})
        hints.add_filter(self.attribute_name, username)
        self.assertEqual(expected_result,
                         self.base_ldap.filter_query(hints=hints, query=query))

    def test_filter_with_hints_and_query_is_none(self):
        hints = driver_hints.Hints()
        username = uuid.uuid4().hex
        hints.add_filter(name=self.attribute_name,
                         value=username,
                         comparator='equals',
                         case_sensitive=False)
        expected_ldap_filter = '(&(%s=%s))' % (
            self.filter_attribute_name, username)
        self.assertEqual(expected_ldap_filter,
                         self.base_ldap.filter_query(hints=hints, query=None))
