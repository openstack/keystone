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
from unittest import mock
import uuid

import fixtures
import ldap.dn
from oslo_config import fixture as config_fixture

from keystone.common import driver_hints
from keystone.common import provider_api
import keystone.conf
from keystone import exception as ks_exception
from keystone.identity.backends.ldap import common as common_ldap
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import fakeldap
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.ksfixtures import ldapdb


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class DnCompareTest(unit.BaseTestCase):
    """Test for the DN comparison functions in keystone.common.ldap.core."""

    def test_prep(self):
        # prep_case_insensitive returns the string with spaces at the front and
        # end if it's already lowercase and no insignificant characters.
        value = 'lowercase value'
        self.assertEqual(value, common_ldap.prep_case_insensitive(value))

    def test_prep_lowercase(self):
        # prep_case_insensitive returns the string with spaces at the front and
        # end and lowercases the value.
        value = 'UPPERCASE VALUE'
        exp_value = value.lower()
        self.assertEqual(exp_value, common_ldap.prep_case_insensitive(value))

    def test_prep_insignificant(self):
        # prep_case_insensitive remove insignificant spaces.
        value = 'before   after'
        exp_value = 'before after'
        self.assertEqual(exp_value, common_ldap.prep_case_insensitive(value))

    def test_prep_insignificant_pre_post(self):
        # prep_case_insensitive remove insignificant spaces.
        value = '   value   '
        exp_value = 'value'
        self.assertEqual(exp_value, common_ldap.prep_case_insensitive(value))

    def test_ava_equal_same(self):
        # is_ava_value_equal returns True if the two values are the same.
        value = 'val1'
        self.assertTrue(common_ldap.is_ava_value_equal('cn', value, value))

    def test_ava_equal_complex(self):
        # is_ava_value_equal returns True if the two values are the same using
        # a value that's got different capitalization and insignificant chars.
        val1 = 'before   after'
        val2 = '  BEFORE  afTer '
        self.assertTrue(common_ldap.is_ava_value_equal('cn', val1, val2))

    def test_ava_different(self):
        # is_ava_value_equal returns False if the values aren't the same.
        self.assertFalse(common_ldap.is_ava_value_equal('cn', 'val1', 'val2'))

    def test_rdn_same(self):
        # is_rdn_equal returns True if the two values are the same.
        rdn = ldap.dn.str2dn('cn=val1')[0]
        self.assertTrue(common_ldap.is_rdn_equal(rdn, rdn))

    def test_rdn_diff_length(self):
        # is_rdn_equal returns False if the RDNs have a different number of
        # AVAs.
        rdn1 = ldap.dn.str2dn('cn=cn1')[0]
        rdn2 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        self.assertFalse(common_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_multi_ava_same_order(self):
        # is_rdn_equal returns True if the RDNs have the same number of AVAs
        # and the values are the same.
        rdn1 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        rdn2 = ldap.dn.str2dn('cn=CN1+ou=OU1')[0]
        self.assertTrue(common_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_multi_ava_diff_order(self):
        # is_rdn_equal returns True if the RDNs have the same number of AVAs
        # and the values are the same, even if in a different order
        rdn1 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        rdn2 = ldap.dn.str2dn('ou=OU1+cn=CN1')[0]
        self.assertTrue(common_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_multi_ava_diff_type(self):
        # is_rdn_equal returns False if the RDNs have the same number of AVAs
        # and the attribute types are different.
        rdn1 = ldap.dn.str2dn('cn=cn1+ou=ou1')[0]
        rdn2 = ldap.dn.str2dn('cn=cn1+sn=sn1')[0]
        self.assertFalse(common_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_attr_type_case_diff(self):
        # is_rdn_equal returns True for same RDNs even when attr type case is
        # different.
        rdn1 = ldap.dn.str2dn('cn=cn1')[0]
        rdn2 = ldap.dn.str2dn('CN=cn1')[0]
        self.assertTrue(common_ldap.is_rdn_equal(rdn1, rdn2))

    def test_rdn_attr_type_alias(self):
        # is_rdn_equal returns False for same RDNs even when attr type alias is
        # used. Note that this is a limitation since an LDAP server should
        # consider them equal.
        rdn1 = ldap.dn.str2dn('cn=cn1')[0]
        rdn2 = ldap.dn.str2dn('2.5.4.3=cn1')[0]
        self.assertFalse(common_ldap.is_rdn_equal(rdn1, rdn2))

    def test_dn_same(self):
        # is_dn_equal returns True if the DNs are the same.
        dn = 'cn=Babs Jansen,ou=OpenStack'
        self.assertTrue(common_ldap.is_dn_equal(dn, dn))

    def test_dn_equal_unicode(self):
        # is_dn_equal can accept unicode
        dn = u'cn=fäké,ou=OpenStack'
        self.assertTrue(common_ldap.is_dn_equal(dn, dn))

    def test_dn_diff_length(self):
        # is_dn_equal returns False if the DNs don't have the same number of
        # RDNs
        dn1 = 'cn=Babs Jansen,ou=OpenStack'
        dn2 = 'cn=Babs Jansen,ou=OpenStack,dc=example.com'
        self.assertFalse(common_ldap.is_dn_equal(dn1, dn2))

    def test_dn_equal_rdns(self):
        # is_dn_equal returns True if the DNs have the same number of RDNs
        # and each RDN is the same.
        dn1 = 'cn=Babs Jansen,ou=OpenStack+cn=OpenSource'
        dn2 = 'CN=Babs Jansen,cn=OpenSource+ou=OpenStack'
        self.assertTrue(common_ldap.is_dn_equal(dn1, dn2))

    def test_dn_parsed_dns(self):
        # is_dn_equal can also accept parsed DNs.
        dn_str1 = ldap.dn.str2dn('cn=Babs Jansen,ou=OpenStack+cn=OpenSource')
        dn_str2 = ldap.dn.str2dn('CN=Babs Jansen,cn=OpenSource+ou=OpenStack')
        self.assertTrue(common_ldap.is_dn_equal(dn_str1, dn_str2))

    def test_startswith_under_child(self):
        # dn_startswith returns True if descendant_dn is a child of dn.
        child = 'cn=Babs Jansen,ou=OpenStack'
        parent = 'ou=OpenStack'
        self.assertTrue(common_ldap.dn_startswith(child, parent))

    def test_startswith_parent(self):
        # dn_startswith returns False if descendant_dn is a parent of dn.
        child = 'cn=Babs Jansen,ou=OpenStack'
        parent = 'ou=OpenStack'
        self.assertFalse(common_ldap.dn_startswith(parent, child))

    def test_startswith_same(self):
        # dn_startswith returns False if DNs are the same.
        dn = 'cn=Babs Jansen,ou=OpenStack'
        self.assertFalse(common_ldap.dn_startswith(dn, dn))

    def test_startswith_not_parent(self):
        # dn_startswith returns False if descendant_dn is not under the dn
        child = 'cn=Babs Jansen,ou=OpenStack'
        parent = 'dc=example.com'
        self.assertFalse(common_ldap.dn_startswith(child, parent))

    def test_startswith_descendant(self):
        # dn_startswith returns True if descendant_dn is a descendant of dn.
        descendant = 'cn=Babs Jansen,ou=Keystone,ou=OpenStack,dc=example.com'
        dn = 'ou=OpenStack,dc=example.com'
        self.assertTrue(common_ldap.dn_startswith(descendant, dn))

        descendant = 'uid=12345,ou=Users,dc=example,dc=com'
        dn = 'ou=Users,dc=example,dc=com'
        self.assertTrue(common_ldap.dn_startswith(descendant, dn))

    def test_startswith_parsed_dns(self):
        # dn_startswith also accepts parsed DNs.
        descendant = ldap.dn.str2dn('cn=Babs Jansen,ou=OpenStack')
        dn = ldap.dn.str2dn('ou=OpenStack')
        self.assertTrue(common_ldap.dn_startswith(descendant, dn))

    def test_startswith_unicode(self):
        # dn_startswith accepts unicode.
        child = u'cn=fäké,ou=OpenStäck'
        parent = u'ou=OpenStäck'
        self.assertTrue(common_ldap.dn_startswith(child, parent))


class LDAPDeleteTreeTest(unit.TestCase):

    def setUp(self):
        super(LDAPDeleteTreeTest, self).setUp()

        self.useFixture(
            ldapdb.LDAPDatabase(dbclass=fakeldap.FakeLdapNoSubtreeDelete))
        self.useFixture(database.Database())

        self.load_backends()
        self.load_fixtures(default_fixtures)

    def config_overrides(self):
        super(LDAPDeleteTreeTest, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(LDAPDeleteTreeTest, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files


class MultiURLTests(unit.TestCase):
    """Test for setting multiple LDAP URLs."""

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    def test_multiple_urls_with_comma_no_conn_pool(self, mock_ldap_bind):
        urls = 'ldap://localhost,ldap://backup.localhost'
        self.config_fixture.config(group='ldap', url=urls, use_pool=False)
        base_ldap = common_ldap.BaseLdap(CONF)
        ldap_connection = base_ldap.get_connection()
        self.assertEqual(urls, ldap_connection.conn.conn._uri)

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    def test_multiple_urls_with_comma_with_conn_pool(self, mock_ldap_bind):
        urls = 'ldap://localhost,ldap://backup.localhost'
        self.config_fixture.config(group='ldap', url=urls, use_pool=True)
        base_ldap = common_ldap.BaseLdap(CONF)
        ldap_connection = base_ldap.get_connection()
        self.assertEqual(urls, ldap_connection.conn.conn_pool.uri)


class LDAPConnectionTimeoutTest(unit.TestCase):
    """Test for Network Connection timeout on LDAP URL connection."""

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    def test_connectivity_timeout_no_conn_pool(self, mock_ldap_bind):
        url = 'ldap://localhost'
        conn_timeout = 1  # 1 second
        self.config_fixture.config(group='ldap',
                                   url=url,
                                   connection_timeout=conn_timeout,
                                   use_pool=False)
        base_ldap = common_ldap.BaseLdap(CONF)
        ldap_connection = base_ldap.get_connection()
        self.assertIsInstance(ldap_connection.conn,
                              common_ldap.PythonLDAPHandler)

        # Ensure that the Network Timeout option is set.
        # Also ensure that the URL is set.
        #
        # We will not verify if an LDAP bind returns the timeout
        # exception as that would fall under the realm of
        # integration testing. If the LDAP option is set properly,
        # and we get back a valid connection URI then that should
        # suffice for this unit test.
        self.assertEqual(conn_timeout,
                         ldap.get_option(ldap.OPT_NETWORK_TIMEOUT))
        self.assertEqual(url, ldap_connection.conn.conn._uri)

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    def test_connectivity_timeout_with_conn_pool(self, mock_ldap_bind):
        url = 'ldap://localhost'
        conn_timeout = 1  # 1 second
        self.config_fixture.config(group='ldap',
                                   url=url,
                                   pool_connection_timeout=conn_timeout,
                                   use_pool=True,
                                   pool_retry_max=1)
        base_ldap = common_ldap.BaseLdap(CONF)
        ldap_connection = base_ldap.get_connection()
        self.assertIsInstance(ldap_connection.conn,
                              common_ldap.PooledLDAPHandler)

        # Ensure that the Network Timeout option is set.
        # Also ensure that the URL is set.
        #
        # We will not verify if an LDAP bind returns the timeout
        # exception as that would fall under the realm of
        # integration testing. If the LDAP option is set properly,
        # and we get back a valid connection URI then that should
        # suffice for this unit test.
        self.assertEqual(conn_timeout,
                         ldap.get_option(ldap.OPT_NETWORK_TIMEOUT))
        self.assertEqual(url, ldap_connection.conn.conn_pool.uri)


class SslTlsTest(unit.BaseTestCase):
    """Test for the SSL/TLS functionality in keystone.common.ldap.core."""

    def setUp(self):
        super(SslTlsTest, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    @mock.patch.object(ldap.ldapobject.LDAPObject, 'start_tls_s')
    def _init_ldap_connection(self, config, mock_ldap_one, mock_ldap_two):
        # Attempt to connect to initialize python-ldap.
        base_ldap = common_ldap.BaseLdap(config)
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
    """Test the paged results functionality in keystone.common.ldap.core."""

    def setUp(self):
        super(LDAPPagedResultsTest, self).setUp()

        self.useFixture(ldapdb.LDAPDatabase())
        self.useFixture(database.Database())

        self.load_backends()
        self.load_fixtures(default_fixtures)

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

        conn = PROVIDERS.identity_api.user.get_connection()
        conn._paged_search_s('dc=example,dc=test',
                             ldap.SCOPE_SUBTREE,
                             'objectclass=*',
                             ['mail', 'userPassword'])
        # verify search_ext() args - attrlist is tricky due to ordering
        args, _ = mock_search_ext.call_args
        self.assertEqual(
            ('dc=example,dc=test', 2, 'objectclass=*'), args[0:3])
        attrlist = sorted([attr for attr in args[3] if attr])
        self.assertEqual(['mail', 'userPassword'], attrlist)


class CommonLdapTestCase(unit.BaseTestCase):
    """These test cases call functions in keystone.common.ldap."""

    def test_binary_attribute_values(self):
        result = [(
            'cn=junk,dc=example,dc=com',
            {
                'cn': ['junk'],
                'sn': [uuid.uuid4().hex],
                'mail': [uuid.uuid4().hex],
                'binary_attr': [b'\x00\xFF\x00\xFF']
            }
        ), ]
        py_result = common_ldap.convert_ldap_result(result)
        # The attribute containing the binary value should
        # not be present in the converted result.
        self.assertNotIn('binary_attr', py_result[0][1])

    def test_utf8_conversion(self):
        value_unicode = u'fäké1'
        value_utf8 = value_unicode.encode('utf-8')

        result_utf8 = common_ldap.utf8_encode(value_unicode)
        self.assertEqual(value_utf8, result_utf8)

        result_utf8 = common_ldap.utf8_encode(value_utf8)
        self.assertEqual(value_utf8, result_utf8)

        result_unicode = common_ldap.utf8_decode(value_utf8)
        self.assertEqual(value_unicode, result_unicode)

        result_unicode = common_ldap.utf8_decode(value_unicode)
        self.assertEqual(value_unicode, result_unicode)

        self.assertRaises(TypeError,
                          common_ldap.utf8_encode,
                          100)

        result_unicode = common_ldap.utf8_decode(100)
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
        py_result = common_ldap.convert_ldap_result(result)
        # The user id should be 0123456, and the enabled
        # flag should be True
        self.assertIs(True, py_result[0][1]['enabled'][0])
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
        py_result = common_ldap.convert_ldap_result(result)
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
        py_result = common_ldap.convert_ldap_result(result)
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
            py_result = common_ldap.convert_ldap_result(result)
            # The user name should still be a string value.
            self.assertEqual(user_name, py_result[0][1]['user_name'][0])

    def test_user_id_attribute_is_uuid_in_byte_form(self):
        results = [(
            'cn=alice,dc=example,dc=com',
            {
                'cn': [b'cn=alice'],
                'objectGUID': [b'\xdd\xd8Rt\xee]bA\x8e(\xe39\x0b\xe1\xf8\xe8'],
                'email': [uuid.uuid4().hex],
                'sn': [uuid.uuid4().hex]
            }
        )]
        py_result = common_ldap.convert_ldap_result(results)
        exp_object_guid = '7452d8dd-5dee-4162-8e28-e3390be1f8e8'
        self.assertEqual(exp_object_guid, py_result[0][1]['objectGUID'][0])


class LDAPFilterQueryCompositionTest(unit.BaseTestCase):
    """These test cases test LDAP filter generation."""

    def setUp(self):
        super(LDAPFilterQueryCompositionTest, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))

        self.base_ldap = common_ldap.BaseLdap(self.config_fixture.conf)

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


class LDAPSizeLimitTest(unit.TestCase):
    """Test the size limit exceeded handling in keystone.common.ldap.core."""

    def setUp(self):
        super(LDAPSizeLimitTest, self).setUp()

        self.useFixture(ldapdb.LDAPDatabase())
        self.useFixture(database.Database())

        self.load_backends()
        self.load_fixtures(default_fixtures)

    def config_overrides(self):
        super(LDAPSizeLimitTest, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(LDAPSizeLimitTest, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    @mock.patch.object(fakeldap.FakeLdap, 'search_s')
    def test_search_s_sizelimit_exceeded(self, mock_search_s):
        mock_search_s.side_effect = ldap.SIZELIMIT_EXCEEDED
        conn = PROVIDERS.identity_api.user.get_connection()
        self.assertRaises(ks_exception.LDAPSizeLimitExceeded,
                          conn.search_s,
                          'dc=example,dc=test',
                          ldap.SCOPE_SUBTREE)
