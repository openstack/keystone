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
import mock

import os
import shutil
import tempfile

from keystone.common import ldap as ks_ldap
from keystone import config
from keystone import tests

CONF = config.CONF


class DnCompareTest(tests.BaseTestCase):
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

    def test_startswith_parsed_dns(self):
        # dn_startswith also accepts parsed DNs.
        descendant = ldap.dn.str2dn('cn=Babs Jansen,ou=OpenStack')
        dn = ldap.dn.str2dn('ou=OpenStack')
        self.assertTrue(ks_ldap.dn_startswith(descendant, dn))


class SslTlsTest(tests.TestCase):
    """Tests for the SSL/TLS functionality in keystone.common.ldap.core."""

    @mock.patch.object(ks_ldap.core.LdapWrapper, 'simple_bind_s')
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
        certdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, certdir)
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
        certdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, certdir)
        self.config_fixture.config(group='ldap',
                                   url='ldaps://localhost',
                                   use_tls=False,
                                   tls_cacertdir=certdir)

        self._init_ldap_connection(CONF)

        # Ensure the cert trust option is set.
        self.assertEqual(certdir, ldap.get_option(ldap.OPT_X_TLS_CACERTDIR))
