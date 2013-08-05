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
import ldap.modlist
import subprocess
import uuid

from keystone.common import ldap as ldap_common
from keystone import config
from keystone import exception
from keystone.identity.backends import ldap as identity_ldap
from keystone.tests import core as test

import test_backend_ldap


CONF = config.CONF


def create_object(dn, attrs):
    conn = ldap.initialize(CONF.ldap.url)
    conn.simple_bind_s(CONF.ldap.user, CONF.ldap.password)
    ldif = ldap.modlist.addModlist(attrs)
    conn.add_s(dn, ldif)
    conn.unbind_s()


class LiveLDAPIdentity(test_backend_ldap.LDAPIdentity):

    def clear_database(self):
        devnull = open('/dev/null', 'w')
        subprocess.call(['ldapdelete',
                         '-x',
                         '-D', CONF.ldap.user,
                         '-H', CONF.ldap.url,
                         '-w', CONF.ldap.password,
                         '-r', CONF.ldap.suffix],
                        stderr=devnull)

        if CONF.ldap.suffix.startswith('ou='):
            tree_dn_attrs = {'objectclass': 'organizationalUnit',
                             'ou': 'openstack'}
        else:
            tree_dn_attrs = {'objectclass': ['dcObject', 'organizationalUnit'],
                             'dc': 'openstack',
                             'ou': 'openstack'}
        create_object(CONF.ldap.suffix, tree_dn_attrs)
        create_object(CONF.ldap.user_tree_dn,
                      {'objectclass': 'organizationalUnit',
                      'ou': 'Users'})
        create_object(CONF.ldap.role_tree_dn,
                      {'objectclass': 'organizationalUnit',
                      'ou': 'Roles'})
        create_object(CONF.ldap.tenant_tree_dn,
                      {'objectclass': 'organizationalUnit',
                      'ou': 'Projects'})
        create_object(CONF.ldap.group_tree_dn,
                      {'objectclass': 'organizationalUnit',
                      'ou': 'UserGroups'})

    def _set_config(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_liveldap.conf')])

    def test_build_tree(self):
        """Regression test for building the tree names
        """
        #logic is different from the fake backend.
        user_api = identity_ldap.UserApi(CONF)
        self.assertTrue(user_api)
        self.assertEquals(user_api.tree_dn, CONF.ldap.user_tree_dn)

    def tearDown(self):
        test.TestCase.tearDown(self)

    def test_ldap_dereferencing(self):
        alt_users_ldif = {'objectclass': ['top', 'organizationalUnit'],
                          'ou': 'alt_users'}
        alt_fake_user_ldif = {'objectclass': ['person', 'inetOrgPerson'],
                              'cn': 'alt_fake1',
                              'sn': 'alt_fake1'}
        aliased_users_ldif = {'objectclass': ['alias', 'extensibleObject'],
                              'aliasedobjectname': "ou=alt_users,%s" %
                              CONF.ldap.suffix}
        create_object("ou=alt_users,%s" % CONF.ldap.suffix, alt_users_ldif)
        create_object("%s=alt_fake1,ou=alt_users,%s" %
                      (CONF.ldap.user_id_attribute, CONF.ldap.suffix),
                      alt_fake_user_ldif)
        create_object("ou=alt_users,%s" % CONF.ldap.user_tree_dn,
                      aliased_users_ldif)

        CONF.ldap.query_scope = 'sub'
        CONF.ldap.alias_dereferencing = 'never'
        self.identity_api = identity_ldap.Identity()
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          'alt_fake1')

        CONF.ldap.alias_dereferencing = 'searching'
        self.identity_api = identity_ldap.Identity()
        user_ref = self.identity_api.get_user('alt_fake1')
        self.assertEqual(user_ref['id'], 'alt_fake1')

        CONF.ldap.alias_dereferencing = 'always'
        self.identity_api = identity_ldap.Identity()
        user_ref = self.identity_api.get_user('alt_fake1')
        self.assertEqual(user_ref['id'], 'alt_fake1')

    def test_base_ldap_connection_deref_option(self):
        deref = ldap_common.parse_deref('default')
        ldap_wrapper = ldap_common.LdapWrapper(CONF.ldap.url,
                                               CONF.ldap.page_size,
                                               alias_dereferencing=deref)
        self.assertEqual(ldap.get_option(ldap.OPT_DEREF),
                         ldap_wrapper.conn.get_option(ldap.OPT_DEREF))

        deref = ldap_common.parse_deref('always')
        ldap_wrapper = ldap_common.LdapWrapper(CONF.ldap.url,
                                               CONF.ldap.page_size,
                                               alias_dereferencing=deref)
        self.assertEqual(ldap.DEREF_ALWAYS,
                         ldap_wrapper.conn.get_option(ldap.OPT_DEREF))

        deref = ldap_common.parse_deref('finding')
        ldap_wrapper = ldap_common.LdapWrapper(CONF.ldap.url,
                                               CONF.ldap.page_size,
                                               alias_dereferencing=deref)
        self.assertEqual(ldap.DEREF_FINDING,
                         ldap_wrapper.conn.get_option(ldap.OPT_DEREF))

        deref = ldap_common.parse_deref('never')
        ldap_wrapper = ldap_common.LdapWrapper(CONF.ldap.url,
                                               CONF.ldap.page_size,
                                               alias_dereferencing=deref)
        self.assertEqual(ldap.DEREF_NEVER,
                         ldap_wrapper.conn.get_option(ldap.OPT_DEREF))

        deref = ldap_common.parse_deref('searching')
        ldap_wrapper = ldap_common.LdapWrapper(CONF.ldap.url,
                                               CONF.ldap.page_size,
                                               alias_dereferencing=deref)
        self.assertEqual(ldap.DEREF_SEARCHING,
                         ldap_wrapper.conn.get_option(ldap.OPT_DEREF))

    #FakeLDAP does not correctly process filters, so this test can only be run
    #against a live LDAP server
    def test_list_groups_for_user_filtered(self):
        domain = self._get_domain_fixture()
        test_groups = []
        test_users = []
        GROUP_COUNT = 3
        USER_COUNT = 2

        for x in range(0, USER_COUNT):
            new_user = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                        'password': uuid.uuid4().hex, 'enabled': True,
                        'domain_id': domain['id']}
            test_users.append(new_user)
            self.identity_api.create_user(new_user['id'], new_user)
        positive_user = test_users[0]
        negative_user = test_users[1]

        for x in range(0, USER_COUNT):
            group_refs = self.identity_api.list_groups_for_user(
                test_users[x]['id'])
            self.assertEquals(len(group_refs), 0)

        for x in range(0, GROUP_COUNT):
            new_group = {'id': uuid.uuid4().hex,
                         'domain_id': domain['id'],
                         'name': uuid.uuid4().hex}
            self.identity_api.create_group(new_group['id'], new_group)
            test_groups.append(new_group)

            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEquals(len(group_refs), x)

            self.identity_api.add_user_to_group(
                positive_user['id'],
                new_group['id'])
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEquals(len(group_refs), x + 1)

            group_refs = self.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEquals(len(group_refs), 0)

        CONF.ldap.group_filter = "(dn=xx)"
        self.reload_backends(CONF.identity.default_domain_id)
        group_refs = self.identity_api.list_groups_for_user(
            positive_user['id'])
        self.assertEquals(len(group_refs), 0)
        group_refs = self.identity_api.list_groups_for_user(
            negative_user['id'])
        self.assertEquals(len(group_refs), 0)

        CONF.ldap.group_filter = "(objectclass=*)"
        self.reload_backends(CONF.identity.default_domain_id)
        group_refs = self.identity_api.list_groups_for_user(
            positive_user['id'])
        self.assertEquals(len(group_refs), GROUP_COUNT)
        group_refs = self.identity_api.list_groups_for_user(
            negative_user['id'])
        self.assertEquals(len(group_refs), 0)

    def test_user_enable_attribute_mask(self):
        CONF.ldap.user_enabled_emulation = False
        CONF.ldap.user_enabled_attribute = 'employeeType'
        super(LiveLDAPIdentity, self).test_user_enable_attribute_mask()

    def test_create_unicode_user_name(self):
        self.skipTest('Addressed by bug #1172106')
