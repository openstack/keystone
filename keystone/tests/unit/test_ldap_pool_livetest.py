# Copyright 2012 OpenStack Foundation
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

import uuid

import ldappool
from oslo_config import cfg

from keystone.common.ldap import core as ldap_core
from keystone.identity.backends import ldap
from keystone.tests import unit
from keystone.tests.unit import fakeldap
from keystone.tests.unit import test_backend_ldap_pool
from keystone.tests.unit import test_ldap_livetest


CONF = cfg.CONF


class LiveLDAPPoolIdentity(test_backend_ldap_pool.LdapPoolCommonTestMixin,
                           test_ldap_livetest.LiveLDAPIdentity):
    """Executes existing LDAP live test with pooled LDAP handler.

    Also executes common pool specific tests via Mixin class.

    """

    def setUp(self):
        super(LiveLDAPPoolIdentity, self).setUp()
        self.addCleanup(self.cleanup_pools)
        # storing to local variable to avoid long references
        self.conn_pools = ldap_core.PooledLDAPHandler.connection_pools

    def config_files(self):
        config_files = super(LiveLDAPPoolIdentity, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_pool_liveldap.conf'))
        return config_files

    def test_assert_connector_used_not_fake_ldap_pool(self):
        handler = ldap_core._get_connection(CONF.ldap.url, use_pool=True)
        self.assertNotEqual(type(handler.Connector),
                            type(fakeldap.FakeLdapPool))
        self.assertEqual(type(ldappool.StateConnector),
                         type(handler.Connector))

    def test_async_search_and_result3(self):
        self.config_fixture.config(group='ldap', page_size=1)
        self.test_user_enable_attribute_mask()

    def test_pool_size_expands_correctly(self):

        who = CONF.ldap.user
        cred = CONF.ldap.password
        # get related connection manager instance
        ldappool_cm = self.conn_pools[CONF.ldap.url]

        def _get_conn():
            return ldappool_cm.connection(who, cred)

        with _get_conn() as c1:  # 1
            self.assertEqual(1, len(ldappool_cm))
            self.assertTrue(c1.connected, True)
            self.assertTrue(c1.active, True)
            with _get_conn() as c2:  # conn2
                self.assertEqual(2, len(ldappool_cm))
                self.assertTrue(c2.connected)
                self.assertTrue(c2.active)

            self.assertEqual(2, len(ldappool_cm))
            # c2 went out of context, its connected but not active
            self.assertTrue(c2.connected)
            self.assertFalse(c2.active)
            with _get_conn() as c3:  # conn3
                self.assertEqual(2, len(ldappool_cm))
                self.assertTrue(c3.connected)
                self.assertTrue(c3.active)
                self.assertTrue(c3 is c2)  # same connection is reused
                self.assertTrue(c2.active)
                with _get_conn() as c4:  # conn4
                    self.assertEqual(3, len(ldappool_cm))
                    self.assertTrue(c4.connected)
                    self.assertTrue(c4.active)

    def test_password_change_with_auth_pool_disabled(self):
        self.config_fixture.config(group='ldap', use_auth_pool=False)
        old_password = self.user_sna['password']

        self.test_password_change_with_pool()

        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=self.user_sna['id'],
                          password=old_password)

    def _create_user_and_authenticate(self, password):
        user_dict = {
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'password': password}
        user = self.identity_api.create_user(user_dict)

        self.identity_api.authenticate(
            context={},
            user_id=user['id'],
            password=password)

        return self.identity_api.get_user(user['id'])

    def _get_auth_conn_pool_cm(self):
        pool_url = ldap_core.PooledLDAPHandler.auth_pool_prefix + CONF.ldap.url
        return self.conn_pools[pool_url]

    def _do_password_change_for_one_user(self, password, new_password):
        self.config_fixture.config(group='ldap', use_auth_pool=True)
        self.cleanup_pools()
        self.load_backends()

        user1 = self._create_user_and_authenticate(password)
        auth_cm = self._get_auth_conn_pool_cm()
        self.assertEqual(1, len(auth_cm))
        user2 = self._create_user_and_authenticate(password)
        self.assertEqual(1, len(auth_cm))
        user3 = self._create_user_and_authenticate(password)
        self.assertEqual(1, len(auth_cm))
        user4 = self._create_user_and_authenticate(password)
        self.assertEqual(1, len(auth_cm))
        user5 = self._create_user_and_authenticate(password)
        self.assertEqual(1, len(auth_cm))

        # connection pool size remains 1 even for different user ldap bind
        # as there is only one active connection at a time

        user_api = ldap.UserApi(CONF)
        u1_dn = user_api._id_to_dn_string(user1['id'])
        u2_dn = user_api._id_to_dn_string(user2['id'])
        u3_dn = user_api._id_to_dn_string(user3['id'])
        u4_dn = user_api._id_to_dn_string(user4['id'])
        u5_dn = user_api._id_to_dn_string(user5['id'])

        # now create multiple active connections for end user auth case which
        # will force to keep them in pool. After that, modify one of user
        # password. Need to make sure that user connection is in middle
        # of pool list.
        auth_cm = self._get_auth_conn_pool_cm()
        with auth_cm.connection(u1_dn, password) as _:
            with auth_cm.connection(u2_dn, password) as _:
                with auth_cm.connection(u3_dn, password) as _:
                    with auth_cm.connection(u4_dn, password) as _:
                        with auth_cm.connection(u5_dn, password) as _:
                            self.assertEqual(5, len(auth_cm))
                            _.unbind_s()

        user3['password'] = new_password
        self.identity_api.update_user(user3['id'], user3)

        return user3

    def test_password_change_with_auth_pool_enabled_long_lifetime(self):
        self.config_fixture.config(group='ldap',
                                   auth_pool_connection_lifetime=600)
        old_password = 'my_password'
        new_password = 'new_password'
        user = self._do_password_change_for_one_user(old_password,
                                                     new_password)
        user.pop('password')

        # with long connection lifetime auth_pool can bind to old password
        # successfully which is not desired if password change is frequent
        # use case in a deployment.
        # This can happen in multiple concurrent connections case only.
        user_ref = self.identity_api.authenticate(
            context={}, user_id=user['id'], password=old_password)

        self.assertDictEqual(user_ref, user)

    def test_password_change_with_auth_pool_enabled_no_lifetime(self):
        self.config_fixture.config(group='ldap',
                                   auth_pool_connection_lifetime=0)

        old_password = 'my_password'
        new_password = 'new_password'
        user = self._do_password_change_for_one_user(old_password,
                                                     new_password)
        # now as connection lifetime is zero, so authentication
        # with old password will always fail.
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={}, user_id=user['id'],
                          password=old_password)
