# Copyright 2013 OpenStack Foundation
# Copyright 2013 IBM Corp.
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

import ldap.modlist
from oslo_config import cfg

from keystone import exception
from keystone import identity
from keystone.tests import unit
from keystone.tests.unit import test_ldap_livetest


CONF = cfg.CONF


def create_object(dn, attrs):
    conn = ldap.initialize(CONF.ldap.url)
    conn.simple_bind_s(CONF.ldap.user, CONF.ldap.password)
    ldif = ldap.modlist.addModlist(attrs)
    conn.add_s(dn, ldif)
    conn.unbind_s()


class LiveTLSLDAPIdentity(test_ldap_livetest.LiveLDAPIdentity):

    def _ldap_skip_live(self):
        self.skip_if_env_not_set('ENABLE_TLS_LDAP_LIVE_TEST')

    def config_files(self):
        config_files = super(LiveTLSLDAPIdentity, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_tls_liveldap.conf'))
        return config_files

    def test_tls_certfile_demand_option(self):
        self.config_fixture.config(group='ldap',
                                   use_tls=True,
                                   tls_cacertdir=None,
                                   tls_req_cert='demand')
        self.identity_api = identity.backends.ldap.Identity()

        user = {'name': 'fake1',
                'password': 'fakepass1',
                'tenants': ['bar']}
        user = self.identity_api.create_user('user')
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['id'], user_ref['id'])

        user['password'] = 'fakepass2'
        self.identity_api.update_user(user['id'], user)

        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound, self.identity_api.get_user,
                          user['id'])

    def test_tls_certdir_demand_option(self):
        self.config_fixture.config(group='ldap',
                                   use_tls=True,
                                   tls_cacertdir=None,
                                   tls_req_cert='demand')
        self.identity_api = identity.backends.ldap.Identity()

        user = {'id': 'fake1',
                'name': 'fake1',
                'password': 'fakepass1',
                'tenants': ['bar']}
        self.identity_api.create_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual('fake1', user_ref['id'])

        user['password'] = 'fakepass2'
        self.identity_api.update_user('fake1', user)

        self.identity_api.delete_user('fake1')
        self.assertRaises(exception.UserNotFound, self.identity_api.get_user,
                          'fake1')

    def test_tls_bad_certfile(self):
        self.config_fixture.config(
            group='ldap',
            use_tls=True,
            tls_req_cert='demand',
            tls_cacertfile='/etc/keystone/ssl/certs/mythicalcert.pem',
            tls_cacertdir=None)
        self.identity_api = identity.backends.ldap.Identity()

        user = {'name': 'fake1',
                'password': 'fakepass1',
                'tenants': ['bar']}
        self.assertRaises(IOError, self.identity_api.create_user, user)

    def test_tls_bad_certdir(self):
        self.config_fixture.config(
            group='ldap',
            use_tls=True,
            tls_cacertfile=None,
            tls_req_cert='demand',
            tls_cacertdir='/etc/keystone/ssl/mythicalcertdir')
        self.identity_api = identity.backends.ldap.Identity()

        user = {'name': 'fake1',
                'password': 'fakepass1',
                'tenants': ['bar']}
        self.assertRaises(IOError, self.identity_api.create_user, user)
