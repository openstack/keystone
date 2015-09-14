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

import datetime
import uuid

from keystoneclient.contrib.ec2 import utils as ec2_utils
from keystoneclient import exceptions as client_exceptions
from keystoneclient.v2_0 import client as ks_client
import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from six.moves import http_client
from six.moves import range
import webob

from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import appserver
from keystone.tests.unit.ksfixtures import database


CONF = cfg.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class ClientDrivenTestCase(unit.TestCase):

    def config_files(self):
        config_files = super(ClientDrivenTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def setUp(self):
        super(ClientDrivenTestCase, self).setUp()

        # FIXME(morganfainberg): Since we are running tests through the
        # controllers and some internal api drivers are SQL-only, the correct
        # approach is to ensure we have the correct backing store. The
        # credential api makes some very SQL specific assumptions that should
        # be addressed allowing for non-SQL based testing to occur.
        self.useFixture(database.Database())
        self.load_backends()

        self.load_fixtures(default_fixtures)

        # TODO(termie): add an admin user to the fixtures and use that user
        # override the fixtures, for now
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_admin['id'])

        conf = self._paste_config('keystone')
        fixture = self.useFixture(appserver.AppServer(conf, appserver.MAIN))
        self.public_server = fixture.server
        fixture = self.useFixture(appserver.AppServer(conf, appserver.ADMIN))
        self.admin_server = fixture.server

        self.default_client = self.get_client()

        self.addCleanup(self.cleanup_instance('public_server', 'admin_server',
                                              'default_client'))

    def _public_url(self):
        public_port = self.public_server.socket_info['socket'][1]
        return "http://localhost:%s/v2.0" % public_port

    def _admin_url(self):
        admin_port = self.admin_server.socket_info['socket'][1]
        return "http://localhost:%s/v2.0" % admin_port

    def _client(self, admin=False, **kwargs):
        url = self._admin_url() if admin else self._public_url()
        kc = ks_client.Client(endpoint=url,
                              auth_url=self._public_url(),
                              **kwargs)
        kc.authenticate()
        # have to manually overwrite the management url after authentication
        kc.management_url = url
        return kc

    def get_client(self, user_ref=None, tenant_ref=None, admin=False):
        if user_ref is None:
            user_ref = self.user_foo
        if tenant_ref is None:
            for user in default_fixtures.USERS:
                # The fixture ID is no longer used as the ID in the database
                # The fixture ID, however, is still used as part of the
                # attribute name when storing the created object on the test
                # case. This means that we need to use the fixture ID below to
                # find the actial object so that we can get the ID as stored
                # in the database to compare against.
                if (getattr(self, 'user_%s' % user['id'])['id'] ==
                        user_ref['id']):
                    tenant_id = user['tenants'][0]
        else:
            tenant_id = tenant_ref['id']

        return self._client(username=user_ref['name'],
                            password=user_ref['password'],
                            tenant_id=tenant_id,
                            admin=admin)

    def test_authenticate_tenant_name_and_tenants(self):
        client = self.get_client()
        tenants = client.tenants.list()
        self.assertEqual(self.tenant_bar['id'], tenants[0].id)

    def test_authenticate_tenant_id_and_tenants(self):
        client = self._client(username=self.user_foo['name'],
                              password=self.user_foo['password'],
                              tenant_id='bar')
        tenants = client.tenants.list()
        self.assertEqual(self.tenant_bar['id'], tenants[0].id)

    def test_authenticate_invalid_tenant_id(self):
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username=self.user_foo['name'],
                          password=self.user_foo['password'],
                          tenant_id='baz')

    def test_authenticate_token_no_tenant(self):
        client = self.get_client()
        token = client.auth_token
        token_client = self._client(token=token)
        tenants = token_client.tenants.list()
        self.assertEqual(self.tenant_bar['id'], tenants[0].id)

    def test_authenticate_token_tenant_id(self):
        client = self.get_client()
        token = client.auth_token
        token_client = self._client(token=token, tenant_id='bar')
        tenants = token_client.tenants.list()
        self.assertEqual(self.tenant_bar['id'], tenants[0].id)

    def test_authenticate_token_invalid_tenant_id(self):
        client = self.get_client()
        token = client.auth_token
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client, token=token,
                          tenant_id=uuid.uuid4().hex)

    def test_authenticate_token_invalid_tenant_name(self):
        client = self.get_client()
        token = client.auth_token
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client, token=token,
                          tenant_name=uuid.uuid4().hex)

    def test_authenticate_token_tenant_name(self):
        client = self.get_client()
        token = client.auth_token
        token_client = self._client(token=token, tenant_name='BAR')
        tenants = token_client.tenants.list()
        self.assertEqual(self.tenant_bar['id'], tenants[0].id)
        self.assertEqual(self.tenant_bar['id'], tenants[0].id)

    def test_authenticate_and_delete_token(self):
        client = self.get_client(admin=True)
        token = client.auth_token
        token_client = self._client(token=token)
        tenants = token_client.tenants.list()
        self.assertEqual(self.tenant_bar['id'], tenants[0].id)

        client.tokens.delete(token_client.auth_token)

        self.assertRaises(client_exceptions.Unauthorized,
                          token_client.tenants.list)

    def test_authenticate_no_password(self):
        user_ref = self.user_foo.copy()
        user_ref['password'] = None
        self.assertRaises(client_exceptions.AuthorizationFailure,
                          self.get_client,
                          user_ref)

    def test_authenticate_no_username(self):
        user_ref = self.user_foo.copy()
        user_ref['name'] = None
        self.assertRaises(client_exceptions.AuthorizationFailure,
                          self.get_client,
                          user_ref)

    def test_authenticate_disabled_tenant(self):
        admin_client = self.get_client(admin=True)

        tenant = {
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'enabled': False,
        }
        tenant_ref = admin_client.tenants.create(
            tenant_name=tenant['name'],
            description=tenant['description'],
            enabled=tenant['enabled'])
        tenant['id'] = tenant_ref.id

        user = {
            'name': uuid.uuid4().hex,
            'password': uuid.uuid4().hex,
            'email': uuid.uuid4().hex,
            'tenant_id': tenant['id'],
        }
        user_ref = admin_client.users.create(
            name=user['name'],
            password=user['password'],
            email=user['email'],
            tenant_id=user['tenant_id'])
        user['id'] = user_ref.id

        # password authentication
        self.assertRaises(
            client_exceptions.Unauthorized,
            self._client,
            username=user['name'],
            password=user['password'],
            tenant_id=tenant['id'])

        # token authentication
        client = self._client(
            username=user['name'],
            password=user['password'])
        self.assertRaises(
            client_exceptions.Unauthorized,
            self._client,
            token=client.auth_token,
            tenant_id=tenant['id'])

    # FIXME(ja): this test should require the "keystone:admin" roled
    #            (probably the role set via --keystone_admin_role flag)
    # FIXME(ja): add a test that admin endpoint is only sent to admin user
    # FIXME(ja): add a test that admin endpoint returns unauthorized if not
    #            admin
    def test_tenant_create_update_and_delete(self):
        tenant_name = 'original_tenant'
        tenant_description = 'My original tenant!'
        tenant_enabled = True
        client = self.get_client(admin=True)

        # create, get, and list a tenant
        tenant = client.tenants.create(tenant_name=tenant_name,
                                       description=tenant_description,
                                       enabled=tenant_enabled)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertEqual(tenant_enabled, tenant.enabled)

        tenant = client.tenants.get(tenant_id=tenant.id)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertEqual(tenant_enabled, tenant.enabled)

        tenant = [t for t in client.tenants.list() if t.id == tenant.id].pop()
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertEqual(tenant_enabled, tenant.enabled)

        # update, get, and list a tenant
        tenant_name = 'updated_tenant'
        tenant_description = 'Updated tenant!'
        tenant_enabled = False
        tenant = client.tenants.update(tenant_id=tenant.id,
                                       tenant_name=tenant_name,
                                       enabled=tenant_enabled,
                                       description=tenant_description)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertEqual(tenant_enabled, tenant.enabled)

        tenant = client.tenants.get(tenant_id=tenant.id)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertEqual(tenant_enabled, tenant.enabled)

        tenant = [t for t in client.tenants.list() if t.id == tenant.id].pop()
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertEqual(tenant_enabled, tenant.enabled)

        # delete, get, and list a tenant
        client.tenants.delete(tenant=tenant.id)
        self.assertRaises(client_exceptions.NotFound, client.tenants.get,
                          tenant.id)
        self.assertFalse([t for t in client.tenants.list()
                         if t.id == tenant.id])

    def test_tenant_create_update_and_delete_unicode(self):
        tenant_name = u'original \u540d\u5b57'
        tenant_description = 'My original tenant!'
        tenant_enabled = True
        client = self.get_client(admin=True)

        # create, get, and list a tenant
        tenant = client.tenants.create(tenant_name,
                                       description=tenant_description,
                                       enabled=tenant_enabled)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertIs(tenant.enabled, tenant_enabled)

        tenant = client.tenants.get(tenant.id)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertIs(tenant.enabled, tenant_enabled)

        # multiple tenants exist due to fixtures, so find the one we're testing
        tenant = [t for t in client.tenants.list() if t.id == tenant.id].pop()
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertIs(tenant.enabled, tenant_enabled)

        # update, get, and list a tenant
        tenant_name = u'updated \u540d\u5b57'
        tenant_description = 'Updated tenant!'
        tenant_enabled = False
        tenant = client.tenants.update(tenant.id,
                                       tenant_name=tenant_name,
                                       enabled=tenant_enabled,
                                       description=tenant_description)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertIs(tenant.enabled, tenant_enabled)

        tenant = client.tenants.get(tenant.id)
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertIs(tenant.enabled, tenant_enabled)

        tenant = [t for t in client.tenants.list() if t.id == tenant.id].pop()
        self.assertEqual(tenant_name, tenant.name)
        self.assertEqual(tenant_description, tenant.description)
        self.assertIs(tenant.enabled, tenant_enabled)

        # delete, get, and list a tenant
        client.tenants.delete(tenant.id)
        self.assertRaises(client_exceptions.NotFound, client.tenants.get,
                          tenant.id)
        self.assertFalse([t for t in client.tenants.list()
                         if t.id == tenant.id])

    def test_tenant_create_no_name(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.tenants.create,
                          tenant_name="")

    def test_tenant_delete_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.tenants.delete,
                          tenant=uuid.uuid4().hex)

    def test_tenant_get_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.tenants.get,
                          tenant_id=uuid.uuid4().hex)

    def test_tenant_update_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.tenants.update,
                          tenant_id=uuid.uuid4().hex)

    def test_tenant_list(self):
        client = self.get_client()
        tenants = client.tenants.list()
        self.assertEqual(1, len(tenants))

        # Admin endpoint should return *all* tenants
        client = self.get_client(admin=True)
        tenants = client.tenants.list()
        self.assertEqual(len(default_fixtures.TENANTS), len(tenants))

    def test_invalid_password(self):
        good_client = self._client(username=self.user_foo['name'],
                                   password=self.user_foo['password'])
        good_client.tenants.list()

        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username=self.user_foo['name'],
                          password=uuid.uuid4().hex)

    def test_invalid_user_and_password(self):
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username=uuid.uuid4().hex,
                          password=uuid.uuid4().hex)

    def test_change_password_invalidates_token(self):
        admin_client = self.get_client(admin=True)

        username = uuid.uuid4().hex
        password = uuid.uuid4().hex
        user = admin_client.users.create(name=username, password=password,
                                         email=uuid.uuid4().hex)

        # auth as user should work before a password change
        client = self._client(username=username, password=password)

        # auth as user with a token should work before a password change
        self._client(token=client.auth_token)

        # administrative password reset
        admin_client.users.update_password(
            user=user.id,
            password=uuid.uuid4().hex)

        # auth as user with original password should not work after change
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username=username,
                          password=password)

        # authenticate with an old token should not work after change
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          token=client.auth_token)

    def test_user_change_own_password_invalidates_token(self):
        # bootstrap a user as admin
        client = self.get_client(admin=True)
        username = uuid.uuid4().hex
        password = uuid.uuid4().hex
        client.users.create(name=username, password=password,
                            email=uuid.uuid4().hex)

        # auth as user should work before a password change
        client = self._client(username=username, password=password)

        # auth as user with a token should work before a password change
        self._client(token=client.auth_token)

        # change the user's own password
        # TODO(dolphm): This should NOT raise an HTTPError at all, but rather
        # this should succeed with a 2xx. This 500 does not prevent the test
        # from demonstrating the desired consequences below, though.
        self.assertRaises(client_exceptions.HTTPError,
                          client.users.update_own_password,
                          password, uuid.uuid4().hex)

        # auth as user with original password should not work after change
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username=username,
                          password=password)

        # auth as user with an old token should not work after change
        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          token=client.auth_token)

    def test_disable_tenant_invalidates_token(self):
        admin_client = self.get_client(admin=True)
        foo_client = self.get_client(self.user_foo)
        tenant_bar = admin_client.tenants.get(self.tenant_bar['id'])

        # Disable the tenant.
        tenant_bar.update(enabled=False)

        # Test that the token has been removed.
        self.assertRaises(client_exceptions.Unauthorized,
                          foo_client.tokens.authenticate,
                          token=foo_client.auth_token)

        # Test that the user access has been disabled.
        self.assertRaises(client_exceptions.Unauthorized,
                          self.get_client,
                          self.user_foo)

    def test_delete_tenant_invalidates_token(self):
        admin_client = self.get_client(admin=True)
        foo_client = self.get_client(self.user_foo)
        tenant_bar = admin_client.tenants.get(self.tenant_bar['id'])

        # Delete the tenant.
        tenant_bar.delete()

        # Test that the token has been removed.
        self.assertRaises(client_exceptions.Unauthorized,
                          foo_client.tokens.authenticate,
                          token=foo_client.auth_token)

        # Test that the user access has been disabled.
        self.assertRaises(client_exceptions.Unauthorized,
                          self.get_client,
                          self.user_foo)

    def test_disable_user_invalidates_token(self):
        admin_client = self.get_client(admin=True)
        foo_client = self.get_client(self.user_foo)

        admin_client.users.update_enabled(user=self.user_foo['id'],
                                          enabled=False)

        self.assertRaises(client_exceptions.Unauthorized,
                          foo_client.tokens.authenticate,
                          token=foo_client.auth_token)

        self.assertRaises(client_exceptions.Unauthorized,
                          self.get_client,
                          self.user_foo)

    def test_delete_user_invalidates_token(self):
        admin_client = self.get_client(admin=True)
        client = self.get_client(admin=False)

        username = uuid.uuid4().hex
        password = uuid.uuid4().hex
        user_id = admin_client.users.create(
            name=username, password=password, email=uuid.uuid4().hex).id

        token_id = client.tokens.authenticate(
            username=username, password=password).id

        # token should be usable before the user is deleted
        client.tokens.authenticate(token=token_id)

        admin_client.users.delete(user=user_id)

        # authenticate with a token should not work after the user is deleted
        self.assertRaises(client_exceptions.Unauthorized,
                          client.tokens.authenticate,
                          token=token_id)

    @mock.patch.object(timeutils, 'utcnow')
    def test_token_expiry_maintained(self, mock_utcnow):
        now = datetime.datetime.utcnow()
        mock_utcnow.return_value = now
        foo_client = self.get_client(self.user_foo)

        orig_token = foo_client.service_catalog.catalog['token']
        mock_utcnow.return_value = now + datetime.timedelta(seconds=1)
        reauthenticated_token = foo_client.tokens.authenticate(
            token=foo_client.auth_token)

        self.assertCloseEnoughForGovernmentWork(
            timeutils.parse_isotime(orig_token['expires']),
            timeutils.parse_isotime(reauthenticated_token.expires))

    def test_user_create_update_delete(self):
        test_username = 'new_user'
        client = self.get_client(admin=True)
        user = client.users.create(name=test_username,
                                   password='password',
                                   email='user1@test.com')
        self.assertEqual(test_username, user.name)

        user = client.users.get(user=user.id)
        self.assertEqual(test_username, user.name)

        user = client.users.update(user=user,
                                   name=test_username,
                                   email='user2@test.com')
        self.assertEqual('user2@test.com', user.email)

        # NOTE(termie): update_enabled doesn't return anything, probably a bug
        client.users.update_enabled(user=user, enabled=False)
        user = client.users.get(user.id)
        self.assertFalse(user.enabled)

        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username=test_username,
                          password='password')
        client.users.update_enabled(user, True)

        user = client.users.update_password(user=user, password='password2')

        self._client(username=test_username,
                     password='password2')

        user = client.users.update_tenant(user=user, tenant='bar')
        # TODO(ja): once keystonelight supports default tenant
        #           when you login without specifying tenant, the
        #           token should be scoped to tenant 'bar'

        client.users.delete(user.id)
        self.assertRaises(client_exceptions.NotFound, client.users.get,
                          user.id)

        # Test creating a user with a tenant (auto-add to tenant)
        user2 = client.users.create(name=test_username,
                                    password='password',
                                    email='user1@test.com',
                                    tenant_id='bar')
        self.assertEqual(test_username, user2.name)

    def test_update_default_tenant_to_existing_value(self):
        client = self.get_client(admin=True)

        user = client.users.create(
            name=uuid.uuid4().hex,
            password=uuid.uuid4().hex,
            email=uuid.uuid4().hex,
            tenant_id=self.tenant_bar['id'])

        # attempting to update the tenant with the existing value should work
        user = client.users.update_tenant(
            user=user, tenant=self.tenant_bar['id'])

    def test_user_create_no_string_password(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.users.create,
                          name='test_user',
                          password=12345,
                          email=uuid.uuid4().hex)

    def test_user_create_no_name(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.users.create,
                          name="",
                          password=uuid.uuid4().hex,
                          email=uuid.uuid4().hex)

    def test_user_create_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.create,
                          name=uuid.uuid4().hex,
                          password=uuid.uuid4().hex,
                          email=uuid.uuid4().hex,
                          tenant_id=uuid.uuid4().hex)

    def test_user_get_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.get,
                          user=uuid.uuid4().hex)

    def test_user_list_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.list,
                          tenant_id=uuid.uuid4().hex)

    def test_user_update_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.update,
                          user=uuid.uuid4().hex)

    def test_user_update_tenant(self):
        client = self.get_client(admin=True)
        tenant_id = uuid.uuid4().hex
        user = client.users.update(user=self.user_foo['id'],
                                   tenant_id=tenant_id)
        self.assertEqual(tenant_id, user.tenant_id)

    def test_user_update_password_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.update_password,
                          user=uuid.uuid4().hex,
                          password=uuid.uuid4().hex)

    def test_user_delete_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.delete,
                          user=uuid.uuid4().hex)

    def test_user_list(self):
        client = self.get_client(admin=True)
        users = client.users.list()
        self.assertTrue(len(users) > 0)
        user = users[0]
        self.assertRaises(AttributeError, lambda: user.password)

    def test_user_get(self):
        client = self.get_client(admin=True)
        user = client.users.get(user=self.user_foo['id'])
        self.assertRaises(AttributeError, lambda: user.password)

    def test_role_get(self):
        client = self.get_client(admin=True)
        role = client.roles.get(role=self.role_admin['id'])
        self.assertEqual(self.role_admin['id'], role.id)

    def test_role_crud(self):
        test_role = 'new_role'
        client = self.get_client(admin=True)
        role = client.roles.create(name=test_role)
        self.assertEqual(test_role, role.name)

        role = client.roles.get(role=role.id)
        self.assertEqual(test_role, role.name)

        client.roles.delete(role=role.id)

        self.assertRaises(client_exceptions.NotFound,
                          client.roles.delete,
                          role=role.id)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.get,
                          role=role.id)

    def test_role_create_no_name(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.roles.create,
                          name="")

    def test_role_create_member_role(self):
        # delete the member role so that we can recreate it
        client = self.get_client(admin=True)
        client.roles.delete(role=CONF.member_role_id)

        # deleting the member role revokes our token, so re-authenticate
        client = self.get_client(admin=True)

        # specify only the role name on creation
        role = client.roles.create(name=CONF.member_role_name)

        # the ID should be set as defined in CONF
        self.assertEqual(CONF.member_role_id, role.id)

    def test_role_get_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.get,
                          role=uuid.uuid4().hex)

    def test_role_delete_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.delete,
                          role=uuid.uuid4().hex)

    def test_role_list_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.roles_for_user,
                          user=uuid.uuid4().hex,
                          tenant=uuid.uuid4().hex)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.roles_for_user,
                          user=self.user_foo['id'],
                          tenant=uuid.uuid4().hex)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.roles_for_user,
                          user=uuid.uuid4().hex,
                          tenant=self.tenant_bar['id'])

    def test_role_list(self):
        client = self.get_client(admin=True)
        roles = client.roles.list()
        # TODO(devcamcar): This assert should be more specific.
        self.assertTrue(len(roles) > 0)

    def test_service_crud(self):
        client = self.get_client(admin=True)

        service_name = uuid.uuid4().hex
        service_type = uuid.uuid4().hex
        service_desc = uuid.uuid4().hex

        # create & read
        service = client.services.create(name=service_name,
                                         service_type=service_type,
                                         description=service_desc)
        self.assertEqual(service_name, service.name)
        self.assertEqual(service_type, service.type)
        self.assertEqual(service_desc, service.description)

        service = client.services.get(id=service.id)
        self.assertEqual(service_name, service.name)
        self.assertEqual(service_type, service.type)
        self.assertEqual(service_desc, service.description)

        service = [x for x in client.services.list() if x.id == service.id][0]
        self.assertEqual(service_name, service.name)
        self.assertEqual(service_type, service.type)
        self.assertEqual(service_desc, service.description)

        # update is not supported in API v2...

        # delete & read
        client.services.delete(id=service.id)
        self.assertRaises(client_exceptions.NotFound,
                          client.services.get,
                          id=service.id)
        services = [x for x in client.services.list() if x.id == service.id]
        self.assertEqual(0, len(services))

    def test_service_delete_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.services.delete,
                          id=uuid.uuid4().hex)

    def test_service_get_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.services.get,
                          id=uuid.uuid4().hex)

    def test_endpoint_delete_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.endpoints.delete,
                          id=uuid.uuid4().hex)

    def test_admin_requires_adminness(self):
        # FIXME(ja): this should be Unauthorized
        exception = client_exceptions.ClientException

        two = self.get_client(self.user_two, admin=True)  # non-admin user

        # USER CRUD
        self.assertRaises(exception,
                          two.users.list)
        self.assertRaises(exception,
                          two.users.get,
                          user=self.user_two['id'])
        self.assertRaises(exception,
                          two.users.create,
                          name='oops',
                          password='password',
                          email='oops@test.com')
        self.assertRaises(exception,
                          two.users.delete,
                          user=self.user_foo['id'])

        # TENANT CRUD
        self.assertRaises(exception,
                          two.tenants.list)
        self.assertRaises(exception,
                          two.tenants.get,
                          tenant_id=self.tenant_bar['id'])
        self.assertRaises(exception,
                          two.tenants.create,
                          tenant_name='oops',
                          description="shouldn't work!",
                          enabled=True)
        self.assertRaises(exception,
                          two.tenants.delete,
                          tenant=self.tenant_baz['id'])

        # ROLE CRUD
        self.assertRaises(exception,
                          two.roles.get,
                          role=self.role_admin['id'])
        self.assertRaises(exception,
                          two.roles.list)
        self.assertRaises(exception,
                          two.roles.create,
                          name='oops')
        self.assertRaises(exception,
                          two.roles.delete,
                          role=self.role_admin['id'])

        # TODO(ja): MEMBERSHIP CRUD
        # TODO(ja): determine what else todo

    def test_tenant_add_and_remove_user(self):
        client = self.get_client(admin=True)
        client.roles.add_user_role(tenant=self.tenant_bar['id'],
                                   user=self.user_two['id'],
                                   role=self.role_other['id'])
        user_refs = client.tenants.list_users(tenant=self.tenant_bar['id'])
        self.assertIn(self.user_two['id'], [x.id for x in user_refs])
        client.roles.remove_user_role(tenant=self.tenant_bar['id'],
                                      user=self.user_two['id'],
                                      role=self.role_other['id'])
        roles = client.roles.roles_for_user(user=self.user_foo['id'],
                                            tenant=self.tenant_bar['id'])
        self.assertNotIn(self.role_other['id'], roles)
        user_refs = client.tenants.list_users(tenant=self.tenant_bar['id'])
        self.assertNotIn(self.user_two['id'], [x.id for x in user_refs])

    def test_user_role_add_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.add_user_role,
                          tenant=uuid.uuid4().hex,
                          user=self.user_foo['id'],
                          role=self.role_member['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.add_user_role,
                          tenant=self.tenant_baz['id'],
                          user=self.user_foo['id'],
                          role=uuid.uuid4().hex)

    def test_user_role_add_no_user(self):
        # If add_user_role and user doesn't exist, doesn't fail.
        client = self.get_client(admin=True)
        client.roles.add_user_role(tenant=self.tenant_baz['id'],
                                   user=uuid.uuid4().hex,
                                   role=self.role_member['id'])

    def test_user_role_remove_404(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=uuid.uuid4().hex,
                          user=self.user_foo['id'],
                          role=self.role_member['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=self.tenant_baz['id'],
                          user=uuid.uuid4().hex,
                          role=self.role_member['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=self.tenant_baz['id'],
                          user=self.user_foo['id'],
                          role=uuid.uuid4().hex)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=self.tenant_baz['id'],
                          user=self.user_foo['id'],
                          role=self.role_member['id'])

    def test_tenant_list_marker(self):
        client = self.get_client()

        # Add two arbitrary tenants to user for testing purposes
        for i in range(2):
            tenant_id = uuid.uuid4().hex
            tenant = {'name': 'tenant-%s' % tenant_id, 'id': tenant_id,
                      'domain_id': DEFAULT_DOMAIN_ID}
            self.resource_api.create_project(tenant_id, tenant)
            self.assignment_api.add_user_to_project(tenant_id,
                                                    self.user_foo['id'])

        tenants = client.tenants.list()
        self.assertEqual(3, len(tenants))

        tenants_marker = client.tenants.list(marker=tenants[0].id)
        self.assertEqual(2, len(tenants_marker))
        self.assertEqual(tenants_marker[0].name, tenants[1].name)
        self.assertEqual(tenants_marker[1].name, tenants[2].name)

    def test_tenant_list_marker_not_found(self):
        client = self.get_client()
        self.assertRaises(client_exceptions.BadRequest,
                          client.tenants.list, marker=uuid.uuid4().hex)

    def test_tenant_list_limit(self):
        client = self.get_client()

        # Add two arbitrary tenants to user for testing purposes
        for i in range(2):
            tenant_id = uuid.uuid4().hex
            tenant = {'name': 'tenant-%s' % tenant_id, 'id': tenant_id,
                      'domain_id': DEFAULT_DOMAIN_ID}
            self.resource_api.create_project(tenant_id, tenant)
            self.assignment_api.add_user_to_project(tenant_id,
                                                    self.user_foo['id'])

        tenants = client.tenants.list()
        self.assertEqual(3, len(tenants))

        tenants_limited = client.tenants.list(limit=2)
        self.assertEqual(2, len(tenants_limited))
        self.assertEqual(tenants[0].name, tenants_limited[0].name)
        self.assertEqual(tenants[1].name, tenants_limited[1].name)

    def test_tenant_list_limit_bad_value(self):
        client = self.get_client()
        self.assertRaises(client_exceptions.BadRequest,
                          client.tenants.list, limit='a')
        self.assertRaises(client_exceptions.BadRequest,
                          client.tenants.list, limit=-1)

    def test_roles_get_by_user(self):
        client = self.get_client(admin=True)
        roles = client.roles.roles_for_user(user=self.user_foo['id'],
                                            tenant=self.tenant_bar['id'])
        self.assertTrue(len(roles) > 0)

    def test_user_can_update_passwd(self):
        client = self.get_client(self.user_two)

        token_id = client.auth_token
        new_password = uuid.uuid4().hex

        # TODO(derekh): Update to use keystoneclient when available
        class FakeResponse(object):
            def start_fake_response(self, status, headers):
                self.response_status = int(status.split(' ', 1)[0])
                self.response_headers = dict(headers)
        responseobject = FakeResponse()

        req = webob.Request.blank(
            '/v2.0/OS-KSCRUD/users/%s' % self.user_two['id'],
            headers={'X-Auth-Token': token_id})
        req.method = 'PATCH'
        req.body = ('{"user":{"password":"%s","original_password":"%s"}}' %
                    (new_password, self.user_two['password']))
        self.public_server.application(req.environ,
                                       responseobject.start_fake_response)

        self.user_two['password'] = new_password
        self.get_client(self.user_two)

    def test_user_cannot_update_other_users_passwd(self):
        client = self.get_client(self.user_two)

        token_id = client.auth_token
        new_password = uuid.uuid4().hex

        # TODO(derekh): Update to use keystoneclient when available
        class FakeResponse(object):
            def start_fake_response(self, status, headers):
                self.response_status = int(status.split(' ', 1)[0])
                self.response_headers = dict(headers)
        responseobject = FakeResponse()

        req = webob.Request.blank(
            '/v2.0/OS-KSCRUD/users/%s' % self.user_foo['id'],
            headers={'X-Auth-Token': token_id})
        req.method = 'PATCH'
        req.body = ('{"user":{"password":"%s","original_password":"%s"}}' %
                    (new_password, self.user_two['password']))
        self.public_server.application(req.environ,
                                       responseobject.start_fake_response)
        self.assertEqual(http_client.FORBIDDEN,
                         responseobject.response_status)

        self.user_two['password'] = new_password
        self.assertRaises(client_exceptions.Unauthorized,
                          self.get_client, self.user_two)

    def test_tokens_after_user_update_passwd(self):
        client = self.get_client(self.user_two)

        token_id = client.auth_token
        new_password = uuid.uuid4().hex

        # TODO(derekh): Update to use keystoneclient when available
        class FakeResponse(object):
            def start_fake_response(self, status, headers):
                self.response_status = int(status.split(' ', 1)[0])
                self.response_headers = dict(headers)
        responseobject = FakeResponse()

        req = webob.Request.blank(
            '/v2.0/OS-KSCRUD/users/%s' % self.user_two['id'],
            headers={'X-Auth-Token': token_id})
        req.method = 'PATCH'
        req.body = ('{"user":{"password":"%s","original_password":"%s"}}' %
                    (new_password, self.user_two['password']))

        rv = self.public_server.application(
            req.environ,
            responseobject.start_fake_response)
        response_json = jsonutils.loads(rv.pop())
        new_token_id = response_json['access']['token']['id']

        self.assertRaises(client_exceptions.Unauthorized, client.tenants.list)
        client.auth_token = new_token_id
        client.tenants.list()

    def test_endpoint_crud(self):
        client = self.get_client(admin=True)

        service = client.services.create(name=uuid.uuid4().hex,
                                         service_type=uuid.uuid4().hex,
                                         description=uuid.uuid4().hex)

        endpoint_region = uuid.uuid4().hex
        invalid_service_id = uuid.uuid4().hex
        endpoint_publicurl = uuid.uuid4().hex
        endpoint_internalurl = uuid.uuid4().hex
        endpoint_adminurl = uuid.uuid4().hex

        # a non-existent service ID should trigger a 400
        self.assertRaises(client_exceptions.BadRequest,
                          client.endpoints.create,
                          region=endpoint_region,
                          service_id=invalid_service_id,
                          publicurl=endpoint_publicurl,
                          adminurl=endpoint_adminurl,
                          internalurl=endpoint_internalurl)

        endpoint = client.endpoints.create(region=endpoint_region,
                                           service_id=service.id,
                                           publicurl=endpoint_publicurl,
                                           adminurl=endpoint_adminurl,
                                           internalurl=endpoint_internalurl)

        self.assertEqual(endpoint_region, endpoint.region)
        self.assertEqual(service.id, endpoint.service_id)
        self.assertEqual(endpoint_publicurl, endpoint.publicurl)
        self.assertEqual(endpoint_internalurl, endpoint.internalurl)
        self.assertEqual(endpoint_adminurl, endpoint.adminurl)

        client.endpoints.delete(id=endpoint.id)
        self.assertRaises(client_exceptions.NotFound, client.endpoints.delete,
                          id=endpoint.id)

    def _send_ec2_auth_request(self, credentials, client=None):
        if not client:
            client = self.default_client
        url = '%s/ec2tokens' % self.default_client.auth_url
        resp = client.session.request(
            url=url, method='POST',
            json={'credentials': credentials})
        return resp, resp.json()

    def _generate_default_user_ec2_credentials(self):
        cred = self. default_client.ec2.create(
            user_id=self.user_foo['id'],
            tenant_id=self.tenant_bar['id'])
        return self._generate_user_ec2_credentials(cred.access, cred.secret)

    def _generate_user_ec2_credentials(self, access, secret):
        signer = ec2_utils.Ec2Signer(secret)
        credentials = {'params': {'SignatureVersion': '2'},
                       'access': access,
                       'verb': 'GET',
                       'host': 'localhost',
                       'path': '/service/cloud'}
        signature = signer.generate(credentials)
        return credentials, signature

    def test_ec2_auth_success(self):
        credentials, signature = self._generate_default_user_ec2_credentials()
        credentials['signature'] = signature
        resp, token = self._send_ec2_auth_request(credentials)
        self.assertEqual(200, resp.status_code)
        self.assertIn('access', token)

    def test_ec2_auth_success_trust(self):
        # Add "other" role user_foo and create trust delegating it to user_two
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_other['id'])
        trust_id = 'atrust123'
        trust = {'trustor_user_id': self.user_foo['id'],
                 'trustee_user_id': self.user_two['id'],
                 'project_id': self.tenant_bar['id'],
                 'impersonation': True}
        roles = [self.role_other]
        self.trust_api.create_trust(trust_id, trust, roles)

        # Create a client for user_two, scoped to the trust
        client = self.get_client(self.user_two)
        ret = client.authenticate(trust_id=trust_id,
                                  tenant_id=self.tenant_bar['id'])
        self.assertTrue(ret)
        self.assertTrue(client.auth_ref.trust_scoped)
        self.assertEqual(trust_id, client.auth_ref.trust_id)

        # Create an ec2 keypair using the trust client impersonating user_foo
        cred = client.ec2.create(user_id=self.user_foo['id'],
                                 tenant_id=self.tenant_bar['id'])
        credentials, signature = self._generate_user_ec2_credentials(
            cred.access, cred.secret)
        credentials['signature'] = signature
        resp, token = self._send_ec2_auth_request(credentials)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(trust_id, token['access']['trust']['id'])
        # TODO(shardy) we really want to check the roles and trustee
        # but because of where the stubbing happens we don't seem to
        # hit the necessary code in controllers.py _authenticate_token
        # so although all is OK via a real request, it incorrect in
        # this test..

    def test_ec2_auth_failure(self):
        credentials, signature = self._generate_default_user_ec2_credentials()
        credentials['signature'] = uuid.uuid4().hex
        self.assertRaises(client_exceptions.Unauthorized,
                          self._send_ec2_auth_request,
                          credentials)

    def test_ec2_credential_crud(self):
        creds = self.default_client.ec2.list(user_id=self.user_foo['id'])
        self.assertEqual([], creds)

        cred = self.default_client.ec2.create(user_id=self.user_foo['id'],
                                              tenant_id=self.tenant_bar['id'])
        creds = self.default_client.ec2.list(user_id=self.user_foo['id'])
        self.assertEqual(creds, [cred])
        got = self.default_client.ec2.get(user_id=self.user_foo['id'],
                                          access=cred.access)
        self.assertEqual(cred, got)

        self.default_client.ec2.delete(user_id=self.user_foo['id'],
                                       access=cred.access)
        creds = self.default_client.ec2.list(user_id=self.user_foo['id'])
        self.assertEqual([], creds)

    def test_ec2_credential_crud_non_admin(self):
        na_client = self.get_client(self.user_two)
        creds = na_client.ec2.list(user_id=self.user_two['id'])
        self.assertEqual([], creds)

        cred = na_client.ec2.create(user_id=self.user_two['id'],
                                    tenant_id=self.tenant_baz['id'])
        creds = na_client.ec2.list(user_id=self.user_two['id'])
        self.assertEqual(creds, [cred])
        got = na_client.ec2.get(user_id=self.user_two['id'],
                                access=cred.access)
        self.assertEqual(cred, got)

        na_client.ec2.delete(user_id=self.user_two['id'],
                             access=cred.access)
        creds = na_client.ec2.list(user_id=self.user_two['id'])
        self.assertEqual([], creds)

    def test_ec2_list_credentials(self):
        cred_1 = self.default_client.ec2.create(
            user_id=self.user_foo['id'],
            tenant_id=self.tenant_bar['id'])
        cred_2 = self.default_client.ec2.create(
            user_id=self.user_foo['id'],
            tenant_id=self.tenant_service['id'])
        cred_3 = self.default_client.ec2.create(
            user_id=self.user_foo['id'],
            tenant_id=self.tenant_mtu['id'])
        two = self.get_client(self.user_two)
        cred_4 = two.ec2.create(user_id=self.user_two['id'],
                                tenant_id=self.tenant_bar['id'])
        creds = self.default_client.ec2.list(user_id=self.user_foo['id'])
        self.assertEqual(3, len(creds))
        self.assertEqual(sorted([cred_1, cred_2, cred_3],
                                key=lambda x: x.access),
                         sorted(creds, key=lambda x: x.access))
        self.assertNotIn(cred_4, creds)

    def test_ec2_credentials_create_404(self):
        self.assertRaises(client_exceptions.NotFound,
                          self.default_client.ec2.create,
                          user_id=uuid.uuid4().hex,
                          tenant_id=self.tenant_bar['id'])
        self.assertRaises(client_exceptions.NotFound,
                          self.default_client.ec2.create,
                          user_id=self.user_foo['id'],
                          tenant_id=uuid.uuid4().hex)

    def test_ec2_credentials_delete_404(self):
        self.assertRaises(client_exceptions.NotFound,
                          self.default_client.ec2.delete,
                          user_id=uuid.uuid4().hex,
                          access=uuid.uuid4().hex)

    def test_ec2_credentials_get_404(self):
        self.assertRaises(client_exceptions.NotFound,
                          self.default_client.ec2.get,
                          user_id=uuid.uuid4().hex,
                          access=uuid.uuid4().hex)

    def test_ec2_credentials_list_404(self):
        self.assertRaises(client_exceptions.NotFound,
                          self.default_client.ec2.list,
                          user_id=uuid.uuid4().hex)

    def test_ec2_credentials_list_user_forbidden(self):
        two = self.get_client(self.user_two)
        self.assertRaises(client_exceptions.Forbidden, two.ec2.list,
                          user_id=self.user_foo['id'])

    def test_ec2_credentials_get_user_forbidden(self):
        cred = self.default_client.ec2.create(user_id=self.user_foo['id'],
                                              tenant_id=self.tenant_bar['id'])

        two = self.get_client(self.user_two)
        self.assertRaises(client_exceptions.Forbidden, two.ec2.get,
                          user_id=self.user_foo['id'], access=cred.access)

        self.default_client.ec2.delete(user_id=self.user_foo['id'],
                                       access=cred.access)

    def test_ec2_credentials_delete_user_forbidden(self):
        cred = self.default_client.ec2.create(user_id=self.user_foo['id'],
                                              tenant_id=self.tenant_bar['id'])

        two = self.get_client(self.user_two)
        self.assertRaises(client_exceptions.Forbidden, two.ec2.delete,
                          user_id=self.user_foo['id'], access=cred.access)

        self.default_client.ec2.delete(user_id=self.user_foo['id'],
                                       access=cred.access)

    def test_endpoint_create_nonexistent_service(self):
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.endpoints.create,
                          region=uuid.uuid4().hex,
                          service_id=uuid.uuid4().hex,
                          publicurl=uuid.uuid4().hex,
                          adminurl=uuid.uuid4().hex,
                          internalurl=uuid.uuid4().hex)

    def test_policy_crud(self):
        # FIXME(dolph): this test was written prior to the v3 implementation of
        #               the client and essentially refers to a non-existent
        #               policy manager in the v2 client. this test needs to be
        #               moved to a test suite running against the v3 api
        self.skipTest('Written prior to v3 client; needs refactor')

        client = self.get_client(admin=True)

        policy_blob = uuid.uuid4().hex
        policy_type = uuid.uuid4().hex
        service = client.services.create(
            name=uuid.uuid4().hex,
            service_type=uuid.uuid4().hex,
            description=uuid.uuid4().hex)
        endpoint = client.endpoints.create(
            service_id=service.id,
            region=uuid.uuid4().hex,
            adminurl=uuid.uuid4().hex,
            internalurl=uuid.uuid4().hex,
            publicurl=uuid.uuid4().hex)

        # create
        policy = client.policies.create(
            blob=policy_blob,
            type=policy_type,
            endpoint=endpoint.id)
        self.assertEqual(policy_blob, policy.policy)
        self.assertEqual(policy_type, policy.type)
        self.assertEqual(endpoint.id, policy.endpoint_id)

        policy = client.policies.get(policy=policy.id)
        self.assertEqual(policy_blob, policy.policy)
        self.assertEqual(policy_type, policy.type)
        self.assertEqual(endpoint.id, policy.endpoint_id)

        endpoints = [x for x in client.endpoints.list() if x.id == endpoint.id]
        endpoint = endpoints[0]
        self.assertEqual(policy_blob, policy.policy)
        self.assertEqual(policy_type, policy.type)
        self.assertEqual(endpoint.id, policy.endpoint_id)

        # update
        policy_blob = uuid.uuid4().hex
        policy_type = uuid.uuid4().hex
        endpoint = client.endpoints.create(
            service_id=service.id,
            region=uuid.uuid4().hex,
            adminurl=uuid.uuid4().hex,
            internalurl=uuid.uuid4().hex,
            publicurl=uuid.uuid4().hex)

        policy = client.policies.update(
            policy=policy.id,
            blob=policy_blob,
            type=policy_type,
            endpoint=endpoint.id)

        policy = client.policies.get(policy=policy.id)
        self.assertEqual(policy_blob, policy.policy)
        self.assertEqual(policy_type, policy.type)
        self.assertEqual(endpoint.id, policy.endpoint_id)

        # delete
        client.policies.delete(policy=policy.id)
        self.assertRaises(
            client_exceptions.NotFound,
            client.policies.get,
            policy=policy.id)
        policies = [x for x in client.policies.list() if x.id == policy.id]
        self.assertEqual(0, len(policies))
