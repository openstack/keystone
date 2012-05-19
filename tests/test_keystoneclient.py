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

import uuid

import nose.exc

from keystone import test

import default_fixtures

OPENSTACK_REPO = 'https://review.openstack.org/p/openstack'
KEYSTONECLIENT_REPO = '%s/python-keystoneclient.git' % OPENSTACK_REPO


class CompatTestCase(test.TestCase):
    def setUp(self):
        super(CompatTestCase, self).setUp()

        revdir = test.checkout_vendor(*self.get_checkout())
        self.add_path(revdir)
        self.clear_module('keystoneclient')

        self.load_backends()
        self.load_fixtures(default_fixtures)

        self.public_server = self.serveapp('keystone', name='main')
        self.admin_server = self.serveapp('keystone', name='admin')

        # TODO(termie): is_admin is being deprecated once the policy stuff
        #               is all working
        # TODO(termie): add an admin user to the fixtures and use that user
        # override the fixtures, for now
        self.metadata_foobar = self.identity_api.update_metadata(
            self.user_foo['id'], self.tenant_bar['id'],
            dict(roles=['keystone_admin'], is_admin='1'))

    def tearDown(self):
        self.public_server.kill()
        self.admin_server.kill()
        self.public_server = None
        self.admin_server = None
        super(CompatTestCase, self).tearDown()

    def _public_url(self):
        public_port = self.public_server.socket_info['socket'][1]
        return "http://localhost:%s/v2.0" % public_port

    def _admin_url(self):
        admin_port = self.admin_server.socket_info['socket'][1]
        return "http://localhost:%s/v2.0" % admin_port

    def _client(self, admin=False, **kwargs):
        from keystoneclient.v2_0 import client as ks_client

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
                if user['id'] == user_ref['id']:
                    tenant_id = user['tenants'][0]
        else:
            tenant_id = tenant_ref['id']

        return self._client(username=user_ref['name'],
                            password=user_ref['password'],
                            tenant_id=tenant_id,
                            admin=admin)


class KeystoneClientTests(object):
    """Tests for all versions of keystoneclient."""

    def test_authenticate_tenant_name_and_tenants(self):
        client = self.get_client()
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_tenant_id_and_tenants(self):
        client = self._client(username=self.user_foo['name'],
                              password=self.user_foo['password'],
                              tenant_id='bar')
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_invalid_tenant_id(self):
        from keystoneclient import exceptions as client_exceptions
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
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_token_tenant_id(self):
        client = self.get_client()
        token = client.auth_token
        token_client = self._client(token=token, tenant_id='bar')
        tenants = token_client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_token_invalid_tenant_id(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client()
        token = client.auth_token
        self.assertRaises(client_exceptions.AuthorizationFailure,
                          self._client, token=token, tenant_id='baz')

    def test_authenticate_token_tenant_name(self):
        client = self.get_client()
        token = client.auth_token
        token_client = self._client(token=token, tenant_name='BAR')
        tenants = token_client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_and_delete_token(self):
        from keystoneclient import exceptions as client_exceptions

        client = self.get_client(admin=True)
        token = client.auth_token
        token_client = self._client(token=token)
        tenants = token_client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

        client.tokens.delete(token_client.auth_token)

        self.assertRaises(client_exceptions.Unauthorized,
                          token_client.tenants.list)

    def test_authenticate_no_password(self):
        from keystoneclient import exceptions as client_exceptions

        user_ref = self.user_foo.copy()
        user_ref['password'] = None
        self.assertRaises(client_exceptions.AuthorizationFailure,
                          self.get_client,
                          user_ref)

    def test_authenticate_no_username(self):
        from keystoneclient import exceptions as client_exceptions

        user_ref = self.user_foo.copy()
        user_ref['name'] = None
        self.assertRaises(client_exceptions.AuthorizationFailure,
                          self.get_client,
                          user_ref)

    # FIXME(ja): this test should require the "keystone:admin" roled
    #            (probably the role set via --keystone_admin_role flag)
    # FIXME(ja): add a test that admin endpoint is only sent to admin user
    # FIXME(ja): add a test that admin endpoint returns unauthorized if not
    #            admin
    def test_tenant_create_update_and_delete(self):
        from keystoneclient import exceptions as client_exceptions

        tenant_name = 'original_tenant'
        tenant_description = 'My original tenant!'
        tenant_enabled = True
        client = self.get_client(admin=True)

        # create, get, and list a tenant
        tenant = client.tenants.create(tenant_name=tenant_name,
                                       description=tenant_description,
                                       enabled=tenant_enabled)
        self.assertEquals(tenant.name, tenant_name)
        self.assertEquals(tenant.description, tenant_description)
        self.assertEquals(tenant.enabled, tenant_enabled)

        tenant = client.tenants.get(tenant_id=tenant.id)
        self.assertEquals(tenant.name, tenant_name)
        self.assertEquals(tenant.description, tenant_description)
        self.assertEquals(tenant.enabled, tenant_enabled)

        tenant = [t for t in client.tenants.list() if t.id == tenant.id].pop()
        self.assertEquals(tenant.name, tenant_name)
        self.assertEquals(tenant.description, tenant_description)
        self.assertEquals(tenant.enabled, tenant_enabled)

        # update, get, and list a tenant
        tenant_name = 'updated_tenant'
        tenant_description = 'Updated tenant!'
        tenant_enabled = False
        tenant = client.tenants.update(tenant_id=tenant.id,
                                       tenant_name=tenant_name,
                                       enabled=tenant_enabled,
                                       description=tenant_description)
        self.assertEquals(tenant.name, tenant_name)
        self.assertEquals(tenant.description, tenant_description)
        self.assertEquals(tenant.enabled, tenant_enabled)

        tenant = client.tenants.get(tenant_id=tenant.id)
        self.assertEquals(tenant.name, tenant_name)
        self.assertEquals(tenant.description, tenant_description)
        self.assertEquals(tenant.enabled, tenant_enabled)

        tenant = [t for t in client.tenants.list() if t.id == tenant.id].pop()
        self.assertEquals(tenant.name, tenant_name)
        self.assertEquals(tenant.description, tenant_description)
        self.assertEquals(tenant.enabled, tenant_enabled)

        # delete, get, and list a tenant
        client.tenants.delete(tenant=tenant.id)
        self.assertRaises(client_exceptions.NotFound, client.tenants.get,
                          tenant.id)
        self.assertFalse([t for t in client.tenants.list()
                           if t.id == tenant.id])

    def test_tenant_create_no_name(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.tenants.create,
                          tenant_name="")

    def test_tenant_delete_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.tenants.delete,
                          tenant=uuid.uuid4().hex)

    def test_tenant_get_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.tenants.get,
                          tenant_id=uuid.uuid4().hex)

    def test_tenant_update_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.tenants.update,
                          tenant_id=uuid.uuid4().hex)

    def test_tenant_list(self):
        client = self.get_client()
        tenants = client.tenants.list()
        self.assertEquals(len(tenants), 1)

        # Admin endpoint should return *all* tenants
        client = self.get_client(admin=True)
        tenants = client.tenants.list()
        self.assertEquals(len(tenants), len(default_fixtures.TENANTS))

    def test_invalid_password(self):
        from keystoneclient import exceptions as client_exceptions

        good_client = self._client(username=self.user_foo['name'],
                                   password=self.user_foo['password'])
        good_client.tenants.list()

        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username=self.user_foo['name'],
                          password='invalid')

    def test_invalid_user_password(self):
        from keystoneclient import exceptions as client_exceptions

        self.assertRaises(client_exceptions.Unauthorized,
                          self._client,
                          username='blah',
                          password='blah')

    def test_change_password_invalidates_token(self):
        from keystoneclient import exceptions as client_exceptions

        client = self.get_client(admin=True)

        username = uuid.uuid4().hex
        passwd = uuid.uuid4().hex
        user = client.users.create(name=username, password=passwd,
                                   email=uuid.uuid4().hex)

        token_id = client.tokens.authenticate(username=username,
                                              password=passwd).id

        # authenticate with a token should work before a password change
        client.tokens.authenticate(token=token_id)

        client.users.update_password(user=user.id, password=uuid.uuid4().hex)

        # authenticate with a token should not work after a password change
        self.assertRaises(client_exceptions.Unauthorized,
                          client.tokens.authenticate,
                          token=token_id)

    def test_disable_user_invalidates_token(self):
        from keystoneclient import exceptions as client_exceptions

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

    def test_user_create_update_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_username = 'new_user'
        client = self.get_client(admin=True)
        user = client.users.create(name=test_username,
                                   password='password',
                                   email='user1@test.com')
        self.assertEquals(user.name, test_username)

        user = client.users.get(user=user.id)
        self.assertEquals(user.name, test_username)

        user = client.users.update(user=user,
                                   name=test_username,
                                   email='user2@test.com')
        self.assertEquals(user.email, 'user2@test.com')

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
        self.assertEquals(user2.name, test_username)

    def test_user_create_no_name(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.users.create,
                          name="",
                          password=uuid.uuid4().hex,
                          email=uuid.uuid4().hex)

    def test_user_create_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.create,
                          name=uuid.uuid4().hex,
                          password=uuid.uuid4().hex,
                          email=uuid.uuid4().hex,
                          tenant_id=uuid.uuid4().hex)

    def test_user_get_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.get,
                          user=uuid.uuid4().hex)

    def test_user_list_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.list,
                          tenant_id=uuid.uuid4().hex)

    def test_user_update_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.update,
                          user=uuid.uuid4().hex)

    def test_user_update_tenant_404(self):
        raise nose.exc.SkipTest('N/A')
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.update,
                          user=self.user_foo['id'],
                          tenant_id=uuid.uuid4().hex)

    def test_user_update_password_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.users.update_password,
                          user=uuid.uuid4().hex,
                          password=uuid.uuid4().hex)

    def test_user_delete_404(self):
        from keystoneclient import exceptions as client_exceptions
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
        role = client.roles.get(role='keystone_admin')
        self.assertEquals(role.id, 'keystone_admin')

    def test_role_crud(self):
        from keystoneclient import exceptions as client_exceptions

        test_role = 'new_role'
        client = self.get_client(admin=True)
        role = client.roles.create(name=test_role)
        self.assertEquals(role.name, test_role)

        role = client.roles.get(role=role.id)
        self.assertEquals(role.name, test_role)

        client.roles.delete(role=role.id)

        self.assertRaises(client_exceptions.NotFound,
                          client.roles.delete,
                          role=role.id)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.get,
                          role=role.id)

    def test_role_create_no_name(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.BadRequest,
                          client.roles.create,
                          name="")

    def test_role_get_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.get,
                          role=uuid.uuid4().hex)

    def test_role_delete_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.delete,
                          role=uuid.uuid4().hex)

    def test_role_list_404(self):
        from keystoneclient import exceptions as client_exceptions
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

    def test_ec2_credential_crud(self):
        client = self.get_client()
        creds = client.ec2.list(user_id=self.user_foo['id'])
        self.assertEquals(creds, [])

        cred = client.ec2.create(user_id=self.user_foo['id'],
                                 tenant_id=self.tenant_bar['id'])
        creds = client.ec2.list(user_id=self.user_foo['id'])
        self.assertEquals(creds, [cred])

        got = client.ec2.get(user_id=self.user_foo['id'], access=cred.access)
        self.assertEquals(cred, got)

        client.ec2.delete(user_id=self.user_foo['id'], access=cred.access)
        creds = client.ec2.list(user_id=self.user_foo['id'])
        self.assertEquals(creds, [])

    def test_ec2_credentials_create_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client()
        self.assertRaises(client_exceptions.NotFound,
                          client.ec2.create,
                          user_id=uuid.uuid4().hex,
                          tenant_id=self.tenant_bar['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.ec2.create,
                          user_id=self.user_foo['id'],
                          tenant_id=uuid.uuid4().hex)

    def test_ec2_credentials_delete_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client()
        self.assertRaises(client_exceptions.NotFound,
                          client.ec2.delete,
                          user_id=uuid.uuid4().hex,
                          access=uuid.uuid4().hex)

    def test_ec2_credentials_get_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client()
        self.assertRaises(client_exceptions.NotFound,
                          client.ec2.get,
                          user_id=uuid.uuid4().hex,
                          access=uuid.uuid4().hex)

    def test_ec2_credentials_list_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client()
        self.assertRaises(client_exceptions.NotFound,
                          client.ec2.list,
                          user_id=uuid.uuid4().hex)

    def test_ec2_credentials_list_user_forbidden(self):
        from keystoneclient import exceptions as client_exceptions

        two = self.get_client(self.user_two)
        self.assertRaises(client_exceptions.Forbidden, two.ec2.list,
                          user_id=self.user_foo['id'])

    def test_ec2_credentials_get_user_forbidden(self):
        from keystoneclient import exceptions as client_exceptions

        foo = self.get_client()
        cred = foo.ec2.create(user_id=self.user_foo['id'],
                              tenant_id=self.tenant_bar['id'])

        two = self.get_client(self.user_two)
        self.assertRaises(client_exceptions.Forbidden, two.ec2.get,
                          user_id=self.user_foo['id'], access=cred.access)

        foo.ec2.delete(user_id=self.user_foo['id'], access=cred.access)

    def test_ec2_credentials_delete_user_forbidden(self):
        from keystoneclient import exceptions as client_exceptions

        foo = self.get_client()
        cred = foo.ec2.create(user_id=self.user_foo['id'],
                              tenant_id=self.tenant_bar['id'])

        two = self.get_client(self.user_two)
        self.assertRaises(client_exceptions.Forbidden, two.ec2.delete,
                          user_id=self.user_foo['id'], access=cred.access)

        foo.ec2.delete(user_id=self.user_foo['id'], access=cred.access)

    def test_service_crud(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)

        service_name = uuid.uuid4().hex
        service_type = uuid.uuid4().hex
        service_desc = uuid.uuid4().hex

        # create & read
        service = client.services.create(name=service_name,
                                         service_type=service_type,
                                         description=service_desc)
        self.assertEquals(service_name, service.name)
        self.assertEquals(service_type, service.type)
        self.assertEquals(service_desc, service.description)

        service = client.services.get(id=service.id)
        self.assertEquals(service_name, service.name)
        self.assertEquals(service_type, service.type)
        self.assertEquals(service_desc, service.description)

        service = [x for x in client.services.list() if x.id == service.id][0]
        self.assertEquals(service_name, service.name)
        self.assertEquals(service_type, service.type)
        self.assertEquals(service_desc, service.description)

        # update is not supported...

        # delete & read
        client.services.delete(id=service.id)
        self.assertRaises(client_exceptions.NotFound,
                          client.services.get,
                          id=service.id)
        services = [x for x in client.services.list() if x.id == service.id]
        self.assertEquals(len(services), 0)

    def test_service_delete_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.services.delete,
                          id=uuid.uuid4().hex)

    def test_service_get_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.services.get,
                          id=uuid.uuid4().hex)

    def test_endpoint_create_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.endpoints.create,
                          region=uuid.uuid4().hex,
                          service_id=uuid.uuid4().hex,
                          publicurl=uuid.uuid4().hex,
                          adminurl=uuid.uuid4().hex,
                          internalurl=uuid.uuid4().hex)

    def test_endpoint_delete_404(self):
        # the catalog backend is expected to return Not Implemented
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.HTTPNotImplemented,
                          client.endpoints.delete,
                          id=uuid.uuid4().hex)

    def test_admin_requires_adminness(self):
        from keystoneclient import exceptions as client_exceptions
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
                          role='keystone_admin')
        self.assertRaises(exception,
                          two.roles.list)
        self.assertRaises(exception,
                          two.roles.create,
                          name='oops')
        self.assertRaises(exception,
                          two.roles.delete,
                          role='keystone_admin')

        # TODO(ja): MEMBERSHIP CRUD
        # TODO(ja): determine what else todo


class KcMasterTestCase(CompatTestCase, KeystoneClientTests):
    def get_checkout(self):
        return KEYSTONECLIENT_REPO, 'master'

    def test_tenant_add_and_remove_user(self):
        client = self.get_client(admin=True)
        client.roles.add_user_role(tenant=self.tenant_baz['id'],
                                   user=self.user_foo['id'],
                                   role=self.role_useless['id'])
        user_refs = client.tenants.list_users(tenant=self.tenant_baz['id'])
        self.assert_(self.user_foo['id'] in [x.id for x in user_refs])
        client.roles.remove_user_role(tenant=self.tenant_baz['id'],
                                      user=self.user_foo['id'],
                                      role=self.role_useless['id'])
        user_refs = client.tenants.list_users(tenant=self.tenant_baz['id'])
        self.assert_(self.user_foo['id'] not in [x.id for x in user_refs])

    def test_user_role_add_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.add_user_role,
                          tenant=uuid.uuid4().hex,
                          user=self.user_foo['id'],
                          role=self.role_useless['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.add_user_role,
                          tenant=self.tenant_baz['id'],
                          user=uuid.uuid4().hex,
                          role=self.role_useless['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.add_user_role,
                          tenant=self.tenant_baz['id'],
                          user=self.user_foo['id'],
                          role=uuid.uuid4().hex)

    def test_user_role_remove_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=uuid.uuid4().hex,
                          user=self.user_foo['id'],
                          role=self.role_useless['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=self.tenant_baz['id'],
                          user=uuid.uuid4().hex,
                          role=self.role_useless['id'])
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=self.tenant_baz['id'],
                          user=self.user_foo['id'],
                          role=uuid.uuid4().hex)
        self.assertRaises(client_exceptions.NotFound,
                          client.roles.remove_user_role,
                          tenant=self.tenant_baz['id'],
                          user=self.user_foo['id'],
                          role=self.role_useless['id'])

    def test_tenant_list_marker(self):
        client = self.get_client()

        # Add two arbitrary tenants to user for testing purposes
        for i in range(2):
            tenant_id = uuid.uuid4().hex
            tenant = {'name': 'tenant-%s' % tenant_id, 'id': tenant_id}
            self.identity_api.create_tenant(tenant_id, tenant)
            self.identity_api.add_user_to_tenant(tenant_id,
                                                 self.user_foo['id'])

        tenants = client.tenants.list()
        self.assertEqual(len(tenants), 3)

        tenants_marker = client.tenants.list(marker=tenants[0].id)
        self.assertEqual(len(tenants_marker), 2)
        self.assertEqual(tenants[1].name, tenants_marker[0].name)
        self.assertEqual(tenants[2].name, tenants_marker[1].name)

    def test_tenant_list_marker_not_found(self):
        from keystoneclient import exceptions as client_exceptions

        client = self.get_client()
        self.assertRaises(client_exceptions.BadRequest,
                          client.tenants.list, marker=uuid.uuid4().hex)

    def test_tenant_list_limit(self):
        client = self.get_client()

        # Add two arbitrary tenants to user for testing purposes
        for i in range(2):
            tenant_id = uuid.uuid4().hex
            tenant = {'name': 'tenant-%s' % tenant_id, 'id': tenant_id}
            self.identity_api.create_tenant(tenant_id, tenant)
            self.identity_api.add_user_to_tenant(tenant_id,
                                                 self.user_foo['id'])

        tenants = client.tenants.list()
        self.assertEqual(len(tenants), 3)

        tenants_limited = client.tenants.list(limit=2)
        self.assertEqual(len(tenants_limited), 2)
        self.assertEqual(tenants[0].name, tenants_limited[0].name)
        self.assertEqual(tenants[1].name, tenants_limited[1].name)

    def test_tenant_list_limit_bad_value(self):
        from keystoneclient import exceptions as client_exceptions

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


class KcEssex3TestCase(CompatTestCase, KeystoneClientTests):
    def get_checkout(self):
        return KEYSTONECLIENT_REPO, 'essex-3'

    def test_tenant_add_and_remove_user(self):
        client = self.get_client(admin=True)
        client.roles.add_user_to_tenant(tenant_id=self.tenant_baz['id'],
                                        user_id=self.user_foo['id'],
                                        role_id=self.role_useless['id'])
        role_refs = client.roles.get_user_role_refs(
                user_id=self.user_foo['id'])
        self.assert_(self.tenant_baz['id'] in [x.tenantId for x in role_refs])

        # get the "role_refs" so we get the proper id, this is how the clients
        # do it
        roleref_refs = client.roles.get_user_role_refs(
                user_id=self.user_foo['id'])
        for roleref_ref in roleref_refs:
            if (roleref_ref.roleId == self.role_useless['id']
                and roleref_ref.tenantId == self.tenant_baz['id']):
                # use python's scope fall through to leave roleref_ref set
                break

        client.roles.remove_user_from_tenant(tenant_id=self.tenant_baz['id'],
                                             user_id=self.user_foo['id'],
                                             role_id=roleref_ref.id)

        role_refs = client.roles.get_user_role_refs(
                user_id=self.user_foo['id'])
        self.assert_(self.tenant_baz['id'] not in
                     [x.tenantId for x in role_refs])

    def test_roles_get_by_user(self):
        client = self.get_client(admin=True)
        roles = client.roles.get_user_role_refs(user_id='foo')
        self.assertTrue(len(roles) > 0)

    def test_role_list_404(self):
        raise nose.exc.SkipTest('N/A')

    def test_authenticate_and_delete_token(self):
        raise nose.exc.SkipTest('N/A')

    def test_user_create_update_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_username = 'new_user'
        client = self.get_client(admin=True)
        user = client.users.create(name=test_username,
                                   password='password',
                                   email='user1@test.com')
        self.assertEquals(user.name, test_username)

        user = client.users.get(user=user.id)
        self.assertEquals(user.name, test_username)

        user = client.users.update_email(user=user, email='user2@test.com')
        self.assertEquals(user.email, 'user2@test.com')

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

    def test_user_update_404(self):
        raise nose.exc.SkipTest('N/A')

    def test_endpoint_create_404(self):
        raise nose.exc.SkipTest('N/A')

    def test_endpoint_delete_404(self):
        raise nose.exc.SkipTest('N/A')
