# vim: tabstop=4 shiftwidth=4 softtabstop=4
import nose.exc

from keystone import config
from keystone import test

import default_fixtures

CONF = config.CONF
OPENSTACK_REPO = 'https://review.openstack.org/p/openstack'
KEYSTONECLIENT_REPO = '%s/python-keystoneclient.git' % OPENSTACK_REPO


class CompatTestCase(test.TestCase):
    def setUp(self):
        super(CompatTestCase, self).setUp()

        revdir = test.checkout_vendor(*self.get_checkout())
        self.add_path(revdir)
        self.clear_module('keystoneclient')

        self.public_app = self.loadapp('keystone', name='main')
        self.admin_app = self.loadapp('keystone', name='admin')

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

    def _public_url(self):
        public_port = self.public_server.socket_info['socket'][1]
        CONF.public_port = public_port
        return "http://localhost:%s/v2.0" % public_port

    def _admin_url(self):
        admin_port = self.admin_server.socket_info['socket'][1]
        CONF.admin_port = admin_port
        return "http://localhost:%s/v2.0" % admin_port

    def _client(self, **kwargs):
        from keystoneclient.v2_0 import client as ks_client

        kc = ks_client.Client(endpoint=self._admin_url(),
                              auth_url=self._public_url(),
                              **kwargs)
        kc.authenticate()
        # have to manually overwrite the management url after authentication
        kc.management_url = self._admin_url()
        return kc

    def get_client(self, user_ref=None, tenant_ref=None):
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
                            tenant_id=tenant_id)


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
        self.assertRaises(client_exceptions.AuthorizationFailure,
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

        client = self.get_client()
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

    # TODO(termie): I'm not really sure that this is testing much
    def test_endpoints(self):
        client = self.get_client()
        token = client.auth_token
        endpoints = client.tokens.endpoints(token=token)

    # FIXME(ja): this test should require the "keystone:admin" roled
    #            (probably the role set via --keystone_admin_role flag)
    # FIXME(ja): add a test that admin endpoint is only sent to admin user
    # FIXME(ja): add a test that admin endpoint returns unauthorized if not
    #            admin
    def test_tenant_create_update_and_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_tenant = 'new_tenant'
        client = self.get_client()
        tenant = client.tenants.create(tenant_name=test_tenant,
                                       description="My new tenant!",
                                       enabled=True)
        self.assertEquals(tenant.name, test_tenant)

        tenant = client.tenants.get(tenant_id=tenant.id)
        self.assertEquals(tenant.name, test_tenant)

        # TODO(devcamcar): update gives 404. why?
        tenant = client.tenants.update(tenant_id=tenant.id,
                                       tenant_name='new_tenant2',
                                       enabled=False,
                                       description='new description')
        self.assertEquals(tenant.name, 'new_tenant2')
        self.assertFalse(tenant.enabled)
        self.assertEquals(tenant.description, 'new description')

        client.tenants.delete(tenant=tenant.id)
        self.assertRaises(client_exceptions.NotFound, client.tenants.get,
                          tenant.id)

    def test_tenant_list(self):
        client = self.get_client()
        tenants = client.tenants.list()
        self.assertEquals(len(tenants), 1)

    def test_invalid_password(self):
        from keystoneclient import exceptions as client_exceptions

        good_client = self._client(username=self.user_foo['name'],
                                   password=self.user_foo['password'])
        good_client.tenants.list()

        self.assertRaises(client_exceptions.AuthorizationFailure,
                          self._client,
                          username=self.user_foo['name'],
                          password='invalid')

    def test_user_create_update_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_username = 'new_user'
        client = self.get_client()
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

        self.assertRaises(client_exceptions.AuthorizationFailure,
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

    def test_user_list(self):
        client = self.get_client()
        users = client.users.list()
        self.assertTrue(len(users) > 0)
        user = users[0]
        self.assertRaises(AttributeError, lambda: user.password)

    def test_user_get(self):
        client = self.get_client()
        user = client.users.get(user=self.user_foo['id'])
        self.assertRaises(AttributeError, lambda: user.password)

    def test_role_get(self):
        client = self.get_client()
        role = client.roles.get(role='keystone_admin')
        self.assertEquals(role.id, 'keystone_admin')

    def test_role_create_and_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_role = 'new_role'
        client = self.get_client()
        role = client.roles.create(name=test_role)
        self.assertEquals(role.name, test_role)

        role = client.roles.get(role=role.id)
        self.assertEquals(role.name, test_role)

        client.roles.delete(role=role.id)

        self.assertRaises(client_exceptions.NotFound, client.roles.get,
                          role=role.id)

    def test_role_list(self):
        client = self.get_client()
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

    def test_service_create_and_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_service = 'new_service'
        client = self.get_client()
        service = client.services.create(name=test_service,
                                         service_type='test',
                                         description='test')
        self.assertEquals(service.name, test_service)

        service = client.services.get(id=service.id)
        self.assertEquals(service.name, test_service)

        client.services.delete(id=service.id)
        self.assertRaises(client_exceptions.NotFound, client.services.get,
                          id=service.id)

    def test_service_list(self):
        client = self.get_client()
        test_service = 'new_service'
        service = client.services.create(name=test_service,
                                         service_type='test',
                                         description='test')
        services = client.services.list()
        # TODO(devcamcar): This assert should be more specific.
        self.assertTrue(len(services) > 0)

    def test_admin_requires_adminness(self):
        from keystoneclient import exceptions as client_exceptions
        # FIXME(ja): this should be Unauthorized
        exception = client_exceptions.ClientException

        two = self.get_client(self.user_two)  # non-admin user

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
        # NOTE(ja): tenants.list is different since /tenants fulfills the
        #           two different tasks: return list of all tenants & return
        #           list of tenants the current user is a member of...
        #           which means if you are admin getting the list
        #           of tenants for admin user is annoying?
        tenants = two.tenants.list()
        self.assertTrue(len(tenants) == 1)
        self.assertTrue(tenants[0].id == self.tenant_baz['id'])
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
        client = self.get_client()
        client.roles.add_user_role(tenant=self.tenant_baz['id'],
                                   user=self.user_foo['id'],
                                   role=self.role_useless['id'])
        tenant_refs = client.tenants.list()
        self.assert_(self.tenant_baz['id'] in
                     [x.id for x in tenant_refs])

        client.roles.remove_user_role(tenant=self.tenant_baz['id'],
                                      user=self.user_foo['id'],
                                      role=self.role_useless['id'])

        tenant_refs = client.tenants.list()
        self.assert_(self.tenant_baz['id'] not in
                     [x.id for x in tenant_refs])

    def test_roles_get_by_user(self):
        client = self.get_client()
        roles = client.roles.roles_for_user(user=self.user_foo['id'],
                                            tenant=self.tenant_bar['id'])
        self.assertTrue(len(roles) > 0)


class KcEssex3TestCase(CompatTestCase, KeystoneClientTests):
    def get_checkout(self):
        return KEYSTONECLIENT_REPO, 'essex-3'

    def test_tenant_add_and_remove_user(self):
        client = self.get_client()
        client.roles.add_user_to_tenant(tenant_id=self.tenant_baz['id'],
                                        user_id=self.user_foo['id'],
                                        role_id=self.role_useless['id'])
        tenant_refs = client.tenants.list()
        self.assert_(self.tenant_baz['id'] in
                     [x.id for x in tenant_refs])

        # get the "role_refs" so we get the proper id, this is how the clients
        # do it
        roleref_refs = client.roles.get_user_role_refs(
                user_id=self.user_foo['id'])
        for roleref_ref in roleref_refs:
          if (roleref_ref.roleId == self.role_useless['id'] and
              roleref_ref.tenantId == self.tenant_baz['id']):
            # use python's scope fall through to leave roleref_ref set
            break

        client.roles.remove_user_from_tenant(tenant_id=self.tenant_baz['id'],
                                             user_id=self.user_foo['id'],
                                             role_id=roleref_ref.id)

        tenant_refs = client.tenants.list()
        self.assert_(self.tenant_baz['id'] not in
                     [x.id for x in tenant_refs])

    def test_roles_get_by_user(self):
        client = self.get_client()
        roles = client.roles.get_user_role_refs(user_id='foo')
        self.assertTrue(len(roles) > 0)

    def test_authenticate_and_delete_token(self):
        raise nose.exc.SkipTest('N/A')
