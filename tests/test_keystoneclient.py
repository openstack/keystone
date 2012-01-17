# vim: tabstop=4 shiftwidth=4 softtabstop=4
from keystone import config
from keystone import test

import default_fixtures

CONF = config.CONF
KEYSTONECLIENT_REPO = 'git://github.com/openstack/python-keystoneclient.git'


class CompatTestCase(test.TestCase):
    def setUp(self):
        super(CompatTestCase, self).setUp()

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


class KcMasterTestCase(CompatTestCase):
    def setUp(self):
        super(KcMasterTestCase, self).setUp()

        revdir = test.checkout_vendor(KEYSTONECLIENT_REPO, 'master')
        self.add_path(revdir)
        from keystoneclient.v2_0 import client as ks_client
        reload(ks_client)

        self._config()
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

    def _config(self):
        CONF(config_files=[test.etcdir('keystone.conf'),
                           test.testsdir('test_overrides.conf')])

    def foo_client(self):
        return self._client(username='FOO',
                            password='foo2',
                            tenant_name='BAR')

    def test_authenticate_tenant_name_and_tenants(self):
        client = self.foo_client()
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_tenant_id_and_tenants(self):
        client = self._client(username='FOO',
                              password='foo2',
                              tenant_id='bar')

        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_token_no_tenant(self):
        client = self.foo_client()
        token = client.auth_token
        token_client = self._client(token=token)
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_token_tenant_id(self):
        client = self.foo_client()
        token = client.auth_token
        token_client = self._client(token=token, tenant_id='bar')
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_token_tenant_name(self):
        client = self.foo_client()
        token = client.auth_token
        token_client = self._client(token=token, tenant_name='BAR')
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    # TODO(termie): I'm not really sure that this is testing much
    def test_endpoints(self):
        client = self.foo_client()
        token = client.auth_token
        endpoints = client.tokens.endpoints(token)

    # FIXME(ja): this test should require the "keystone:admin" roled
    #            (probably the role set via --keystone_admin_role flag)
    # FIXME(ja): add a test that admin endpoint is only sent to admin user
    # FIXME(ja): add a test that admin endpoint returns unauthorized if not
    #            admin
    def test_tenant_create_update_and_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_tenant = 'new_tenant'
        client = self.foo_client()
        tenant = client.tenants.create(test_tenant,
                                       description="My new tenant!",
                                       enabled=True)
        self.assertEquals(tenant.name, test_tenant)

        tenant = client.tenants.get(tenant.id)
        self.assertEquals(tenant.name, test_tenant)

        # TODO(devcamcar): update gives 404. why?
        tenant = client.tenants.update(tenant.id,
                                       tenant_name='new_tenant2',
                                       enabled=False,
                                       description='new description')
        self.assertEquals(tenant.name, 'new_tenant2')
        self.assertFalse(tenant.enabled)
        self.assertEquals(tenant.description, 'new description')

        client.tenants.delete(tenant.id)
        self.assertRaises(client_exceptions.NotFound, client.tenants.get,
                          tenant.id)

    def test_tenant_list(self):
        client = self.foo_client()
        tenants = client.tenants.list()
        self.assertEquals(len(tenants), 1)

    def test_tenant_add_and_remove_user(self):
        client = self.foo_client()
        client.roles.add_user_to_tenant(self.tenant_baz['id'],
                                        self.user_foo['id'],
                                        self.role_useless['id'])
        tenant_refs = client.tenants.list()
        self.assert_(self.tenant_baz['id'] in
                     [x.id for x in tenant_refs])

        # get the "role_refs" so we get the proper id, this is how the clients
        # do it
        roleref_refs = client.roles.get_user_role_refs(self.user_foo['id'])
        for roleref_ref in roleref_refs:
          if (roleref_ref.roleId == self.role_useless['id'] and
              roleref_ref.tenantId == self.tenant_baz['id']):
            # use python's scope fall through to leave roleref_ref set
            break


        client.roles.remove_user_from_tenant(self.tenant_baz['id'],
                                             self.user_foo['id'],
                                             roleref_ref.id)

        tenant_refs = client.tenants.list()
        self.assert_(self.tenant_baz['id'] not in
                     [x.id for x in tenant_refs])

    def test_user_create_update_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_user = 'new_user'
        client = self.foo_client()
        user = client.users.create(test_user, 'password', 'user1@test.com')
        self.assertEquals(user.name, test_user)

        user = client.users.get(user.id)
        self.assertEquals(user.name, test_user)

        user = client.users.update_email(user, 'user2@test.com')
        self.assertEquals(user.email, 'user2@test.com')

        # NOTE(termie): update_enabled doesn't return anything, probably a bug
        client.users.update_enabled(user, False)
        user = client.users.get(user.id)
        self.assertFalse(user.enabled)

        # TODO(devcamcar): How to assert this succeeded?
        user = client.users.update_password(user, 'password2')

        # TODO(devcamcar): How to assert this succeeded?
        user = client.users.update_tenant(user, 'bar')

        client.users.delete(user.id)
        self.assertRaises(client_exceptions.NotFound, client.users.get,
                          user.id)

    def test_user_list(self):
        client = self.foo_client()
        users = client.users.list()
        self.assertTrue(len(users) > 0)

    def test_role_get(self):
        client = self.foo_client()
        role = client.roles.get('keystone_admin')
        self.assertEquals(role.id, 'keystone_admin')

    def test_role_create_and_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_role = 'new_role'
        client = self.foo_client()
        role = client.roles.create(test_role)
        self.assertEquals(role.name, test_role)

        role = client.roles.get(role)
        self.assertEquals(role.name, test_role)

        client.roles.delete(role)

        self.assertRaises(client_exceptions.NotFound, client.roles.get,
                          test_role)

    def test_role_list(self):
        client = self.foo_client()
        roles = client.roles.list()
        # TODO(devcamcar): This assert should be more specific.
        self.assertTrue(len(roles) > 0)

    def test_roles_get_by_user(self):
        client = self.foo_client()
        roles = client.roles.get_user_role_refs('foo')
        self.assertTrue(len(roles) > 0)

    def test_ec2_credential_creation(self):
        from keystoneclient import exceptions as client_exceptions

        client = self.foo_client()
        creds = client.ec2.list(self.user_foo['id'])
        self.assertEquals(creds, [])

        cred = client.ec2.create(self.user_foo['id'], self.tenant_bar['id'])
        creds = client.ec2.list(self.user_foo['id'])
        self.assertEquals(creds, [cred])

        got = client.ec2.get(self.user_foo['id'], cred.access)
        self.assertEquals(cred, got)

        # FIXME(ja): need to test ec2 validation here

        client.ec2.delete(self.user_foo['id'], cred.access)
        creds = client.ec2.list(self.user_foo['id'])
        self.assertEquals(creds, [])

    def test_service_create_and_delete(self):
        from keystoneclient import exceptions as client_exceptions

        test_service = 'new_service'
        client = self.foo_client()
        service = client.services.create(test_service, 'test', 'test')
        self.assertEquals(service.name, test_service)

        service = client.services.get(service.id)
        self.assertEquals(service.name, test_service)

        client.services.delete(service.id)
        self.assertRaises(client_exceptions.NotFound, client.services.get,
                          service.id)

    def test_service_list(self):
        client = self.foo_client()
        test_service = 'new_service'
        service = client.services.create(test_service, 'test', 'test')
        services = client.services.list()
        # TODO(devcamcar): This assert should be more specific.
        self.assertTrue(len(services) > 0)
