import logging

from keystonelight import test

import default_fixtures


KEYSTONECLIENT_REPO = 'git://github.com/openstack/python-keystoneclient.git'


class CompatTestCase(test.TestCase):
    def setUp(self):
        super(CompatTestCase, self).setUp()

    def _public_url(self):
        public_port = self.public_server.socket_info['socket'][1]
        self.options['public_port'] = public_port
        return "http://localhost:%s/v2.0" % public_port

    def _admin_url(self):
        admin_port = self.admin_server.socket_info['socket'][1]
        self.options['admin_port'] = admin_port
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


class MasterCompatTestCase(CompatTestCase):
    def setUp(self):
        super(MasterCompatTestCase, self).setUp()

        revdir = test.checkout_vendor(KEYSTONECLIENT_REPO, 'master')
        self.add_path(revdir)
        from keystoneclient.v2_0 import client as ks_client
        reload(ks_client)

        self.options = self.appconfig('keystoneclient_compat_master')
        self.public_app = self.loadapp('keystoneclient_compat_master',
                                        name='main')
        self.admin_app = self.loadapp('keystoneclient_compat_master',
                                      name='admin')

        self.load_backends()
        self.load_fixtures(default_fixtures)

        self.public_server = self.serveapp('keystoneclient_compat_master',
                                           name='main')
        self.admin_server = self.serveapp('keystoneclient_compat_master',
                                          name='admin')

        # TODO(termie): is_admin is being deprecated once the policy stuff
        #               is all working
        # TODO(termie): add an admin user to the fixtures and use that user
        # override the fixtures, for now
        self.extras_foobar = self.identity_api.update_extras(
            self.user_foo['id'], self.tenant_bar['id'],
            dict(roles=['keystone_admin'], is_admin='1'))

    # def test_authenticate(self):
    #     from keystoneclient.v2_0 import client as ks_client
    #
    #     port = self.server.socket_info['socket'][1]
    #     client = ks_client.Client(auth_url="http://localhost:%s/v2.0" % port,
    #                               username='foo',
    #                               password='foo',
    #                               project_id='bar')
    #     client.authenticate()

    def test_authenticate_tenant_name_and_tenants(self):
        client = self._client(username='FOO',
                              password='foo2',
                              tenant_name='BAR')
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    def test_authenticate_tenant_id_and_tenants(self):
        client = self._client(username='FOO',
                              password='foo2',
                              tenant_id='bar')
        tenants = client.tenants.list()
        self.assertEquals(tenants[0].id, self.tenant_bar['id'])

    # FIXME(ja): this test should require the "keystone:admin" roled
    #            (probably the role set via --keystone_admin_role flag)
    # FIXME(ja): add a test that admin endpoint is only sent to admin user
    # FIXME(ja): add a test that admin endpoint returns unauthorized if not
    #            admin
    def test_tenant_create(self):
        client = self._client(username='FOO',
                              password='foo2',
                              tenant_name='BAR')
        client.tenants.create(
            "hello", description="My new tenant!", enabled=True)
        # FIXME(ja): assert tenant was created
