import unittest2 as unittest
import uuid

from keystone import backends
import keystone.backends.api as api
from keystone import models
from keystone import utils


class BackendTestCase(unittest.TestCase):
    """
    Base class to run tests for Keystone backends (and backend configs)
    """

    def setUp(self, options=None):
        super(BackendTestCase, self).setUp()
        # Set up root options if missing
        if options is None:
            options = {
            'backends': None,
            "keystone-service-admin-role": "KeystoneServiceAdmin",
            "keystone-admin-role": "KeystoneAdmin",
            "hash-password": "False"
            }

        # set up default backend if none supplied
        if 'backends' not in options or options['backends'] is None:
            options['backends'] = 'keystone.backends.sqlalchemy'
            if 'keystone.backends.sqlalchemy' not in options:
                options['keystone.backends.sqlalchemy'] = {
                "sql_connection": "sqlite://",
                "backend_entities": "['UserRoleAssociation', 'Endpoints',\
                                     'Role', 'Tenant', 'User',\
                                     'Credentials', 'EndpointTemplates',\
                                     'Token', 'Service']",
                "sql_idle_timeout": "30"
                }

        # Init backends module constants (without initializing backends)
        no_backend_init = options.copy()
        no_backend_init['backends'] = None
        backends.configure_backends(no_backend_init)

        backend_list = options['backends']
        for backend in backend_list.split(','):
            backend_module = utils.import_module(backend)
            settings = options[backend]
            backend_module.configure_backend(settings)

    def test_registration(self):
        self.assertIsNotNone(backends.api.CREDENTIALS)
        self.assertIsNotNone(backends.api.ENDPOINT_TEMPLATE)
        self.assertIsNotNone(backends.api.ROLE)
        self.assertIsNotNone(backends.api.SERVICE)
        self.assertIsNotNone(backends.api.TENANT)
        self.assertIsNotNone(backends.api.TOKEN)
        self.assertIsNotNone(backends.api.USER)

    def test_basic_tenant_create(self):
        tenant = models.Tenant(name="Tee One", description="This is T1",
                               enabled=True)

        original_tenant = tenant.copy()
        new_tenant = api.TENANT.create(tenant)
        self.assertIsInstance(new_tenant, models.Tenant)
        for k, v in original_tenant.items():
            if k not in ['id'] and k in new_tenant:
                self.assertEquals(new_tenant[k], v)
        self.assertEqual(original_tenant, tenant, "Backend modified provided \
tenant")

    def test_tenant_create_with_id(self):
        tenant = models.Tenant(id="T2", name="Tee Two", description="This is \
T2", enabled=True)

        original_tenant = tenant.copy()
        new_tenant = api.TENANT.create(tenant)
        self.assertIsInstance(new_tenant, models.Tenant)
        for k, v in original_tenant.items():
            if k in new_tenant:
                self.assertEquals(new_tenant[k], v)
        self.assertEqual(original_tenant, tenant, "Backend modified provided \
tenant")

    def test_tenant_update(self):
        tenant = models.Tenant(id="T3", name="Tee Three",
            description="This is T3", enabled=True)

        new_tenant = api.TENANT.create(tenant)

        new_tenant.enabled = False
        new_tenant.description = "This is UPDATED T3"

        api.TENANT.update("T3", new_tenant)

        updated_tenant = api.TENANT.get("T3")

        self.assertEqual(new_tenant, updated_tenant)


class LDAPBackendTestCase(BackendTestCase):
    def __init__(self, options=None):
        if options is None:
            options = {
            'backends': 'keystone.backends.sqlalchemy,keystone.backends.ldap',
            "keystone-service-admin-role": "KeystoneServiceAdmin",
            "keystone-admin-role": "KeystoneAdmin",
            "hash-password": "False",
            'keystone.backends.sqlalchemy': {
                "sql_connection": "sqlite:///",
                "backend_entities": "['Endpoints', 'Role',\
                                     'Credentials', 'EndpointTemplates',\
                                     'Token', 'Service']",
                "sql_idle_timeout": "30"
                },
            'keystone.backends.ldap': {
                'ldap_url': 'fake://memory',
                'ldap_user': 'cn=Admin',
                'ldap_password': 'password',
                'backend_entities': "['Tenant', 'User', 'UserRoleAssociation',\
                    'Role']"
                }
            }
        super(LDAPBackendTestCase, self).__init__(options)

if __name__ == '__main__':
    unittest.main()
