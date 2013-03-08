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

from keystone import catalog
from keystone.common import sql
from keystone import config
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import test
from keystone import token
from keystone import trust


import default_fixtures
import test_backend

CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class SqlTests(test.TestCase):
    def setUp(self):
        super(SqlTests, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_sql.conf')])

        # initialize managers and override drivers
        self.catalog_man = catalog.Manager()
        self.identity_man = identity.Manager()
        self.token_man = token.Manager()
        self.trust_man = trust.Manager()
        self.policy_man = policy.Manager()

        # create shortcut references to each driver
        self.catalog_api = self.catalog_man.driver
        self.identity_api = self.identity_man.driver
        self.token_api = self.token_man.driver
        self.policy_api = self.policy_man.driver
        self.trust_api = self.trust_man.driver

        # populate the engine with tables & fixtures
        self.load_fixtures(default_fixtures)
        #defaulted by the data load
        self.user_foo['enabled'] = True

    def tearDown(self):
        sql.set_global_engine(None)
        super(SqlTests, self).tearDown()


class SqlIdentity(SqlTests, test_backend.IdentityTests):
    def test_delete_user_with_project_association(self):
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        self.identity_man.create_user({}, user['id'], user)
        self.identity_api.add_user_to_project(self.tenant_bar['id'],
                                              user['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_projects_for_user,
                          user['id'])

    def test_create_null_user_name(self):
        user = {'id': uuid.uuid4().hex,
                'name': None,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_user, {},
                          user['id'],
                          user)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          user['name'],
                          DEFAULT_DOMAIN_ID)

    def test_create_null_project_name(self):
        tenant = {'id': uuid.uuid4().hex,
                  'name': None,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_project, {},
                          tenant['id'],
                          tenant)
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_project,
                          tenant['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_project_by_name,
                          tenant['name'],
                          DEFAULT_DOMAIN_ID)

    def test_create_null_role_name(self):
        role = {'id': uuid.uuid4().hex,
                'name': None}
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_role,
                          role['id'],
                          role)
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.get_role,
                          role['id'])

    def test_delete_project_with_user_association(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'passwd'}
        self.identity_man.create_user({}, 'fake', user)
        self.identity_api.add_user_to_project(self.tenant_bar['id'],
                                              user['id'])
        self.identity_api.delete_project(self.tenant_bar['id'])
        tenants = self.identity_api.get_projects_for_user(user['id'])
        self.assertEquals(tenants, [])

    def test_delete_user_with_metadata(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'passwd'}
        self.identity_man.create_user({}, 'fake', user)
        self.identity_api.create_metadata(user['id'],
                                          self.tenant_bar['id'],
                                          {'extra': 'extra'})
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.MetadataNotFound,
                          self.identity_api.get_metadata,
                          user['id'],
                          self.tenant_bar['id'])

    def test_delete_project_with_metadata(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'passwd'}
        self.identity_man.create_user({}, 'fake', user)
        self.identity_api.create_metadata(user['id'],
                                          self.tenant_bar['id'],
                                          {'extra': 'extra'})
        self.identity_api.delete_project(self.tenant_bar['id'])
        self.assertRaises(exception.MetadataNotFound,
                          self.identity_api.get_metadata,
                          user['id'],
                          self.tenant_bar['id'])

    def test_update_project_returns_extra(self):
        """This tests for backwards-compatibility with an essex/folsom bug.

        Non-indexed attributes were returned in an 'extra' attribute, instead
        of on the entity itself; for consistency and backwards compatibility,
        those attributes should be included twice.

        This behavior is specific to the SQL driver.

        """
        tenant_id = uuid.uuid4().hex
        arbitrary_key = uuid.uuid4().hex
        arbitrary_value = uuid.uuid4().hex
        tenant = {
            'id': tenant_id,
            'name': uuid.uuid4().hex,
            'domain_id': DEFAULT_DOMAIN_ID,
            arbitrary_key: arbitrary_value}
        ref = self.identity_man.create_project({}, tenant_id, tenant)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertIsNone(ref.get('extra'))

        tenant['name'] = uuid.uuid4().hex
        ref = self.identity_api.update_project(tenant_id, tenant)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertEqual(arbitrary_value, ref['extra'][arbitrary_key])

    def test_update_user_returns_extra(self):
        """This tests for backwards-compatibility with an essex/folsom bug.

        Non-indexed attributes were returned in an 'extra' attribute, instead
        of on the entity itself; for consistency and backwards compatibility,
        those attributes should be included twice.

        This behavior is specific to the SQL driver.

        """
        user_id = uuid.uuid4().hex
        arbitrary_key = uuid.uuid4().hex
        arbitrary_value = uuid.uuid4().hex
        user = {
            'id': user_id,
            'name': uuid.uuid4().hex,
            'domain_id': DEFAULT_DOMAIN_ID,
            'password': uuid.uuid4().hex,
            arbitrary_key: arbitrary_value}
        ref = self.identity_man.create_user({}, user_id, user)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertIsNone(ref.get('password'))
        self.assertIsNone(ref.get('extra'))

        user['name'] = uuid.uuid4().hex
        user['password'] = uuid.uuid4().hex
        ref = self.identity_api.update_user(user_id, user)
        self.assertIsNone(ref.get('password'))
        self.assertIsNone(ref['extra'].get('password'))
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertEqual(arbitrary_value, ref['extra'][arbitrary_key])


class SqlTrust(SqlTests, test_backend.TrustTests):
    pass


class SqlToken(SqlTests, test_backend.TokenTests):
    pass


class SqlCatalog(SqlTests, test_backend.CatalogTests):
    def test_malformed_catalog_throws_error(self):
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service.copy())

        malformed_url = "http://192.168.1.104:$(compute_port)s/v2/$(tenant)s"
        endpoint = {
            'id': uuid.uuid4().hex,
            'region': uuid.uuid4().hex,
            'service_id': service['id'],
            'interface': 'public',
            'url': malformed_url,
        }
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

        with self.assertRaises(exception.MalformedEndpoint):
            self.catalog_api.get_catalog('fake-user', 'fake-tenant')

    def test_get_catalog_with_empty_public_url(self):
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service.copy())

        endpoint = {
            'id': uuid.uuid4().hex,
            'region': uuid.uuid4().hex,
            'interface': 'public',
            'url': '',
            'service_id': service['id'],
        }
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

        catalog = self.catalog_api.get_catalog('user', 'tenant')
        catalog_endpoint = catalog[endpoint['region']][service['type']]
        self.assertEqual(catalog_endpoint['name'], service['name'])
        self.assertEqual(catalog_endpoint['id'], endpoint['id'])
        self.assertEqual(catalog_endpoint['publicURL'], '')
        self.assertIsNone(catalog_endpoint.get('adminURL'))
        self.assertIsNone(catalog_endpoint.get('internalURL'))

    def test_create_endpoint_400(self):
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service.copy())

        endpoint = {
            'id': uuid.uuid4().hex,
            'region': "0" * 256,
            'service_id': service['id'],
            'interface': 'public',
            'url': uuid.uuid4().hex,
        }

        with self.assertRaises(exception.StringLengthExceeded):
            self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())


class SqlPolicy(SqlTests, test_backend.PolicyTests):
    pass
