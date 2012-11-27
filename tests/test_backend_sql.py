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

from keystone.common import sql
from keystone import catalog
from keystone import config
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import test
from keystone import token

import default_fixtures
import test_backend


CONF = config.CONF


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
        self.policy_man = policy.Manager()

        # create shortcut references to each driver
        self.catalog_api = self.catalog_man.driver
        self.identity_api = self.identity_man.driver
        self.token_api = self.token_man.driver
        self.policy_api = self.policy_man.driver

        # populate the engine with tables & fixtures
        self.load_fixtures(default_fixtures)
        #defaulted by the data load
        self.user_foo['enabled'] = True

    def tearDown(self):
        sql.set_global_engine(None)
        super(SqlTests, self).tearDown()


class SqlIdentity(SqlTests, test_backend.IdentityTests):
    def test_delete_user_with_tenant_association(self):
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex}
        self.identity_api.create_user(user['id'], user)
        self.identity_api.add_user_to_tenant(self.tenant_bar['id'],
                                             user['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_tenants_for_user,
                          user['id'])

    def test_create_null_user_name(self):
        user = {'id': uuid.uuid4().hex,
                'name': None,
                'password': uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user['id'],
                          user)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          user['name'])

    def test_create_null_tenant_name(self):
        tenant = {'id': uuid.uuid4().hex,
                  'name': None}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_tenant,
                          tenant['id'],
                          tenant)
        self.assertRaises(exception.TenantNotFound,
                          self.identity_api.get_tenant,
                          tenant['id'])
        self.assertRaises(exception.TenantNotFound,
                          self.identity_api.get_tenant_by_name,
                          tenant['name'])

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

    def test_delete_tenant_with_user_association(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'password': 'passwd'}
        self.identity_api.create_user('fake', user)
        self.identity_api.add_user_to_tenant(self.tenant_bar['id'],
                                             user['id'])
        self.identity_api.delete_tenant(self.tenant_bar['id'])
        tenants = self.identity_api.get_tenants_for_user(user['id'])
        self.assertEquals(tenants, [])

    def test_delete_user_with_metadata(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'password': 'passwd'}
        self.identity_api.create_user('fake', user)
        self.identity_api.create_metadata(user['id'],
                                          self.tenant_bar['id'],
                                          {'extra': 'extra'})
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.MetadataNotFound,
                          self.identity_api.get_metadata,
                          user['id'],
                          self.tenant_bar['id'])

    def test_delete_tenant_with_metadata(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'password': 'passwd'}
        self.identity_api.create_user('fake', user)
        self.identity_api.create_metadata(user['id'],
                                          self.tenant_bar['id'],
                                          {'extra': 'extra'})
        self.identity_api.delete_tenant(self.tenant_bar['id'])
        self.assertRaises(exception.MetadataNotFound,
                          self.identity_api.get_metadata,
                          user['id'],
                          self.tenant_bar['id'])

    def test_update_tenant_returns_extra(self):
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
            arbitrary_key: arbitrary_value}
        ref = self.identity_api.create_tenant(tenant_id, tenant)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertIsNone(ref.get('extra'))

        tenant['name'] = uuid.uuid4().hex
        ref = self.identity_api.update_tenant(tenant_id, tenant)
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
            'password': uuid.uuid4().hex,
            arbitrary_key: arbitrary_value}
        ref = self.identity_api.create_user(user_id, user)
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


class SqlToken(SqlTests, test_backend.TokenTests):
    pass


class SqlCatalog(SqlTests, test_backend.CatalogTests):
    def test_malformed_catalog_throws_error(self):
        self.catalog_api.create_service('a', {"id": "a", "desc": "a1",
                                        "name": "b"})
        badurl = "http://192.168.1.104:$(compute_port)s/v2/$(tenant)s"
        self.catalog_api.create_endpoint('b', {"id": "b", "region": "b1",
                                         "service_id": "a", "adminurl": badurl,
                                         "internalurl": badurl,
                                         "publicurl": badurl})
        with self.assertRaises(exception.MalformedEndpoint):
            self.catalog_api.get_catalog('fake-user', 'fake-tenant')

    def test_get_catalog_without_endpoint(self):
        new_service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(
            new_service['id'],
            new_service.copy())
        service_id = new_service['id']

        new_endpoint = {
            'id': uuid.uuid4().hex,
            'region': uuid.uuid4().hex,
            'service_id': service_id,
        }

        self.catalog_api.create_endpoint(
            new_endpoint['id'],
            new_endpoint.copy())

        catalog = self.catalog_api.get_catalog('user', 'tenant')

        service_type = new_service['type']
        region = new_endpoint['region']

        self.assertEqual(catalog[region][service_type]['name'],
                         new_service['name'])
        self.assertEqual(catalog[region][service_type]['id'],
                         new_endpoint['id'])
        self.assertEqual(catalog[region][service_type]['publicURL'],
                         "")
        self.assertEqual(catalog[region][service_type]['adminURL'],
                         None)
        self.assertEqual(catalog[region][service_type]['internalURL'],
                         None)

    def test_delete_service_with_endpoints(self):
        self.catalog_api.create_service('c', {"id": "c", "desc": "a1",
                                        "name": "d"})
        self.catalog_api.create_endpoint('d', {"id": "d", "region": None,
                                         "service_id": "c", "adminurl": None,
                                         "internalurl": None,
                                         "publicurl": None})
        self.catalog_api.delete_service("c")
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_man.delete_service, {}, "c")
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_man.delete_endpoint, {}, "d")


class SqlPolicy(SqlTests, test_backend.PolicyTests):
    pass
