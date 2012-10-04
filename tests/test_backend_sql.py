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
from keystone.catalog.backends import sql as catalog_sql
from keystone.common.sql import util as sql_util
from keystone import config
from keystone import exception
from keystone.identity.backends import sql as identity_sql
from keystone import test
from keystone.token.backends import sql as token_sql

import default_fixtures
import test_backend


CONF = config.CONF


class SqlIdentity(test.TestCase, test_backend.IdentityTests):
    def setUp(self):
        super(SqlIdentity, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
        self.identity_api = identity_sql.Identity()
        self.load_fixtures(default_fixtures)

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


class SqlToken(test.TestCase, test_backend.TokenTests):
    def setUp(self):
        super(SqlToken, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
        self.token_api = token_sql.Token()


class SqlCatalog(test.TestCase, test_backend.CatalogTests):
    def setUp(self):
        super(SqlCatalog, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
        self.catalog_api = catalog_sql.Catalog()
        self.catalog_man = catalog.Manager()
        self.load_fixtures(default_fixtures)

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
