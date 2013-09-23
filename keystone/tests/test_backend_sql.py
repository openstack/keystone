# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import uuid

import sqlalchemy

from keystone.common import sql
from keystone import config
from keystone import exception
from keystone.identity.backends import sql as identity_sql
from keystone import tests
from keystone.tests import default_fixtures
from keystone.tests import test_backend


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class SqlTests(tests.TestCase, sql.Base):

    def setUp(self):
        super(SqlTests, self).setUp()
        self.config([tests.etcdir('keystone.conf.sample'),
                     tests.testsdir('test_overrides.conf'),
                     tests.testsdir('backend_sql.conf')])

        self.load_backends()

        # create tables and keep an engine reference for cleanup.
        # this must be done after the models are loaded by the managers.
        self.engine = self.get_engine()
        sql.ModelBase.metadata.create_all(bind=self.engine)

        # populate the engine with tables & fixtures
        self.load_fixtures(default_fixtures)
        #defaulted by the data load
        self.user_foo['enabled'] = True

    def tearDown(self):
        sql.ModelBase.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        sql.set_global_engine(None)
        super(SqlTests, self).tearDown()


class SqlModels(SqlTests):
    def setUp(self):
        super(SqlModels, self).setUp()

        self.metadata = sql.ModelBase.metadata
        self.metadata.bind = self.engine

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 self.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def assertExpectedSchema(self, table, cols):
        table = self.select_table(table)
        for col, type_, length in cols:
            self.assertIsInstance(table.c[col].type, type_)
            if length:
                self.assertEquals(table.c[col].type.length, length)

    def test_user_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 255),
                ('password', sql.String, 128),
                ('domain_id', sql.String, 64),
                ('enabled', sql.Boolean, None),
                ('extra', sql.JsonBlob, None))
        self.assertExpectedSchema('user', cols)

    def test_group_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 64),
                ('description', sql.Text, None),
                ('domain_id', sql.String, 64),
                ('extra', sql.JsonBlob, None))
        self.assertExpectedSchema('group', cols)

    def test_domain_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 64),
                ('enabled', sql.Boolean, None))
        self.assertExpectedSchema('domain', cols)

    def test_project_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 64),
                ('description', sql.Text, None),
                ('domain_id', sql.String, 64),
                ('enabled', sql.Boolean, None),
                ('extra', sql.JsonBlob, None))
        self.assertExpectedSchema('project', cols)

    def test_role_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 255))
        self.assertExpectedSchema('role', cols)

    def test_user_project_metadata_model(self):
        cols = (('user_id', sql.String, 64),
                ('project_id', sql.String, 64),
                ('data', sql.JsonBlob, None))
        self.assertExpectedSchema('user_project_metadata', cols)

    def test_user_domain_metadata_model(self):
        cols = (('user_id', sql.String, 64),
                ('domain_id', sql.String, 64),
                ('data', sql.JsonBlob, None))
        self.assertExpectedSchema('user_domain_metadata', cols)

    def test_group_project_metadata_model(self):
        cols = (('group_id', sql.String, 64),
                ('project_id', sql.String, 64),
                ('data', sql.JsonBlob, None))
        self.assertExpectedSchema('group_project_metadata', cols)

    def test_group_domain_metadata_model(self):
        cols = (('group_id', sql.String, 64),
                ('domain_id', sql.String, 64),
                ('data', sql.JsonBlob, None))
        self.assertExpectedSchema('group_domain_metadata', cols)

    def test_user_group_membership(self):
        cols = (('group_id', sql.String, 64),
                ('user_id', sql.String, 64))
        self.assertExpectedSchema('user_group_membership', cols)


class SqlIdentity(SqlTests, test_backend.IdentityTests):
    def test_password_hashed(self):
        session = self.identity_api.get_session()
        user_ref = self.identity_api._get_user(session, self.user_foo['id'])
        self.assertNotEqual(user_ref['password'], self.user_foo['password'])

    def test_delete_user_with_project_association(self):
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        self.identity_api.create_user(user['id'], user)
        self.identity_api.add_user_to_project(self.tenant_bar['id'],
                                              user['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          user['id'])

    def test_create_null_user_name(self):
        user = {'id': uuid.uuid4().hex,
                'name': None,
                'domain_id': DEFAULT_DOMAIN_ID,
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
                          user['name'],
                          DEFAULT_DOMAIN_ID)

    def test_create_null_project_name(self):
        tenant = {'id': uuid.uuid4().hex,
                  'name': None,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.assignment_api.create_project,
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
        self.identity_api.create_user('fake', user)
        self.identity_api.add_user_to_project(self.tenant_bar['id'],
                                              user['id'])
        self.assignment_api.delete_project(self.tenant_bar['id'])
        tenants = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEquals(tenants, [])

    def test_metadata_removed_on_delete_user(self):
        # A test to check that the internal representation
        # or roles is correctly updated when a user is deleted
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'passwd'}
        self.identity_api.create_user(user['id'], user)
        role = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex}
        self.identity_api.create_role(role['id'], role)
        self.identity_api.add_role_to_user_and_project(
            user['id'],
            self.tenant_bar['id'],
            role['id'])
        self.identity_api.delete_user(user['id'])

        # Now check whether the internal representation of roles
        # has been deleted
        self.assertRaises(exception.MetadataNotFound,
                          self.assignment_api._get_metadata,
                          user['id'],
                          self.tenant_bar['id'])

    def test_metadata_removed_on_delete_project(self):
        # A test to check that the internal representation
        # or roles is correctly updated when a project is deleted
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'passwd'}
        self.identity_api.create_user(user['id'], user)
        role = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex}
        self.identity_api.create_role(role['id'], role)
        self.identity_api.add_role_to_user_and_project(
            user['id'],
            self.tenant_bar['id'],
            role['id'])
        self.assignment_api.delete_project(self.tenant_bar['id'])

        # Now check whether the internal representation of roles
        # has been deleted
        self.assertRaises(exception.MetadataNotFound,
                          self.assignment_api._get_metadata,
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
        ref = self.assignment_api.create_project(tenant_id, tenant)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertIsNone(ref.get('extra'))

        tenant['name'] = uuid.uuid4().hex
        ref = self.assignment_api.update_project(tenant_id, tenant)
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

    def test_sql_user_to_dict_null_default_project_id(self):
        user_id = uuid.uuid4().hex
        user = {
            'id': user_id,
            'name': uuid.uuid4().hex,
            'domain_id': DEFAULT_DOMAIN_ID,
            'password': uuid.uuid4().hex}

        self.identity_api.create_user(user_id, user)
        session = self.get_session()
        query = session.query(identity_sql.User)
        query = query.filter_by(id=user_id)
        raw_user_ref = query.one()
        self.assertIsNone(raw_user_ref.default_project_id)
        user_ref = raw_user_ref.to_dict()
        self.assertNotIn('default_project_id', user_ref)
        session.close()


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

        self.assertRaises(exception.MalformedEndpoint,
                          self.catalog_api.get_catalog,
                          'fake-user',
                          'fake-tenant')

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

        self.assertRaises(exception.StringLengthExceeded,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint.copy())


class SqlPolicy(SqlTests, test_backend.PolicyTests):
    pass


class SqlInheritance(SqlTests, test_backend.InheritanceTests):
    pass


class SqlTokenCacheInvalidation(SqlTests, test_backend.TokenCacheInvalidation):
    def setUp(self):
        super(SqlTokenCacheInvalidation, self).setUp()
        self._create_test_data()
