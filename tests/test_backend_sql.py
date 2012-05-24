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

from keystone import config
from keystone import exception
from keystone import test
from keystone.common.sql import util as sql_util
from keystone.identity.backends import sql as identity_sql
from keystone.token.backends import sql as token_sql

import test_backend
import default_fixtures


CONF = config.CONF


class SqlIdentity(test.TestCase, test_backend.IdentityTests):
    def setUp(self):
        super(SqlIdentity, self).setUp()
        CONF(config_files=[test.etcdir('keystone.conf.sample'),
                           test.testsdir('test_overrides.conf'),
                           test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
        self.identity_api = identity_sql.Identity()
        self.load_fixtures(default_fixtures)

    def test_delete_user_with_tenant_association(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'password': 'passwd'}
        self.identity_api.create_user('fake', user)
        self.identity_api.add_user_to_tenant(self.tenant_bar['id'],
                                             user['id'])
        self.identity_api.delete_user(user['id'])
        tenants = self.identity_api.get_tenants_for_user(user['id'])
        self.assertEquals(tenants, [])

    def test_create_null_user_name(self):
        user = {'id': uuid.uuid4().hex,
                'name': None,
                'password': uuid.uuid4().hex}
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_user,
                          user['id'],
                          user)
        # TODO(dolph): can be uncommented pending bug 968519
        #self.assertRaises(exception.UserNotFound,
        #                  self.identity_api.get_user,
        #                  user['id'])
        #self.assertRaises(exception.UserNotFound,
        #                  self.identity_api.get_user_by_name,
        #                  user['name'])

    def test_create_null_tenant_name(self):
        tenant = {'id': uuid.uuid4().hex,
                  'name': None}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_tenant,
                          tenant['id'],
                          tenant)
        # TODO(dolph): can be uncommented pending bug 968519
        #self.assertRaises(exception.TenantNotFound,
        #                  self.identity_api.get_tenant,
        #                  tenant['id'])
        #self.assertRaises(exception.TenantNotFound,
        #                  self.identity_api.get_tenant_by_name,
        #                  tenant['name'])

    def test_create_null_role_name(self):
        role = {'id': uuid.uuid4().hex,
                'name': None}
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_role,
                          role['id'],
                          role)
        # TODO(dolph): can be uncommented pending bug 968519
        #self.assertRaises(exception.RoleNotFound,
        #                  self.identity_api.get_role,
        #                  role['id'])

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
        metadata = self.identity_api.get_metadata(user['id'],
                                                  self.tenant_bar['id'])
        self.assertEquals(metadata, {})

    def test_delete_tenant_with_metadata(self):
        user = {'id': 'fake',
                'name': 'fakeuser',
                'password': 'passwd'}
        self.identity_api.create_user('fake', user)
        self.identity_api.create_metadata(user['id'],
                                          self.tenant_bar['id'],
                                          {'extra': 'extra'})
        self.identity_api.delete_tenant(self.tenant_bar['id'])
        metadata = self.identity_api.get_metadata(user['id'],
                                                  self.tenant_bar['id'])
        self.assertEquals(metadata, {})


class SqlToken(test.TestCase, test_backend.TokenTests):
    def setUp(self):
        super(SqlToken, self).setUp()
        CONF(config_files=[test.etcdir('keystone.conf.sample'),
                           test.testsdir('test_overrides.conf'),
                           test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
        self.token_api = token_sql.Token()


#class SqlCatalog(test_backend_kvs.KvsCatalog):
#  def setUp(self):
#    super(SqlCatalog, self).setUp()
#    self.catalog_api = sql.SqlCatalog()
#    self._load_fixtures()

#  def _load_fixtures(self):
#    self.catalog_foobar = self.catalog_api._create_catalog(
#        'foo', 'bar',
#        {'RegionFoo': {'service_bar': {'foo': 'bar'}}})

#  def test_get_catalog_bad_user(self):
#    catalog_ref = self.catalog_api.get_catalog('foo' + 'WRONG', 'bar')
#    self.assert_(catalog_ref is None)

#  def test_get_catalog_bad_tenant(self):
#    catalog_ref = self.catalog_api.get_catalog('foo', 'bar' + 'WRONG')
#    self.assert_(catalog_ref is None)

#  def test_get_catalog(self):
#    catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
#    self.assertDictEqual(catalog_ref, self.catalog_foobar)
