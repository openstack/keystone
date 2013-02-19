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

from keystone import catalog
from keystone.catalog.backends import kvs as catalog_kvs
from keystone import exception
from keystone.identity.backends import kvs as identity_kvs
from keystone import test
from keystone.token.backends import kvs as token_kvs

import default_fixtures
import test_backend


class KvsIdentity(test.TestCase, test_backend.IdentityTests):
    def setUp(self):
        super(KvsIdentity, self).setUp()
        self.identity_api = identity_kvs.Identity(db={})
        self.load_fixtures(default_fixtures)

    def test_list_user_projects(self):
        # NOTE(chungg): not implemented
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_create_duplicate_group_name_in_different_domains(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_create_duplicate_user_name_in_different_domains(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_create_duplicate_project_name_in_different_domains(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_move_user_between_domains(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_move_user_between_domains_with_clashing_names_fails(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_move_group_between_domains(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_move_group_between_domains_with_clashing_names_fails(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_move_project_between_domains(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')

    def test_move_project_between_domains_with_clashing_names_fails(self):
        raise nose.exc.SkipTest('Blocked by bug 1119770')


class KvsToken(test.TestCase, test_backend.TokenTests):
    def setUp(self):
        super(KvsToken, self).setUp()
        self.token_api = token_kvs.Token(db={})


class KvsCatalog(test.TestCase, test_backend.CatalogTests):
    def setUp(self):
        super(KvsCatalog, self).setUp()
        self.catalog_api = catalog_kvs.Catalog(db={})
        self.catalog_man = catalog.Manager()
        self.load_fixtures(default_fixtures)
        self._load_fake_catalog()

    def _load_fake_catalog(self):
        self.catalog_foobar = self.catalog_api._create_catalog(
            'foo', 'bar',
            {'RegionFoo': {'service_bar': {'foo': 'bar'}}})

    def test_get_catalog_404(self):
        # FIXME(dolph): this test should be moved up to test_backend
        # FIXME(dolph): exceptions should be UserNotFound and ProjectNotFound
        self.assertRaises(exception.NotFound,
                          self.catalog_api.get_catalog,
                          uuid.uuid4().hex,
                          'bar')

        self.assertRaises(exception.NotFound,
                          self.catalog_api.get_catalog,
                          'foo',
                          uuid.uuid4().hex)

    def test_get_catalog(self):
        catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
        self.assertDictEqual(catalog_ref, self.catalog_foobar)
