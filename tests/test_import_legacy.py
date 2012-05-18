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

import os

import sqlite3
#import sqlalchemy

from keystone import config
from keystone import test
from keystone.common.sql import legacy
from keystone.common.sql import util as sql_util
from keystone.identity.backends import sql as identity_sql
from keystone.catalog.backends import templated as catalog_templated


CONF = config.CONF


class ImportLegacy(test.TestCase):
    def setUp(self):
        super(ImportLegacy, self).setUp()
        CONF(config_files=[test.etcdir('keystone.conf.sample'),
                           test.testsdir('test_overrides.conf'),
                           test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
        self.identity_api = identity_sql.Identity()

    def setup_old_database(self, sql_dump):
        sql_path = test.testsdir(sql_dump)
        db_path = test.testsdir('%s.db' % sql_dump)
        try:
            os.unlink(db_path)
        except OSError:
            pass
        script_str = open(sql_path).read().strip()
        conn = sqlite3.connect(db_path)
        conn.executescript(script_str)
        conn.commit()
        return db_path

    def test_import_d5(self):
        db_path = self.setup_old_database('legacy_d5.sqlite')
        migration = legacy.LegacyMigration('sqlite:///%s' % db_path)
        migration.migrate_all()

        admin_id = '1'
        user_ref = self.identity_api.get_user(admin_id)
        self.assertEquals(user_ref['name'], 'admin')
        self.assertEquals(user_ref['enabled'], True)

        # check password hashing
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
            user_id=admin_id, password='secrete')

        # check catalog
        self._check_catalog(migration)

    def test_import_diablo(self):
        db_path = self.setup_old_database('legacy_diablo.sqlite')
        migration = legacy.LegacyMigration('sqlite:///%s' % db_path)
        migration.migrate_all()

        admin_id = '1'
        user_ref = self.identity_api.get_user(admin_id)
        self.assertEquals(user_ref['name'], 'admin')
        self.assertEquals(user_ref['enabled'], True)

        # check password hashing
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
            user_id=admin_id, password='secrete')

        # check catalog
        self._check_catalog(migration)

    def test_import_essex(self):
        db_path = self.setup_old_database('legacy_essex.sqlite')
        migration = legacy.LegacyMigration('sqlite:///%s' % db_path)
        migration.migrate_all()

        admin_id = 'c93b19ea3fa94484824213db8ac0afce'
        user_ref = self.identity_api.get_user(admin_id)
        self.assertEquals(user_ref['name'], 'admin')
        self.assertEquals(user_ref['enabled'], True)

        # check password hashing
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
            user_id=admin_id, password='secrete')

        # check catalog
        self._check_catalog(migration)

    def _check_catalog(self, migration):
        catalog_lines = migration.dump_catalog()
        catalog = catalog_templated.parse_templates(catalog_lines)
        self.assert_('RegionOne' in catalog)
        self.assert_('compute' in catalog['RegionOne'])
        self.assert_('adminURL' in catalog['RegionOne']['compute'])
