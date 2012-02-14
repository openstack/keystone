# vim: tabstop=4 shiftwidth=4 softtabstop=4

import os

import sqlite3
#import sqlalchemy

from keystone import config
from keystone import test
from keystone.common.sql import legacy
from keystone.common.sql import util as sql_util
from keystone.identity.backends import sql as identity_sql
from keystone.token.backends import sql as token_sql



CONF = config.CONF


class ImportLegacy(test.TestCase):
  def setUp(self):
    super(ImportLegacy, self).setUp()
    CONF(config_files=[test.etcdir('keystone.conf'),
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

    user_ref = self.identity_api.get_user('1')
    self.assertEquals(user_ref['name'], 'admin')

  def test_import_diablo(self):
    db_path = self.setup_old_database('legacy_diablo.sqlite')
    migration = legacy.LegacyMigration('sqlite:///%s' % db_path)
    migration.migrate_all()

    user_ref = self.identity_api.get_user('1')
    self.assertEquals(user_ref['name'], 'admin')

  def test_import_essex(self):
    db_path = self.setup_old_database('legacy_essex.sqlite')
    migration = legacy.LegacyMigration('sqlite:///%s' % db_path)
    migration.migrate_all()

    user_ref = self.identity_api.get_user('c93b19ea3fa94484824213db8ac0afce')
    self.assertEquals(user_ref['name'], 'admin')
