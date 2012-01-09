# vim: tabstop=4 shiftwidth=4 softtabstop=4
from keystone import config
from keystone import test
from keystone.backends.sql import util as sql_util
from keystone.backends.sql import migration

import test_keystoneclient


CONF = config.CONF


class KcMasterSqlTestCase(test_keystoneclient.KcMasterTestCase):
    def _config(self):
        CONF(config_files=[test.etcdir('keystone.conf'),
                           test.testsdir('test_overrides.conf'),
                           test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
