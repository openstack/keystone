# vim: tabstop=4 shiftwidth=4 softtabstop=4
from keystonelight import config
from keystonelight import test
from keystonelight.backends.sql import util as sql_util
from keystonelight.backends.sql import migration

import test_keystoneclient


CONF = config.CONF


class KcMasterSqlTestCase(test_keystoneclient.KcMasterTestCase):
    def _config(self):
        CONF(config_files=['default.conf', 'backend_sql.conf'])
        sql_util.setup_test_database()
