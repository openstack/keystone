# vim: tabstop=4 shiftwidth=4 softtabstop=4

import os

from keystone import config
from keystone.common.sql import migration


CONF = config.CONF


def setup_test_database():
    # TODO(termie): be smart about this
    try:
        os.unlink('test.db')
    except Exception:
        pass
    migration.db_sync()
