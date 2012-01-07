import os

from keystonelight import config
from keystonelight.backends.sql import migration


CONF = config.CONF


def setup_test_database():
  # TODO(termie): be smart about this
  try:
    os.unlink('bla.db')
  except Exception:
    pass
  migration.db_sync()
