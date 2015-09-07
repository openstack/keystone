# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools
import os

import fixtures
from oslo_config import cfg
from oslo_db import options as db_options

from keystone.common import sql
from keystone.tests import unit


CONF = cfg.CONF


def run_once(f):
    """A decorator to ensure the decorated function is only executed once.

    The decorated function cannot expect any arguments.
    """
    @functools.wraps(f)
    def wrapper():
        if not wrapper.already_ran:
            f()
            wrapper.already_ran = True
    wrapper.already_ran = False
    return wrapper


# NOTE(I159): Every execution all the options will be cleared. The method must
# be called at the every fixture initialization.
def initialize_sql_session():
    # Make sure the DB is located in the correct location, in this case set
    # the default value, as this should be able to be overridden in some
    # test cases.
    db_options.set_defaults(
        CONF,
        connection=unit.IN_MEM_DB_CONN_STRING)


@run_once
def _load_sqlalchemy_models():
    """Find all modules containing SQLAlchemy models and import them.

    This creates more consistent, deterministic test runs because tables
    for all core and extension models are always created in the test
    database. We ensure this by importing all modules that contain model
    definitions.

    The database schema during test runs is created using reflection.
    Reflection is simply SQLAlchemy taking the model definitions for
    all models currently imported and making tables for each of them.
    The database schema created during test runs may vary between tests
    as more models are imported. Importing all models at the start of
    the test run avoids this problem.

    """
    keystone_root = os.path.normpath(os.path.join(
        os.path.dirname(__file__), '..', '..', '..'))
    for root, dirs, files in os.walk(keystone_root):
        # NOTE(morganfainberg): Slice the keystone_root off the root to ensure
        # we do not end up with a module name like:
        # Users.home.openstack.keystone.assignment.backends.sql
        root = root[len(keystone_root):]
        if root.endswith('backends') and 'sql.py' in files:
            # The root will be prefixed with an instance of os.sep, which will
            # make the root after replacement '.<root>', the 'keystone' part
            # of the module path is always added to the front
            module_name = ('keystone.%s.sql' %
                           root.replace(os.sep, '.').lstrip('.'))
            __import__(module_name)


class Database(fixtures.Fixture):
    """A fixture for setting up and tearing down a database.

    """

    def __init__(self):
        super(Database, self).__init__()
        initialize_sql_session()
        _load_sqlalchemy_models()

    def setUp(self):
        super(Database, self).setUp()

        self.engine = sql.get_engine()
        self.addCleanup(sql.cleanup)
        sql.ModelBase.metadata.create_all(bind=self.engine)
        self.addCleanup(sql.ModelBase.metadata.drop_all, bind=self.engine)

    def recreate(self):
        sql.ModelBase.metadata.create_all(bind=self.engine)
