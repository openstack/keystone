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
import shutil

from keystone.common.sql import migration
from keystone import config


CONF = config.CONF


def setup_test_database():
    try:
        if os.path.exists('test.db'):
            os.unlink('test.db')
        if not os.path.exists('test.db.pristine'):
            migration.db_sync()
            shutil.copyfile('test.db', 'test.db.pristine')
        else:
            shutil.copyfile('test.db.pristine', 'test.db')
    except Exception:
        pass


def teardown_test_database():
    if os.path.exists('test.db.pristine'):
        os.unlink('test.db.pristine')
