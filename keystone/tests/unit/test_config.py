# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid

from oslo_config import cfg

from keystone import config
from keystone import exception
from keystone.tests import unit


CONF = cfg.CONF


class ConfigTestCase(unit.TestCase):

    def config_files(self):
        config_files = super(ConfigTestCase, self).config_files()
        # Insert the keystone sample as the first config file to be loaded
        # since it is used in one of the code paths to determine the paste-ini
        # location.
        config_files.insert(0, unit.dirs.etc('keystone.conf.sample'))
        return config_files

    def test_paste_config(self):
        self.assertEqual(unit.dirs.etc('keystone-paste.ini'),
                         config.find_paste_config())
        self.config_fixture.config(group='paste_deploy',
                                   config_file=uuid.uuid4().hex)
        self.assertRaises(exception.ConfigFileNotFound,
                          config.find_paste_config)
        self.config_fixture.config(group='paste_deploy', config_file='')
        self.assertEqual(unit.dirs.etc('keystone.conf.sample'),
                         config.find_paste_config())

    def test_config_default(self):
        self.assertIs(None, CONF.auth.password)
        self.assertIs(None, CONF.auth.token)


class DeprecatedTestCase(unit.TestCase):
    """Test using the original (deprecated) name for renamed options."""

    def config_files(self):
        config_files = super(DeprecatedTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('deprecated.conf'))
        return config_files

    def test_sql(self):
        # Options in [sql] were moved to [database] in Icehouse for the change
        # to use oslo-incubator's db.sqlalchemy.sessions.

        self.assertEqual('sqlite://deprecated', CONF.database.connection)
        self.assertEqual(54321, CONF.database.idle_timeout)


class DeprecatedOverrideTestCase(unit.TestCase):
    """Test using the deprecated AND new name for renamed options."""

    def config_files(self):
        config_files = super(DeprecatedOverrideTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('deprecated_override.conf'))
        return config_files

    def test_sql(self):
        # Options in [sql] were moved to [database] in Icehouse for the change
        # to use oslo-incubator's db.sqlalchemy.sessions.

        self.assertEqual('sqlite://new', CONF.database.connection)
        self.assertEqual(65432, CONF.database.idle_timeout)
