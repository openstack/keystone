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

import keystone.conf
from keystone import exception
from keystone.server import wsgi
from keystone.tests import unit


CONF = keystone.conf.CONF


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
                         wsgi.find_paste_config())
        self.config_fixture.config(group='paste_deploy',
                                   config_file=uuid.uuid4().hex)
        self.assertRaises(exception.ConfigFileNotFound,
                          wsgi.find_paste_config)
        self.config_fixture.config(group='paste_deploy', config_file='')
        self.assertEqual(unit.dirs.etc('keystone.conf.sample'),
                         wsgi.find_paste_config())

    def test_config_default(self):
        self.assertIsNone(CONF.auth.password)
        self.assertIsNone(CONF.auth.token)

    def test_profiler_config_default(self):
        """Check config.set_config_defaults() has set [profiler]enabled."""
        self.assertEqual(False, CONF.profiler.enabled)


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
