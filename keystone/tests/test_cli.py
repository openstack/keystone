# Copyright 2014 IBM Corp.
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

from keystone import cli
from keystone import tests
from keystone.tests.ksfixtures import database


class CliTestCase(tests.SQLDriverOverrides, tests.TestCase):
    def config_files(self):
        config_files = super(CliTestCase, self).config_files()
        config_files.append(tests.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def test_token_flush(self):
        self.useFixture(database.Database())
        self.load_backends()
        cli.TokenFlush.main()
