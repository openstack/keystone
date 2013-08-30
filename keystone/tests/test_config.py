# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.tests import core as test

from keystone import config
from keystone import exception


CONF = config.CONF


class ConfigTestCase(test.TestCase):
    def test_paste_config(self):
        self.assertEqual(config.find_paste_config(),
                         test.etcdir('keystone-paste.ini'))
        self.opt_in_group('paste_deploy', config_file='XYZ')
        self.assertRaises(exception.PasteConfigNotFound,
                          config.find_paste_config)
        self.opt_in_group('paste_deploy', config_file='')
        self.assertEqual(config.find_paste_config(),
                         test.etcdir('keystone.conf.sample'))

    def test_config_default(self):
        self.assertEqual('keystone.auth.plugins.password.Password',
                         CONF.auth.password)
        self.assertEqual('keystone.auth.plugins.token.Token',
                         CONF.auth.token)
