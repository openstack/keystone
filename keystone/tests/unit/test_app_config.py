# encoding: utf-8
#
# Copyright 2012 OpenStack Foundation
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

from keystone.server.flask import core as server_flask
from keystone.tests import unit


class AppConfigTest(unit.TestCase):
    default_config_file = 'keystone.conf'
    custom_config_dir = '/etc/kst/'
    custom_config_files = ['kst.conf', 'kst2.conf']

    def test_config_files_have_default_values_when_envars_not_set(self):
        config_files = server_flask._get_config_files()
        config_files.sort()
        expected_config_files = []
        self.assertListEqual(config_files, expected_config_files)

    def test_config_files_have_default_values_with_empty_envars(self):
        env = {'OS_KEYSTONE_CONFIG_FILES': '',
               'OS_KEYSTONE_CONFIG_DIR': ''}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = []
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_single_config_file_under_default_config_dir(self):
        cfg = self.custom_config_files[0]
        env = {'OS_KEYSTONE_CONFIG_FILES': cfg}
        config_files = server_flask._get_config_files(env)
        expected_config_files = [cfg]
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_multiple_config_files_under_default_config_dir(self):
        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(self.custom_config_files)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = self.custom_config_files
        self.assertListEqual(config_files, expected_config_files)

        config_with_empty_strings = self.custom_config_files + ['', ' ']
        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(config_with_empty_strings)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_single_absolute_path_config_file(self):
        cfg = self.custom_config_files[0]
        cfgpath = os.path.join(self.custom_config_dir, cfg)
        env = {'OS_KEYSTONE_CONFIG_FILES': cfgpath}
        config_files = server_flask._get_config_files(env)
        self.assertListEqual(config_files, [cfgpath])

    def test_can_use_multiple_absolute_path_config_files(self):
        cfgpaths = [os.path.join(self.custom_config_dir, cfg)
                    for cfg in self.custom_config_files]
        cfgpaths.sort()
        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(cfgpaths)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, cfgpaths)

        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(cfgpaths + ['', ' '])}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, cfgpaths)

    def test_can_use_default_config_files_with_custom_config_dir(self):
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [os.path.join(self.custom_config_dir,
                                              self.default_config_file)]
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_single_config_file_under_custom_config_dir(self):
        cfg = self.custom_config_files[0]
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': cfg}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [os.path.join(self.custom_config_dir, cfg)]
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_multiple_config_files_under_custom_config_dir(self):
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': ';'.join(self.custom_config_files)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [os.path.join(self.custom_config_dir, s)
                                 for s in self.custom_config_files]
        expected_config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

        config_with_empty_strings = self.custom_config_files + ['', ' ']
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': ';'.join(config_with_empty_strings)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

    def test_can_mix_relative_and_absolute_paths_config_file(self):
        cfg0 = self.custom_config_files[0]
        cfgpath0 = os.path.join(self.custom_config_dir,
                                self.custom_config_files[0])
        cfgpath1 = os.path.join(self.custom_config_dir,
                                self.custom_config_files[1])
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': ';'.join([cfg0, cfgpath1])}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [cfgpath0, cfgpath1]
        expected_config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join([cfg0, cfgpath1])}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [cfg0, cfgpath1]
        expected_config_files.sort()
        self.assertListEqual(config_files, expected_config_files)
