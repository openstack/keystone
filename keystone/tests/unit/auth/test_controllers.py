# Copyright 2015 IBM Corp.

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

from unittest import mock
import uuid

import fixtures
from oslo_config import cfg
from oslo_config import fixture as config_fixture
import stevedore
from stevedore import extension

from keystone.auth import core
from keystone.tests import unit


class TestLoadAuthMethod(unit.BaseTestCase):
    def test_entrypoint_works(self):
        method = uuid.uuid4().hex
        plugin_name = self.getUniqueString()

        # Register the method using the given plugin
        cf = self.useFixture(config_fixture.Config())
        cf.register_opt(cfg.StrOpt(method), group='auth')
        cf.config(group='auth', **{method: plugin_name})

        # Setup stevedore.DriverManager to return a driver for the plugin
        extension_ = extension.Extension(
            plugin_name, entry_point=mock.sentinel.entry_point,
            plugin=mock.sentinel.plugin,
            obj=mock.sentinel.driver)
        auth_plugin_namespace = 'keystone.auth.%s' % method
        fake_driver_manager = stevedore.DriverManager.make_test_instance(
            extension_, namespace=auth_plugin_namespace)

        driver_manager_mock = self.useFixture(fixtures.MockPatchObject(
            stevedore, 'DriverManager', return_value=fake_driver_manager)).mock

        driver = core.load_auth_method(method)

        self.assertEqual(auth_plugin_namespace, fake_driver_manager.namespace)
        driver_manager_mock.assert_called_once_with(
            auth_plugin_namespace, plugin_name, invoke_on_load=True)
        self.assertIs(mock.sentinel.driver, driver)

    def test_entrypoint_fails(self):
        method = uuid.uuid4().hex
        plugin_name = self.getUniqueString()

        # Register the method using the given plugin
        cf = self.useFixture(config_fixture.Config())
        cf.register_opt(cfg.StrOpt(method), group='auth')
        cf.config(group='auth', **{method: plugin_name})

        # stevedore.DriverManager raises RuntimeError if it can't load the
        # driver.
        self.useFixture(fixtures.MockPatchObject(
            stevedore, 'DriverManager', side_effect=RuntimeError))

        self.assertRaises(RuntimeError, core.load_auth_method, method)
