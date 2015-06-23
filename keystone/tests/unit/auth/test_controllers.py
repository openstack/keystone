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

import uuid

import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_utils import importutils
from oslotest import mockpatch

from keystone.auth import controllers
from keystone.tests import unit


class TestLoadAuthMethod(unit.BaseTestCase):
    def test_import_works(self):
        method = uuid.uuid4().hex
        plugin_name = self.getUniqueString()

        # Register the method using the given plugin
        cf = self.useFixture(config_fixture.Config())
        cf.register_opt(cfg.StrOpt(method), group='auth')
        cf.config(group='auth', **{method: plugin_name})

        self.useFixture(mockpatch.PatchObject(
            importutils, 'import_object', return_value=mock.sentinel.driver))

        driver = controllers.load_auth_method(method)
        self.assertIs(driver, mock.sentinel.driver)

    def test_import_fails(self):
        method = uuid.uuid4().hex
        plugin_name = self.getUniqueString()

        # Register the method using the given plugin
        cf = self.useFixture(config_fixture.Config())
        cf.register_opt(cfg.StrOpt(method), group='auth')
        cf.config(group='auth', **{method: plugin_name})

        class TestException(Exception):
            pass

        self.useFixture(mockpatch.PatchObject(
            importutils, 'import_object', side_effect=TestException))

        self.assertRaises(TestException, controllers.load_auth_method, method)
