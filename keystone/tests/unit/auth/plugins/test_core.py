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

from keystone.auth import plugins
from keystone.tests import unit


class TestPluginCore(unit.TestCase):

    def test_construct_method_map_with_one_methods(self):
        auth_methods = ['password']
        self.config_fixture.config(group='auth', methods=auth_methods)

        expected_method_map = {1: 'password'}
        method_map = plugins.construct_method_map_from_config()
        self.assertDictEqual(expected_method_map, method_map)

    def test_construct_method_map_with_two_methods(self):
        auth_methods = ['password', 'token']
        self.config_fixture.config(group='auth', methods=auth_methods)

        expected_method_map = {1: 'password', 2: 'token'}
        method_map = plugins.construct_method_map_from_config()
        self.assertDictEqual(expected_method_map, method_map)

    def test_construct_method_map_with_three_methods(self):
        auth_methods = ['password', 'token', 'totp']
        self.config_fixture.config(group='auth', methods=auth_methods)

        expected_method_map = {1: 'password', 2: 'token', 4: 'totp'}
        method_map = plugins.construct_method_map_from_config()
        self.assertDictEqual(expected_method_map, method_map)

    def test_convert_methods_to_integer(self):
        auth_methods = ['password', 'token', 'totp']
        self.config_fixture.config(group='auth', methods=auth_methods)

        method_integer = plugins.convert_method_list_to_integer(['password'])
        self.assertEqual(1, method_integer)

        method_integer = plugins.convert_method_list_to_integer(
            ['password', 'token']
        )
        self.assertEqual(3, method_integer)

        method_integer = plugins.convert_method_list_to_integer(
            ['password', 'totp']
        )
        self.assertEqual(5, method_integer)

        method_integer = plugins.convert_method_list_to_integer(
            ['token', 'totp']
        )
        self.assertEqual(6, method_integer)

        method_integer = plugins.convert_method_list_to_integer(
            ['password', 'token', 'totp']
        )
        self.assertEqual(7, method_integer)

    def test_convert_integer_to_methods(self):
        auth_methods = ['password', 'token', 'totp']
        self.config_fixture.config(group='auth', methods=auth_methods)

        expected_methods = ['password']
        methods = plugins.convert_integer_to_method_list(1)
        self.assertTrue(len(methods) == 1)
        for method in methods:
            self.assertIn(method, expected_methods)

        expected_methods = ['password', 'token']
        methods = plugins.convert_integer_to_method_list(3)
        self.assertTrue(len(methods) == 2)
        for method in methods:
            self.assertIn(method, expected_methods)

        expected_methods = ['password', 'totp']
        methods = plugins.convert_integer_to_method_list(5)
        self.assertTrue(len(methods) == 2)
        for method in methods:
            self.assertIn(method, expected_methods)

        expected_methods = ['token', 'totp']
        methods = plugins.convert_integer_to_method_list(6)
        self.assertTrue(len(methods) == 2)
        for method in methods:
            self.assertIn(method, expected_methods)

        expected_methods = ['password', 'token', 'totp']
        methods = plugins.convert_integer_to_method_list(7)
        self.assertTrue(len(methods) == 3)
        for method in methods:
            self.assertIn(method, expected_methods)
