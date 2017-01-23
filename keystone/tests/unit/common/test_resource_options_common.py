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

from keystone.common import resource_options
from keystone.tests import unit


class TestResourceOptionObjects(unit.BaseTestCase):
    def test_option_init_validation(self):
        # option_name must be a string
        self.assertRaises(TypeError,
                          resource_options.ResourceOption, 'test', 1234)
        # option_id must be a string
        self.assertRaises(TypeError,
                          resource_options.ResourceOption, 1234, 'testing')
        # option_id must be 4 characters
        self.assertRaises(ValueError,
                          resource_options.ResourceOption,
                          'testing',
                          'testing')
        resource_options.ResourceOption('test', 'testing')

    def test_duplicate_option_cases(self):
        option_id_str_valid = 'test'
        registry = resource_options.ResourceOptionRegistry(option_id_str_valid)
        option_name_unique = uuid.uuid4().hex

        option = resource_options.ResourceOption(
            option_id_str_valid, option_name_unique)
        option_dup_id = resource_options.ResourceOption(
            option_id_str_valid, uuid.uuid4().hex)
        option_dup_name = resource_options.ResourceOption(
            uuid.uuid4().hex[:4], option_name_unique)

        registry.register_option(option)

        self.assertRaises(ValueError, registry.register_option, option_dup_id)
        self.assertRaises(ValueError, registry.register_option,
                          option_dup_name)
        self.assertIs(1, len(registry.options))
        registry.register_option(option)
        self.assertIs(1, len(registry.options))

    def test_registry(self):
        option = resource_options.ResourceOption(uuid.uuid4().hex[:4],
                                                 uuid.uuid4().hex)
        option2 = resource_options.ResourceOption(uuid.uuid4().hex[:4],
                                                  uuid.uuid4().hex)
        registry = resource_options.ResourceOptionRegistry('TEST')

        registry.register_option(option)
        self.assertIn(option.option_name, registry.option_names)
        self.assertIs(1, len(registry.options))
        self.assertIn(option.option_id, registry.option_ids)
        registry.register_option(option2)
        self.assertIn(option2.option_name, registry.option_names)
        self.assertIs(2, len(registry.options))
        self.assertIn(option2.option_id, registry.option_ids)
        self.assertIs(option,
                      registry.get_option_by_id(option.option_id))
        self.assertIs(option2,
                      registry.get_option_by_id(option2.option_id))
        self.assertIs(option,
                      registry.get_option_by_name(option.option_name))
        self.assertIs(option2,
                      registry.get_option_by_name(option2.option_name))
