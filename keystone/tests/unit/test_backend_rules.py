# Copyright 2013 OpenStack Foundation
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


from keystone import exception
from keystone.tests import unit
from keystone.tests.unit.policy import test_backends as policy_tests


class RulesPolicy(unit.TestCase, policy_tests.PolicyTests):
    def setUp(self):
        super().setUp()
        self.load_backends()

    def config_overrides(self):
        super().config_overrides()
        self.config_fixture.config(group='policy', driver='rules')

    def test_create(self):
        self.assertRaises(exception.NotImplemented, super().test_create)

    def test_get(self):
        self.assertRaises(exception.NotImplemented, super().test_get)

    def test_list(self):
        self.assertRaises(exception.NotImplemented, super().test_list)

    def test_update(self):
        self.assertRaises(exception.NotImplemented, super().test_update)

    def test_delete(self):
        self.assertRaises(exception.NotImplemented, super().test_delete)

    def test_get_policy_returns_not_found(self):
        self.assertRaises(
            exception.NotImplemented, super().test_get_policy_returns_not_found
        )

    def test_update_policy_returns_not_found(self):
        self.assertRaises(
            exception.NotImplemented,
            super().test_update_policy_returns_not_found,
        )

    def test_delete_policy_returns_not_found(self):
        self.assertRaises(
            exception.NotImplemented,
            super().test_delete_policy_returns_not_found,
        )
