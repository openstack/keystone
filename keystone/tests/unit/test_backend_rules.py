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
from keystone.tests.unit import test_backend


class RulesPolicy(unit.TestCase, test_backend.PolicyTests):
    def setUp(self):
        super(RulesPolicy, self).setUp()
        self.load_backends()

    def config_overrides(self):
        super(RulesPolicy, self).config_overrides()
        self.config_fixture.config(group='policy', driver='rules')

    def test_create(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_create)

    def test_get(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_get)

    def test_list(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_list)

    def test_update(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_update)

    def test_delete(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_delete)

    def test_get_policy_404(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_get_policy_404)

    def test_update_policy_404(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_update_policy_404)

    def test_delete_policy_404(self):
        self.assertRaises(exception.NotImplemented,
                          super(RulesPolicy, self).test_delete_policy_404)
