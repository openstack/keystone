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

import stevedore
from testtools import matchers

from keystone.tests.unit import core as test


class TestEntryPoints(test.TestCase):
    def test_entry_point_middleware(self):
        """Assert that our list of expected middleware is present."""
        expected_names = [
            'cors',
            'debug',
            'request_id',
            'sizelimit',
        ]

        em = stevedore.ExtensionManager('keystone.server_middleware')

        actual_names = [extension.name for extension in em]

        self.assertThat(actual_names, matchers.ContainsAll(expected_names))
