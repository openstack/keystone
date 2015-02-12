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

from keystone.common import driver_hints
from keystone.tests.unit import core as test


class ListHintsTests(test.TestCase):

    def test_create_iterate_satisfy(self):
        hints = driver_hints.Hints()
        hints.add_filter('t1', 'data1')
        hints.add_filter('t2', 'data2')
        self.assertEqual(2, len(hints.filters))
        filter = hints.get_exact_filter_by_name('t1')
        self.assertEqual('t1', filter['name'])
        self.assertEqual('data1', filter['value'])
        self.assertEqual('equals', filter['comparator'])
        self.assertEqual(False, filter['case_sensitive'])

        hints.filters.remove(filter)
        filter_count = 0
        for filter in hints.filters:
            filter_count += 1
            self.assertEqual('t2', filter['name'])
        self.assertEqual(1, filter_count)

    def test_multiple_creates(self):
        hints = driver_hints.Hints()
        hints.add_filter('t1', 'data1')
        hints.add_filter('t2', 'data2')
        self.assertEqual(2, len(hints.filters))
        hints2 = driver_hints.Hints()
        hints2.add_filter('t4', 'data1')
        hints2.add_filter('t5', 'data2')
        self.assertEqual(2, len(hints.filters))

    def test_limits(self):
        hints = driver_hints.Hints()
        self.assertIsNone(hints.limit)
        hints.set_limit(10)
        self.assertEqual(10, hints.limit['limit'])
        self.assertFalse(hints.limit['truncated'])
        hints.set_limit(11)
        self.assertEqual(11, hints.limit['limit'])
        self.assertFalse(hints.limit['truncated'])
        hints.set_limit(10, truncated=True)
        self.assertEqual(10, hints.limit['limit'])
        self.assertTrue(hints.limit['truncated'])
