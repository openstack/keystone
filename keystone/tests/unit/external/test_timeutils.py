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

import datetime

import keystone.tests.unit as tests


class TestTimeUtils(tests.BaseTestCase):

    def test_parsing_date_strings_returns_a_datetime(self):
        example_date_str = '2015-09-23T04:45:37.196621Z'
        dt = datetime.datetime.strptime(example_date_str, tests.TIME_FORMAT)
        self.assertIsInstance(dt, datetime.datetime)

    def test_parsing_invalid_date_strings_raises_a_ValueError(self):
        example_date_str = ''
        simple_format = '%Y'
        self.assertRaises(ValueError,
                          datetime.datetime.strptime,
                          example_date_str,
                          simple_format)
