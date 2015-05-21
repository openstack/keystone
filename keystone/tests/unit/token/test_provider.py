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

import six
from six.moves import urllib

from keystone.tests import unit
from keystone.token import provider


class TestRandomStrings(unit.BaseTestCase):
    def test_strings_are_url_safe(self):
        s = provider.random_urlsafe_str()
        self.assertEqual(s, urllib.parse.quote_plus(s))

    def test_strings_can_be_converted_to_bytes(self):
        s = provider.random_urlsafe_str()
        self.assertTrue(isinstance(s, six.string_types))

        b = provider.random_urlsafe_str_to_bytes(s)
        self.assertTrue(isinstance(b, bytes))
