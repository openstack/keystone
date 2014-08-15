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

from keystone.catalog import core
from keystone import config
from keystone import exception
from keystone import tests


CONF = config.CONF


class FormatUrlTests(tests.TestCase):

    def setUp(self):
        super(FormatUrlTests, self).setUp()
        whitelist = ['host', 'port', 'part1', 'part2']
        CONF.catalog.endpoint_substitution_whitelist = whitelist

    def test_successful_formatting(self):
        url_template = 'http://%(host)s:%(port)d/%(part1)s/%(part2)s'
        values = {'host': 'server', 'port': 9090, 'part1': 'A', 'part2': 'B'}
        actual_url = core.format_url(url_template, values)

        expected_url = 'http://server:9090/A/B'
        self.assertEqual(actual_url, expected_url)

    def test_raises_malformed_on_missing_key(self):
        self.assertRaises(exception.MalformedEndpoint,
                          core.format_url,
                          "http://%(foo)s/%(bar)s",
                          {"foo": "1"})

    def test_raises_malformed_on_wrong_type(self):
        self.assertRaises(exception.MalformedEndpoint,
                          core.format_url,
                          "http://%foo%s",
                          {"foo": "1"})

    def test_raises_malformed_on_incomplete_format(self):
        self.assertRaises(exception.MalformedEndpoint,
                          core.format_url,
                          "http://%(foo)",
                          {"foo": "1"})

    def test_formatting_a_non_string(self):
        def _test(url_template):
            self.assertRaises(exception.MalformedEndpoint,
                              core.format_url,
                              url_template,
                              {})

        _test(None)
        _test(object())

    def test_substitution_with_key_not_whitelisted(self):
        url_template = 'http://%(host)s:%(port)d/%(part1)s/%(part2)s/%(part3)s'
        values = {'host': 'server', 'port': 9090,
                  'part1': 'A', 'part2': 'B', 'part3': 'C'}
        self.assertRaises(exception.MalformedEndpoint,
                          core.format_url,
                          url_template,
                          values)
