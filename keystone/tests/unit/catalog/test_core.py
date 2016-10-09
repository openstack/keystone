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

from keystone.common import utils
from keystone import exception
from keystone.tests import unit


class FormatUrlTests(unit.BaseTestCase):

    def test_successful_formatting(self):
        url_template = ('http://$(public_bind_host)s:$(admin_port)d/'
                        '$(tenant_id)s/$(user_id)s/$(project_id)s')
        project_id = uuid.uuid4().hex
        values = {'public_bind_host': 'server', 'admin_port': 9090,
                  'tenant_id': 'A', 'user_id': 'B', 'project_id': project_id}
        actual_url = utils.format_url(url_template, values)

        expected_url = 'http://server:9090/A/B/%s' % (project_id,)
        self.assertEqual(expected_url, actual_url)

    def test_raises_malformed_on_missing_key(self):
        self.assertRaises(exception.MalformedEndpoint,
                          utils.format_url,
                          "http://$(public_bind_host)s/$(public_port)d",
                          {"public_bind_host": "1"})

    def test_raises_malformed_on_wrong_type(self):
        self.assertRaises(exception.MalformedEndpoint,
                          utils.format_url,
                          "http://$(public_bind_host)d",
                          {"public_bind_host": "something"})

    def test_raises_malformed_on_incomplete_format(self):
        self.assertRaises(exception.MalformedEndpoint,
                          utils.format_url,
                          "http://$(public_bind_host)",
                          {"public_bind_host": "1"})

    def test_formatting_a_non_string(self):
        def _test(url_template):
            self.assertRaises(exception.MalformedEndpoint,
                              utils.format_url,
                              url_template,
                              {})

        _test(None)
        _test(object())

    def test_substitution_with_key_not_allowed(self):
        # If the url template contains a substitution that's not in the allowed
        # list then MalformedEndpoint is raised.
        # For example, admin_token isn't allowed.
        url_template = ('http://$(public_bind_host)s:$(public_port)d/'
                        '$(project_id)s/$(user_id)s/$(admin_token)s')
        values = {'public_bind_host': 'server', 'public_port': 9090,
                  'project_id': 'A', 'user_id': 'B', 'admin_token': 'C'}
        self.assertRaises(exception.MalformedEndpoint,
                          utils.format_url,
                          url_template,
                          values)

    def test_substitution_with_allowed_tenant_keyerror(self):
        # No value of 'tenant_id' is passed into url_template.
        # mod: format_url will return None instead of raising
        # "MalformedEndpoint" exception.
        # This is intentional behavior since we don't want to skip
        # all the later endpoints once there is an URL of endpoint
        # trying to replace 'tenant_id' with None.
        url_template = ('http://$(public_bind_host)s:$(admin_port)d/'
                        '$(tenant_id)s/$(user_id)s')
        values = {'public_bind_host': 'server', 'admin_port': 9090,
                  'user_id': 'B'}
        self.assertIsNone(utils.format_url(url_template, values,
                          silent_keyerror_failures=['tenant_id']))

    def test_substitution_with_allowed_project_keyerror(self):
        # No value of 'project_id' is passed into url_template.
        # mod: format_url will return None instead of raising
        # "MalformedEndpoint" exception.
        # This is intentional behavior since we don't want to skip
        # all the later endpoints once there is an URL of endpoint
        # trying to replace 'project_id' with None.
        url_template = ('http://$(public_bind_host)s:$(admin_port)d/'
                        '$(project_id)s/$(user_id)s')
        values = {'public_bind_host': 'server', 'admin_port': 9090,
                  'user_id': 'B'}
        self.assertIsNone(utils.format_url(url_template, values,
                          silent_keyerror_failures=['project_id']))
