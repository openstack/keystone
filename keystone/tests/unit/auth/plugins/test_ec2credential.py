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

from keystone import auth
from keystone.auth.plugins import ec2credential
from keystone import exception
from keystone.tests import unit


class TestEc2CredentialPlugin(unit.TestCase):
    def test_load_default_plugin(self):
        plugin = auth.core.load_auth_method('ec2credential')
        self.assertIsInstance(plugin, ec2credential.Plugin)

    def test_method_in_default_auth_methods(self):
        self.assertIn('ec2credential', self.config_fixture.conf.auth.methods)

    def test_authenticate_is_never_successful(self):
        # The plugin is a marker: EC2 credentials are validated by the
        # /v3/ec2tokens endpoint, never via /v3/auth/tokens.
        plugin = ec2credential.Plugin()
        self.assertRaises(
            exception.Unauthorized,
            plugin.authenticate,
            {'user': {'id': 'abc'}},
        )
