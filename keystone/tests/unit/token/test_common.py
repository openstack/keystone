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

from six.moves import urllib

from keystone.tests import unit
from keystone.token import provider
from keystone.token.providers import common


class TestTokenProvidersCommon(unit.TestCase):
    def test_strings_are_url_safe(self):
        s = common.random_urlsafe_str()
        self.assertEqual(s, urllib.parse.quote_plus(s))

    def test_unsupported_provider_raises_import_error(self):
        namespace = "keystone.token.provider"
        # Generate a random name
        driver = uuid.uuid4().hex
        self.config_fixture.config(group='token', provider=driver)
        msg = "Unable to find '%(driver)s' driver in '%(namespace)s'." % {
            'namespace': namespace, 'driver': driver
        }

        self.assertRaisesRegex(ImportError, msg, provider.Manager)
