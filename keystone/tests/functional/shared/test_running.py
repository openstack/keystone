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

import requests
import testtools.matchers


is_multiple_choices = testtools.matchers.Equals(
    requests.status_codes.codes.multiple_choices)
is_ok = testtools.matchers.Equals(requests.status_codes.codes.ok)


class TestServerRunning(testtools.TestCase):
    versions = ('v2.0', 'v3')
    admin_url = 'http://localhost:35357'
    public_url = 'http://localhost:5000'

    def test_admin_responds_with_multiple_choices(self):
        resp = requests.get(self.admin_url)
        self.assertThat(resp.status_code, is_multiple_choices)

    def test_admin_versions(self):
        for version in self.versions:
            resp = requests.get(self.admin_url + '/' + version)
            self.assertThat(
                resp.status_code,
                testtools.matchers.Annotate(
                    'failed for version %s' % version, is_ok))

    def test_public_responds_with_multiple_choices(self):
        resp = requests.get(self.public_url)
        self.assertThat(resp.status_code, is_multiple_choices)

    def test_public_versions(self):
        for version in self.versions:
            resp = requests.get(self.public_url + '/' + version)
            self.assertThat(
                resp.status_code,
                testtools.matchers.Annotate(
                    'failed for version %s' % version, is_ok))


class TestServerRunningOnPath(TestServerRunning):
    admin_url = 'http://localhost/identity_admin'
    public_url = 'http://localhost/identity'
