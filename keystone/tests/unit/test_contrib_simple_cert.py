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

import http.client

from keystone.tests.unit import test_v3


class BaseTestCase(test_v3.RestfulTestCase):

    CA_PATH = '/v3/OS-SIMPLE-CERT/ca'
    CERT_PATH = '/v3/OS-SIMPLE-CERT/certificates'


class TestSimpleCert(BaseTestCase):

    def request_cert(self, path):
        self.request(app=self.public_app,
                     method='GET',
                     path=path,
                     expected_status=http.client.GONE)

    def test_ca_cert(self):
        self.request_cert(self.CA_PATH)

    def test_signing_cert(self):
        self.request_cert(self.CERT_PATH)
