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

from keystone.tests.unit import test_v3


class BaseTestCase(test_v3.RestfulTestCase):

    EXTENSION_TO_ADD = 'simple_cert_extension'

    CA_PATH = '/v3/OS-SIMPLE-CERT/ca'
    CERT_PATH = '/v3/OS-SIMPLE-CERT/certificates'


class TestSimpleCert(BaseTestCase):

    def request_cert(self, path):
        content_type = 'application/x-pem-file'
        response = self.request(app=self.public_app,
                                method='GET',
                                path=path,
                                headers={'Accept': content_type},
                                expected_status=200)

        self.assertEqual(content_type, response.content_type.lower())
        self.assertIn('---BEGIN', response.body)

        return response

    def test_ca_cert(self):
        self.request_cert(self.CA_PATH)

    def test_signing_cert(self):
        self.request_cert(self.CERT_PATH)

    def test_missing_file(self):
        # these files do not exist
        self.config_fixture.config(group='signing',
                                   ca_certs=uuid.uuid4().hex,
                                   certfile=uuid.uuid4().hex)

        for path in [self.CA_PATH, self.CERT_PATH]:
            self.request(app=self.public_app,
                         method='GET',
                         path=path,
                         expected_status=500)
