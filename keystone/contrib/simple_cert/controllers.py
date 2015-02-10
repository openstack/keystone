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

from oslo_config import cfg
import webob

from keystone.common import controller
from keystone.common import dependency
from keystone import exception

CONF = cfg.CONF


@dependency.requires('token_provider_api')
class SimpleCert(controller.V3Controller):

    def _get_certificate(self, name):
        try:
            with open(name, 'r') as f:
                body = f.read()
        except IOError:
            raise exception.CertificateFilesUnavailable()

        # NOTE(jamielennox): We construct the webob Response ourselves here so
        # that we don't pass through the JSON encoding process.
        headers = [('Content-Type', 'application/x-pem-file')]
        return webob.Response(body=body, headerlist=headers, status="200 OK")

    def get_ca_certificate(self, context):
        return self._get_certificate(CONF.signing.ca_certs)

    def list_certificates(self, context):
        return self._get_certificate(CONF.signing.certfile)
