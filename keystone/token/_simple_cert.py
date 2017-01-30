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

# TODO(morganfainberg): Remove this file and extension in the "O" release as
# it is only used in support of the PKI/PKIz token providers.
import functools

import webob

from keystone.common import controller
from keystone.common import dependency
from keystone.common import extension
from keystone.common import json_home
from keystone.common import wsgi
import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF
EXTENSION_DATA = {
    'name': 'OpenStack Simple Certificate API',
    'namespace': 'https://docs.openstack.org/identity/api/ext/'
                 'OS-SIMPLE-CERT/v1.0',
    'alias': 'OS-SIMPLE-CERT',
    'updated': '2014-01-20T12:00:0-00:00',
    'description': 'OpenStack simple certificate retrieval extension',
    'links': [
        {
            'rel': 'describedby',
            'type': 'text/html',
            'href': 'https://developer.openstack.org/'
                    'api-ref-identity-v2-ext.html',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)

build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-SIMPLE-CERT', extension_version='1.0')


class Routers(wsgi.RoutersBase):

    def _construct_url(self, suffix):
        return "/OS-SIMPLE-CERT/%s" % suffix

    def append_v3_routers(self, mapper, routers):
        controller = SimpleCert()

        self._add_resource(
            mapper, controller,
            path=self._construct_url('ca'),
            get_action='get_ca_certificate',
            rel=build_resource_relation(resource_name='ca_certificate'))
        self._add_resource(
            mapper, controller,
            path=self._construct_url('certificates'),
            get_action='list_certificates',
            rel=build_resource_relation(resource_name='certificates'))


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
