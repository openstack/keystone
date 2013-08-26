# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
#
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

"""Main entry point into the S3 Credentials service.

This service provides S3 token validation for services configured with the
s3_token middleware to authorize S3 requests.

This service uses the same credentials used by EC2. Refer to the documentation
for the EC2 module for how to generate the required credentials.
"""

import base64
import hashlib
import hmac

from keystone.common import extension
from keystone.common import utils
from keystone.common import wsgi
from keystone import config
from keystone.contrib.ec2 import controllers
from keystone import exception

CONF = config.CONF

EXTENSION_DATA = {
    'name': 'OpenStack S3 API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 's3tokens/v1.0',
    'alias': 's3tokens',
    'updated': '2013-07-07T12:00:0-00:00',
    'description': 'OpenStack S3 API.',
    'links': [
        {
            'rel': 'describedby',
            # TODO(ayoung): needs a description
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)


class S3Extension(wsgi.ExtensionRouter):
    def add_routes(self, mapper):
        controller = S3Controller()
        # validation
        mapper.connect('/s3tokens',
                       controller=controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))


class S3Controller(controllers.Ec2Controller):
    def check_signature(self, creds_ref, credentials):
        msg = base64.urlsafe_b64decode(str(credentials['token']))
        key = str(creds_ref['secret'])
        signed = base64.encodestring(
            hmac.new(key, msg, hashlib.sha1).digest()).strip()

        if not utils.auth_str_equal(credentials['signature'], signed):
            raise exception.Unauthorized('Credential signature mismatch')
