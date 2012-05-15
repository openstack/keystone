# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
import hmac

from hashlib import sha1

from keystone import config
from keystone import exception
from keystone.common import utils
from keystone.common import wsgi
from keystone.contrib import ec2

CONF = config.CONF


class S3Extension(wsgi.ExtensionRouter):
    def add_routes(self, mapper):
        controller = S3Controller()
        # validation
        mapper.connect('/s3tokens',
                       controller=controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))


class S3Controller(ec2.Ec2Controller):
    def check_signature(self, creds_ref, credentials):
        msg = base64.urlsafe_b64decode(str(credentials['token']))
        key = str(creds_ref['secret'])
        signed = base64.encodestring(hmac.new(key, msg, sha1).digest()).strip()

        if not utils.auth_str_equal(credentials['signature'], signed):
            raise exception.Unauthorized()
