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

import six
from six.moves import http_client

from keystone.common import json_home
from keystone.common import utils
from keystone.common import wsgi
from keystone.contrib.ec2 import controllers
from keystone import exception
from keystone.i18n import _


class S3Extension(wsgi.RoutersBase):

    _path_prefixes = ('s3tokens',)

    def append_v3_routers(self, mapper, routers):
        controller = S3Controller()
        # validation
        self._add_resource(
            mapper, controller,
            path='/s3tokens',
            post_action='authenticate',
            rel=json_home.build_v3_extension_resource_relation(
                's3tokens', '1.0', 's3tokens'))


class S3Controller(controllers.Ec2ControllerV3):
    def check_signature(self, creds_ref, credentials):
        string_to_sign = base64.urlsafe_b64decode(str(credentials['token']))

        if string_to_sign[0:4] != b'AWS4':
            signature = self._calculate_signature_v1(string_to_sign,
                                                     creds_ref['secret'])
        else:
            signature = self._calculate_signature_v4(string_to_sign,
                                                     creds_ref['secret'])

        if not utils.auth_str_equal(credentials['signature'], signature):
            raise exception.Unauthorized(
                message=_('Credential signature mismatch'))

    def _calculate_signature_v1(self, string_to_sign, secret_key):
        """Calculate a v1 signature.

        :param bytes string_to_sign: String that contains request params and
                                     is used for calculate signature of request
        :param text secret_key: Second auth key of EC2 account that is used to
                                sign requests
        """
        key = str(secret_key).encode('utf-8')
        if six.PY2:
            b64_encode = base64.encodestring
        else:
            b64_encode = base64.encodebytes
        signed = b64_encode(hmac.new(key, string_to_sign, hashlib.sha1)
                            .digest()).decode('utf-8').strip()
        return signed

    def _calculate_signature_v4(self, string_to_sign, secret_key):
        """Calculate a v4 signature.

        :param bytes string_to_sign: String that contains request params and
                                     is used for calculate signature of request
        :param text secret_key: Second auth key of EC2 account that is used to
                                sign requests
        """
        parts = string_to_sign.split(b'\n')
        if len(parts) != 4 or parts[0] != b'AWS4-HMAC-SHA256':
            raise exception.Unauthorized(message=_('Invalid EC2 signature.'))
        scope = parts[2].split(b'/')
        if len(scope) != 4 or scope[2] != b's3' or scope[3] != b'aws4_request':
            raise exception.Unauthorized(message=_('Invalid EC2 signature.'))

        def _sign(key, msg):
            return hmac.new(key, msg, hashlib.sha256).digest()

        signed = _sign(('AWS4' + secret_key).encode('utf-8'), scope[0])
        signed = _sign(signed, scope[1])
        signed = _sign(signed, scope[2])
        signed = _sign(signed, b'aws4_request')

        signature = hmac.new(signed, string_to_sign, hashlib.sha256)
        return signature.hexdigest()

    def render_token_data_response(self, token_id, token_data):
        """Render token data HTTP response.

        Note: We neither want nor need to send back the token id.
        """
        status = (http_client.OK,
                  http_client.responses[http_client.OK])
        return wsgi.render_response(body=token_data, status=status)
