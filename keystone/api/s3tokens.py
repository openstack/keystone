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

# This file handles all flask-restful resources for /v3/s3tokens

import base64
import hashlib
import hmac

import flask
import http.client
from oslo_serialization import jsonutils

from keystone.api._shared import EC2_S3_Resource
from keystone.api._shared import json_home_relations
from keystone.common import render_token
from keystone.common import utils
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask


def _calculate_signature_v1(string_to_sign, secret_key):
    """Calculate a v1 signature.

    :param bytes string_to_sign: String that contains request params and
                                 is used for calculate signature of request
    :param text secret_key: Second auth key of EC2 account that is used to
                            sign requests
    """
    key = str(secret_key).encode('utf-8')
    b64_encode = base64.encodebytes
    signed = b64_encode(hmac.new(key, string_to_sign, hashlib.sha1)
                        .digest()).decode('utf-8').strip()
    return signed


def _calculate_signature_v4(string_to_sign, secret_key):
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
    if len(scope) != 4 or scope[3] != b'aws4_request':
        raise exception.Unauthorized(message=_('Invalid EC2 signature.'))
    allowed_services = [b's3', b'iam', b'sts']
    if scope[2] not in allowed_services:
        raise exception.Unauthorized(message=_('Invalid EC2 signature.'))

    def _sign(key, msg):
        return hmac.new(key, msg, hashlib.sha256).digest()

    signed = _sign(('AWS4' + secret_key).encode('utf-8'), scope[0])
    signed = _sign(signed, scope[1])
    signed = _sign(signed, scope[2])
    signed = _sign(signed, b'aws4_request')

    signature = hmac.new(signed, string_to_sign, hashlib.sha256)
    return signature.hexdigest()


class S3Resource(EC2_S3_Resource.ResourceBase):
    @staticmethod
    def _check_signature(creds_ref, credentials):
        string_to_sign = base64.urlsafe_b64decode(str(credentials['token']))

        if string_to_sign[0:4] != b'AWS4':
            signature = _calculate_signature_v1(string_to_sign,
                                                creds_ref['secret'])
        else:
            signature = _calculate_signature_v4(string_to_sign,
                                                creds_ref['secret'])

        if not utils.auth_str_equal(credentials['signature'], signature):
            raise exception.Unauthorized(
                message=_('Credential signature mismatch'))

    @ks_flask.unenforced_api
    def post(self):
        """Authenticate s3token.

        POST /v3/s3tokens
        """
        token = self.handle_authenticate()
        token_reference = render_token.render_token_response_from_model(token)
        resp_body = jsonutils.dumps(token_reference)
        response = flask.make_response(resp_body, http.client.OK)
        response.headers['Content-Type'] = 'application/json'
        return response


class S3Api(ks_flask.APIBase):
    _name = 's3tokens'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=S3Resource,
            url='/s3tokens',
            resource_kwargs={},
            rel='s3tokens',
            resource_relation_func=(
                json_home_relations.s3_token_resource_rel_func))
    ]


APIs = (S3Api,)
