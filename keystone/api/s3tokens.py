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
import http.client

import flask
from oslo_serialization import jsonutils

from keystone.api._shared import EC2_S3_Resource
from keystone.api._shared import json_home_relations
from keystone.common import rbac_enforcer
from keystone.common import render_token
from keystone.common import utils
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask

ENFORCER = rbac_enforcer.RBACEnforcer


def _calculate_signature_v1(string_to_sign, secret_key):
    """Calculate a v1 signature.

    :param bytes string_to_sign: String that contains request params and
                                 is used for calculate signature of request
    :param text secret_key: Second auth key of EC2 account that is used to
                            sign requests
    """
    key = str(secret_key).encode('utf-8')
    b64_encode = base64.encodebytes
    signed = (
        b64_encode(hmac.new(key, string_to_sign, hashlib.sha1).digest())
        .decode('utf-8')
        .strip()
    )
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
            signature = _calculate_signature_v1(
                string_to_sign, creds_ref['secret']
            )
        else:
            signature = _calculate_signature_v4(
                string_to_sign, creds_ref['secret']
            )

        if not utils.auth_str_equal(credentials['signature'], signature):
            raise exception.Unauthorized(
                message=_('Credential signature mismatch')
            )

    @staticmethod
    def _extract_timestamp_from_token(token):
        """Extract the request date from a Swift s3token string-to-sign.

        The token field is the urlsafe-base64 encoding of the string-to-sign
        that ``_check_signature`` already verified. Layouts:

        * SigV4: line 0 is ``AWS4-HMAC-SHA256``, line 1 is
          ``YYYYMMDDTHHMMSSZ``.
        * SigV2 header auth with ``Date``: line 3 is the RFC 1123 date.
        * SigV2 header auth with ``x-amz-date``: line 3 is empty and the
          date appears as an ``x-amz-date:`` amz-header line.
        * SigV2 query auth: line 3 is Unix epoch ``Expires``.
        """
        try:
            sts = base64.urlsafe_b64decode(str(token)).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            return None

        lines = sts.split('\n')
        if not lines:
            return None

        if lines[0] == 'AWS4-HMAC-SHA256':
            if len(lines) < 2:
                return None
            date_field = lines[1].strip()
            return date_field or None

        # SigV2: Verb\nContent-MD5\nContent-Type\nDate|Expires\n...
        if len(lines) > 3 and lines[3].strip():
            return lines[3].strip()

        for line in lines[4:]:
            if line.lower().startswith('x-amz-date:'):
                return line.split(':', 1)[1].strip() or None
        return None

    @staticmethod
    def _check_timestamp(credentials):
        base = EC2_S3_Resource.ResourceBase
        timestamp = base._timestamp_from_params_or_headers(credentials)
        if not timestamp:
            timestamp = S3Resource._extract_timestamp_from_token(
                credentials.get('token')
            )
        if not timestamp:
            raise exception.Unauthorized(
                _(
                    'EC2/S3 signed requests must include a timestamp '
                    '(Timestamp query parameter or X-Amz-Date).'
                )
            )
        base._enforce_auth_ttl(base._parse_timestamp(timestamp))

    def post(self):
        """Authenticate s3token.

        POST /v3/s3tokens
        """
        # Use standard Keystone policy enforcement for s3tokens access
        ENFORCER.enforce_call(action='identity:s3tokens_validate')

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
                json_home_relations.s3_token_resource_rel_func
            ),
        )
    ]


APIs = (S3Api,)
