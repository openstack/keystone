# Copyright 2018 Catalyst Cloud Ltd
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

import flask
import http.client
from oslo_serialization import jsonutils

from keystone.common import authorization
from keystone.common import provider_api
from keystone import exception


PROVIDERS = provider_api.ProviderAPIs


def extract_receipt(auth_context):
    receipt_id = flask.request.headers.get(
        authorization.AUTH_RECEIPT_HEADER, None)
    if receipt_id:
        receipt = PROVIDERS.receipt_provider_api.validate_receipt(
            receipt_id)

        if auth_context['user_id'] != receipt.user_id:
            raise exception.ReceiptNotFound(
                "AuthContext user_id: %s does not match "
                "user_id for supplied auth receipt: %s" %
                (auth_context['user_id'], receipt.user_id),
                receipt_id=receipt_id
            )
    else:
        receipt = None
    return receipt


def _render_receipt_response_from_model(receipt):
    receipt_reference = {
        'receipt': {
            'methods': receipt.methods,
            'user': {
                'id': receipt.user['id'],
                'name': receipt.user['name'],
                'domain': {
                    'id': receipt.user_domain['id'],
                    'name': receipt.user_domain['name'],
                }
            },
            'expires_at': receipt.expires_at,
            'issued_at': receipt.issued_at,
        },
        'required_auth_methods': receipt.required_methods,
    }
    return receipt_reference


def build_receipt(mfa_error):
    receipt = PROVIDERS.receipt_provider_api. \
        issue_receipt(mfa_error.user_id, mfa_error.methods)
    resp_data = _render_receipt_response_from_model(receipt)
    resp_body = jsonutils.dumps(resp_data)
    response = flask.make_response(resp_body, http.client.UNAUTHORIZED)
    response.headers[authorization.AUTH_RECEIPT_HEADER] = receipt.id
    response.headers['Content-Type'] = 'application/json'
    return response
