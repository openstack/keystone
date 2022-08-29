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

# This file handles all flask-restful resources for /v3/ec2tokens

import urllib.parse

import flask
import http.client
from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_serialization import jsonutils

from keystone.api._shared import EC2_S3_Resource
from keystone.api._shared import json_home_relations
from keystone.common import render_token
from keystone.common import utils
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask


CRED_TYPE_EC2 = 'ec2'


class EC2TokensResource(EC2_S3_Resource.ResourceBase):
    @staticmethod
    def _check_signature(creds_ref, credentials):
        signer = ec2_utils.Ec2Signer(creds_ref['secret'])
        signature = signer.generate(credentials)
        # NOTE(davechecn): credentials.get('signature') is not guaranteed to
        # exist, we need to check it explicitly.
        if credentials.get('signature'):
            if utils.auth_str_equal(credentials['signature'], signature):
                return True
            # NOTE(vish): Some client libraries don't use the port when
            # signing requests, so try again without the port.
            elif ':' in credentials['host']:
                parsed = urllib.parse.urlsplit('//' + credentials['host'])
                credentials['host'] = parsed.hostname
                # NOTE(davechen): we need to reinitialize 'signer' to avoid
                # contaminated status of signature, this is similar with
                # other programming language libraries, JAVA for example.
                signer = ec2_utils.Ec2Signer(creds_ref['secret'])
                signature = signer.generate(credentials)
                if utils.auth_str_equal(
                        credentials['signature'], signature):
                    return True
            raise exception.Unauthorized(_('Invalid EC2 signature.'))
        # Raise the exception when credentials.get('signature') is None
        else:
            raise exception.Unauthorized(
                _('EC2 signature not supplied.'))

    @ks_flask.unenforced_api
    def post(self):
        """Authenticate ec2 token.

        POST /v3/ec2tokens
        """
        token = self.handle_authenticate()
        token_reference = render_token.render_token_response_from_model(token)
        resp_body = jsonutils.dumps(token_reference)
        response = flask.make_response(resp_body, http.client.OK)
        response.headers['X-Subject-Token'] = token.id
        response.headers['Content-Type'] = 'application/json'
        return response


class EC2TokensAPI(ks_flask.APIBase):
    _name = 'ec2tokens'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=EC2TokensResource,
            url='/ec2tokens',
            resource_kwargs={},
            rel='ec2tokens',
            resource_relation_func=(
                json_home_relations.os_ec2_resource_rel_func))
    ]


APIs = (EC2TokensAPI,)
