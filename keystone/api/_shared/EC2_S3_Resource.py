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

# Common base resource for EC2 and S3 Authentication

import sys

from oslo_serialization import jsonutils
import six
from werkzeug import exceptions

from keystone.common import provider_api
from keystone.common import utils
from keystone import exception as ks_exceptions
from keystone.i18n import _
from keystone.server import flask as ks_flask

PROVIDERS = provider_api.ProviderAPIs
CRED_TYPE_EC2 = 'ec2'


class ResourceBase(ks_flask.ResourceBase):
    def get(self):
        # SPECIAL CASE: GET is not allowed, raise METHOD_NOT_ALLOWED
        raise exceptions.MethodNotAllowed(valid_methods=['POST'])

    @staticmethod
    def _check_signature(cred_ref, credentials):
        # NOTE(morgan): @staticmethod doesn't always play nice with
        # the ABC module.
        raise NotImplementedError()

    def handle_authenticate(self):
        # TODO(morgan): convert this dirty check to JSON Schema validation
        # this mirrors the previous behavior of the webob system where an
        # empty request body for s3 and ec2 tokens would result in a BAD
        # REQUEST. Almost all other APIs use JSON Schema and therefore would
        # catch this early on. S3 and EC2 did not ever get json schema
        # implemented for them.
        if not self.request_body_json:
            msg = _('request must include a request body')
            raise ks_exceptions.ValidationError(msg)

        # NOTE(morgan): THIS IS SLOPPY! Apparently... keystone passed values
        # as "credential" and "credentials" in into the s3/ec2 authenticate
        # methods. There is no reason the multiple names should have worked
        # except that we totally did something wonky in the past... so now
        # there are 2 dirty "acceptable" body hacks for compatibility....
        # Try "credentials" then "credential" and THEN ec2Credentials. Final
        # default is {}
        credentials = (
            self.request_body_json.get('credentials') or
            self.request_body_json.get('credential') or
            self.request_body_json.get('ec2Credentials')
        )
        if not credentials:
            credentials = {}

        if 'access' not in credentials:
            raise ks_exceptions.Unauthorized(_('EC2 Signature not supplied'))

        # Load the credential from the backend
        credential_id = utils.hash_access_key(credentials['access'])
        cred = PROVIDERS.credential_api.get_credential(credential_id)
        if not cred or cred['type'] != CRED_TYPE_EC2:
            raise ks_exceptions.Unauthorized(_('EC2 access key not found.'))

        # load from json if needed
        try:
            loaded = jsonutils.loads(cred['blob'])
        except TypeError:
            loaded = cred['blob']

        # Convert to the legacy format
        cred_data = dict(
            user_id=cred.get('user_id'),
            project_id=cred.get('project_id'),
            access=loaded.get('access'),
            secret=loaded.get('secret'),
            trust_id=loaded.get('trust_id')
        )

        # validate the signature
        self._check_signature(cred_data, credentials)
        project_ref = PROVIDERS.resource_api.get_project(
            cred_data['project_id'])
        user_ref = PROVIDERS.identity_api.get_user(cred_data['user_id'])

        # validate that the auth info is valid and nothing is disabled
        try:
            PROVIDERS.identity_api.assert_user_enabled(
                user_id=user_ref['id'], user=user_ref)
            PROVIDERS.resource_api.assert_project_enabled(
                project_id=project_ref['id'], project=project_ref)
        except AssertionError as e:
            six.reraise(
                ks_exceptions.Unauthorized,
                ks_exceptions.Unauthorized(e),
                sys.exc_info()[2])

        roles = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            user_ref['id'], project_ref['id'])

        if not roles:
            raise ks_exceptions.Unauthorized(_('User not valid for project.'))

        for r_id in roles:
            # Assert all roles exist.
            PROVIDERS.role_api.get_role(r_id)

        method_names = ['ec2credential']

        token = PROVIDERS.token_provider_api.issue_token(
            user_id=user_ref['id'], method_names=method_names,
            project_id=project_ref['id'])
        return token
