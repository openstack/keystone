# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

"""Main entry point into the EC2 Credentials service.

This service allows the creation of access/secret credentials used for
the ec2 interop layer of OpenStack.

A user can create as many access/secret pairs, each of which map to a
specific project.  This is required because OpenStack supports a user
belonging to multiple projects, whereas the signatures created on ec2-style
requests don't allow specification of which project the user wishes to act
upon.

To complete the cycle, we provide a method that OpenStack services can
use to validate a signature and get a corresponding OpenStack token.  This
token allows method calls to other services within the context the
access/secret was created.  As an example, Nova requests Keystone to validate
the signature of a request, receives a token, and then makes a request to
Glance to list images needed to perform the requested task.

"""

import uuid

from keystoneclient.contrib.ec2 import utils as ec2_utils

from keystone.common import controller
from keystone.common import dependency
from keystone.common import utils
from keystone import exception
from keystone import token


@dependency.requires('assignment_api', 'catalog_api', 'credential_api',
                     'identity_api', 'token_api', 'token_provider_api')
class Ec2Controller(controller.V2Controller):
    def check_signature(self, creds_ref, credentials):
        signer = ec2_utils.Ec2Signer(creds_ref['secret'])
        signature = signer.generate(credentials)
        if utils.auth_str_equal(credentials['signature'], signature):
            return
        # NOTE(vish): Some libraries don't use the port when signing
        #             requests, so try again without port.
        elif ':' in credentials['signature']:
            hostname, _port = credentials['host'].split(':')
            credentials['host'] = hostname
            signature = signer.generate(credentials)
            if not utils.auth_str_equal(credentials.signature, signature):
                raise exception.Unauthorized(message='Invalid EC2 signature.')
        else:
            raise exception.Unauthorized(message='EC2 signature not supplied.')

    def authenticate(self, context, credentials=None, ec2Credentials=None):
        """Validate a signed EC2 request and provide a token.

        Other services (such as Nova) use this **admin** call to determine
        if a request they signed received is from a valid user.

        If it is a valid signature, an OpenStack token that maps
        to the user/tenant is returned to the caller, along with
        all the other details returned from a normal token validation
        call.

        The returned token is useful for making calls to other
        OpenStack services within the context of the request.

        :param context: standard context
        :param credentials: dict of ec2 signature
        :param ec2Credentials: DEPRECATED dict of ec2 signature
        :returns: token: OpenStack token equivalent to access key along
                         with the corresponding service catalog and roles
        """

        # FIXME(ja): validate that a service token was used!

        # NOTE(termie): backwards compat hack
        if not credentials and ec2Credentials:
            credentials = ec2Credentials

        if 'access' not in credentials:
            raise exception.Unauthorized(message='EC2 signature not supplied.')

        creds_ref = self._get_credentials(credentials['access'])
        self.check_signature(creds_ref, credentials)

        # TODO(termie): don't create new tokens every time
        # TODO(termie): this is copied from TokenController.authenticate
        token_id = uuid.uuid4().hex
        tenant_ref = self.assignment_api.get_project(creds_ref['tenant_id'])
        user_ref = self.identity_api.get_user(creds_ref['user_id'])
        metadata_ref = {}
        metadata_ref['roles'] = (
            self.assignment_api.get_roles_for_user_and_project(
                user_ref['id'], tenant_ref['id']))

        # Validate that the auth info is valid and nothing is disabled
        token.validate_auth_info(self, user_ref, tenant_ref)

        roles = metadata_ref.get('roles', [])
        if not roles:
            raise exception.Unauthorized(message='User not valid for tenant.')
        roles_ref = [self.assignment_api.get_role(role_id)
                     for role_id in roles]

        catalog_ref = self.catalog_api.get_catalog(
            user_ref['id'], tenant_ref['id'], metadata_ref)

        # NOTE(morganfainberg): Make sure the data is in correct form since it
        # might be consumed external to Keystone and this is a v2.0 controller.
        # The token provider doesn't actually expect either v2 or v3 user data.
        user_ref = self.identity_api.v3_to_v2_user(user_ref)
        auth_token_data = dict(user=user_ref,
                               tenant=tenant_ref,
                               metadata=metadata_ref,
                               id='placeholder')
        (token_id, token_data) = self.token_provider_api.issue_v2_token(
            auth_token_data, roles_ref, catalog_ref)
        return token_data

    def create_credential(self, context, user_id, tenant_id):
        """Create a secret/access pair for use with ec2 style auth.

        Generates a new set of credentials that map the user/tenant
        pair.

        :param context: standard context
        :param user_id: id of user
        :param tenant_id: id of tenant
        :returns: credential: dict of ec2 credential
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)

        self._assert_valid_user_id(user_id)
        self._assert_valid_project_id(tenant_id)
        blob = {'access': uuid.uuid4().hex,
                'secret': uuid.uuid4().hex}
        credential_id = utils.hash_access_key(blob['access'])
        cred_ref = {'user_id': user_id,
                    'project_id': tenant_id,
                    'blob': blob,
                    'id': credential_id,
                    'type': 'ec2'}
        self.credential_api.create_credential(credential_id, cred_ref)
        return {'credential': self._convert_v3_to_ec2_credential(cred_ref)}

    def get_credentials(self, context, user_id):
        """List all credentials for a user.

        :param context: standard context
        :param user_id: id of user
        :returns: credentials: list of ec2 credential dicts
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        self._assert_valid_user_id(user_id)
        credential_refs = self.credential_api.list_credentials(
            user_id=user_id)
        return {'credentials':
                [self._convert_v3_to_ec2_credential(credential)
                for credential in credential_refs]}

    def get_credential(self, context, user_id, credential_id):
        """Retrieve a user's access/secret pair by the access key.

        Grab the full access/secret pair for a given access key.

        :param context: standard context
        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: credential: dict of ec2 credential
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        self._assert_valid_user_id(user_id)
        return {'credential': self._get_credentials(credential_id)}

    def delete_credential(self, context, user_id, credential_id):
        """Delete a user's access/secret pair.

        Used to revoke a user's access/secret pair

        :param context: standard context
        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: bool: success
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
            self._assert_owner(user_id, credential_id)

        self._assert_valid_user_id(user_id)
        self._get_credentials(credential_id)
        ec2_credential_id = utils.hash_access_key(credential_id)
        return self.credential_api.delete_credential(ec2_credential_id)

    def _convert_v3_to_ec2_credential(self, credential):

        blob = credential['blob']
        return {'user_id': credential.get('user_id'),
                'tenant_id': credential.get('project_id'),
                'access': blob.get('access'),
                'secret': blob.get('secret')}

    def _get_credentials(self, credential_id):
        """Return credentials from an ID.

        :param credential_id: id of credential
        :raises exception.Unauthorized: when credential id is invalid
        :returns: credential: dict of ec2 credential.
        """
        ec2_credential_id = utils.hash_access_key(credential_id)
        creds = self.credential_api.get_credential(ec2_credential_id)
        if not creds:
            raise exception.Unauthorized(message='EC2 access key not found.')
        return self._convert_v3_to_ec2_credential(creds)

    def _assert_identity(self, context, user_id):
        """Check that the provided token belongs to the user.

        :param context: standard context
        :param user_id: id of user
        :raises exception.Forbidden: when token is invalid

        """
        try:
            token_ref = self.token_api.get_token(context['token_id'])
        except exception.TokenNotFound as e:
            raise exception.Unauthorized(e)

        if token_ref['user'].get('id') != user_id:
            raise exception.Forbidden(_('Token belongs to another user'))

    def _is_admin(self, context):
        """Wrap admin assertion error return statement.

        :param context: standard context
        :returns: bool: success

        """
        try:
            self.assert_admin(context)
            return True
        except exception.Forbidden:
            return False

    def _assert_owner(self, user_id, credential_id):
        """Ensure the provided user owns the credential.

        :param user_id: expected credential owner
        :param credential_id: id of credential object
        :raises exception.Forbidden: on failure

        """
        ec2_credential_id = utils.hash_access_key(credential_id)
        cred_ref = self.credential_api.get_credential(ec2_credential_id)
        if user_id != cred_ref['user_id']:
            raise exception.Forbidden(_('Credential belongs to another user'))

    def _assert_valid_user_id(self, user_id):
        """Ensure a valid user id.

        :param context: standard context
        :param user_id: expected credential owner
        :raises exception.UserNotFound: on failure

        """
        user_ref = self.identity_api.get_user(user_id)
        if not user_ref:
            raise exception.UserNotFound(user_id=user_id)

    def _assert_valid_project_id(self, project_id):
        """Ensure a valid project id.

        :param context: standard context
        :param project_id: expected project
        :raises exception.ProjectNotFound: on failure

        """
        project_ref = self.assignment_api.get_project(project_id)
        if not project_ref:
            raise exception.ProjectNotFound(project_id=project_id)
