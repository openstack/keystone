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

A user can create as many access/secret pairs, each of which is mapped to a
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

import abc
import sys
import uuid

from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_serialization import jsonutils
import six
from six.moves import http_client

from keystone.common import controller
from keystone.common import provider_api
from keystone.common import utils
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _

CRED_TYPE_EC2 = 'ec2'
CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


@six.add_metaclass(abc.ABCMeta)
class Ec2ControllerCommon(provider_api.ProviderAPIMixin, object):
    def check_signature(self, creds_ref, credentials):
        signer = ec2_utils.Ec2Signer(creds_ref['secret'])
        signature = signer.generate(credentials)
        # NOTE(davechen): credentials.get('signature') is not guaranteed to
        # exist, we need check it explicitly.
        if credentials.get('signature'):
            if utils.auth_str_equal(credentials['signature'], signature):
                return True
            # NOTE(vish): Some client libraries don't use the port when signing
            #             requests, so try again without port.
            elif ':' in credentials['host']:
                hostname, _port = credentials['host'].split(':')
                credentials['host'] = hostname
                # NOTE(davechen): we need reinitialize 'signer' to avoid
                # contaminated status of signature, this is similar with
                # other programming language libraries, JAVA for example.
                signer = ec2_utils.Ec2Signer(creds_ref['secret'])
                signature = signer.generate(credentials)
                if utils.auth_str_equal(credentials['signature'],
                                        signature):
                    return True
                raise exception.Unauthorized(
                    message=_('Invalid EC2 signature.'))
            else:
                raise exception.Unauthorized(
                    message=_('EC2 signature not supplied.'))
        # Raise the exception when credentials.get('signature') is None
        else:
            raise exception.Unauthorized(
                message=_('EC2 signature not supplied.'))

    @abc.abstractmethod
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
        raise exception.NotImplemented()

    def _authenticate(self, credentials=None, ec2credentials=None):
        """Common code shared between the V2 and V3 authenticate methods.

        :returns: user_ref, tenant_ref, roles_ref
        """
        # FIXME(ja): validate that a service token was used!

        # NOTE(termie): backwards compat hack
        if not credentials and ec2credentials:
            credentials = ec2credentials

        if 'access' not in credentials:
            raise exception.Unauthorized(
                message=_('EC2 signature not supplied.'))

        creds_ref = self._get_credentials(credentials['access'])
        self.check_signature(creds_ref, credentials)

        # TODO(termie): don't create new tokens every time
        # TODO(termie): this is copied from TokenController.authenticate
        tenant_ref = self.resource_api.get_project(creds_ref['tenant_id'])
        user_ref = self.identity_api.get_user(creds_ref['user_id'])

        # Validate that the auth info is valid and nothing is disabled
        try:
            self.identity_api.assert_user_enabled(
                user_id=user_ref['id'], user=user_ref)
            self.resource_api.assert_domain_enabled(
                domain_id=user_ref['domain_id'])
            self.resource_api.assert_project_enabled(
                project_id=tenant_ref['id'], project=tenant_ref)
        except AssertionError as e:
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

        roles = self.assignment_api.get_roles_for_user_and_project(
            user_ref['id'], tenant_ref['id']
        )
        if not roles:
            raise exception.Unauthorized(
                message=_('User not valid for tenant.'))
        roles_ref = [self.role_api.get_role(role_id) for role_id in roles]

        return user_ref, tenant_ref, roles_ref

    def create_credential(self, request, user_id, tenant_id):
        """Create a secret/access pair for use with ec2 style auth.

        Generates a new set of credentials that map the user/tenant
        pair.

        :param request: current request
        :param user_id: id of user
        :param tenant_id: id of tenant
        :returns: credential: dict of ec2 credential
        """
        self.identity_api.get_user(user_id)
        self.resource_api.get_project(tenant_id)
        blob = {'access': uuid.uuid4().hex,
                'secret': uuid.uuid4().hex,
                'trust_id': request.context.trust_id}
        credential_id = utils.hash_access_key(blob['access'])
        cred_ref = {'user_id': user_id,
                    'project_id': tenant_id,
                    'blob': jsonutils.dumps(blob),
                    'id': credential_id,
                    'type': CRED_TYPE_EC2}
        self.credential_api.create_credential(credential_id, cred_ref)
        return {'credential': self._convert_v3_to_ec2_credential(cred_ref)}

    def get_credentials(self, user_id):
        """List all credentials for a user.

        :param user_id: id of user
        :returns: credentials: list of ec2 credential dicts
        """
        self.identity_api.get_user(user_id)
        credential_refs = self.credential_api.list_credentials_for_user(
            user_id, type=CRED_TYPE_EC2)
        return {'credentials':
                [self._convert_v3_to_ec2_credential(credential)
                    for credential in credential_refs]}

    def get_credential(self, user_id, credential_id):
        """Retrieve a user's access/secret pair by the access key.

        Grab the full access/secret pair for a given access key.

        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: credential: dict of ec2 credential
        """
        self.identity_api.get_user(user_id)
        return {'credential': self._get_credentials(credential_id)}

    def delete_credential(self, user_id, credential_id):
        """Delete a user's access/secret pair.

        Used to revoke a user's access/secret pair

        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: bool: success
        """
        self.identity_api.get_user(user_id)
        self._get_credentials(credential_id)
        ec2_credential_id = utils.hash_access_key(credential_id)
        return self.credential_api.delete_credential(ec2_credential_id)

    @staticmethod
    def _convert_v3_to_ec2_credential(credential):
        # Prior to bug #1259584 fix, blob was stored unserialized
        # but it should be stored as a json string for compatibility
        # with the v3 credentials API.  Fall back to the old behavior
        # for backwards compatibility with existing DB contents
        try:
            blob = jsonutils.loads(credential['blob'])
        except TypeError:
            blob = credential['blob']
        return {'user_id': credential.get('user_id'),
                'tenant_id': credential.get('project_id'),
                'access': blob.get('access'),
                'secret': blob.get('secret'),
                'trust_id': blob.get('trust_id')}

    def _get_credentials(self, credential_id):
        """Return credentials from an ID.

        :param credential_id: id of credential
        :raises keystone.exception.Unauthorized: when credential id is invalid
            or when the credential type is not ec2
        :returns: credential: dict of ec2 credential.
        """
        ec2_credential_id = utils.hash_access_key(credential_id)
        cred = self.credential_api.get_credential(ec2_credential_id)
        if not cred or cred['type'] != CRED_TYPE_EC2:
            raise exception.Unauthorized(
                message=_('EC2 access key not found.'))
        return self._convert_v3_to_ec2_credential(cred)

    def render_token_data_response(self, token_id, token_data):
        """Render token data HTTP response.

        Stash token ID into the X-Subject-Token header.

        """
        status = (http_client.OK,
                  http_client.responses[http_client.OK])
        headers = [('X-Subject-Token', token_id)]

        return wsgi.render_response(body=token_data,
                                    status=status,
                                    headers=headers)


class Ec2ControllerV3(Ec2ControllerCommon, controller.V3Controller):

    collection_name = 'credentials'
    member_name = 'credential'

    def _check_credential_owner_and_user_id_match(self, request, prep_info,
                                                  user_id, credential_id):
        # NOTE(morganfainberg): this method needs to capture the arguments of
        # the method that is decorated with @controller.protected() (with
        # exception of the first argument ('context') since the protected
        # method passes in *args, **kwargs. In this case, it is easier to see
        # the expected input if the argspec is `user_id` and `credential_id`
        # explicitly (matching the :class:`.ec2_delete_credential()` method
        # below).
        ref = {}
        credential_id = utils.hash_access_key(credential_id)
        ref['credential'] = self.credential_api.get_credential(credential_id)
        # NOTE(morganfainberg): policy_api is required for this
        # check_protection to properly be able to perform policy enforcement.
        self.check_protection(request, prep_info, ref)

    def authenticate(self, context, credentials=None, ec2Credentials=None):
        (user_ref, project_ref, roles_ref) = self._authenticate(
            credentials=credentials, ec2credentials=ec2Credentials
        )

        method_names = ['ec2credential']

        token = self.token_provider_api.issue_token(
            user_ref['id'], method_names, project_id=project_ref['id']
        )
        token_reference = controller.render_token_response_from_model(token)
        return self.render_token_data_response(token.id, token_reference)

    @controller.protected(callback=_check_credential_owner_and_user_id_match)
    def ec2_get_credential(self, request, user_id, credential_id):
        ref = super(Ec2ControllerV3, self).get_credential(user_id,
                                                          credential_id)
        return Ec2ControllerV3.wrap_member(request.context_dict,
                                           ref['credential'])

    @controller.protected()
    def ec2_list_credentials(self, request, user_id):
        refs = super(Ec2ControllerV3, self).get_credentials(user_id)
        return Ec2ControllerV3.wrap_collection(request.context_dict,
                                               refs['credentials'])

    @controller.protected()
    def ec2_create_credential(self, request, user_id, tenant_id):
        ref = super(Ec2ControllerV3, self).create_credential(
            request, user_id, tenant_id)
        return Ec2ControllerV3.wrap_member(request.context_dict,
                                           ref['credential'])

    @controller.protected(callback=_check_credential_owner_and_user_id_match)
    def ec2_delete_credential(self, request, user_id, credential_id):
        return super(Ec2ControllerV3, self).delete_credential(user_id,
                                                              credential_id)

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        path = '/users/%(user_id)s/credentials/OS-EC2/%(credential_id)s'
        url = cls.base_url(context, path) % {
            'user_id': ref['user_id'],
            'credential_id': ref['access']}
        ref.setdefault('links', {})
        ref['links']['self'] = url
