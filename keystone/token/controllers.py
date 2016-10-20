# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import datetime
import sys

from keystone.common import utils
from keystoneclient.common import cms
from oslo_log import log
from oslo_serialization import jsonutils
import six

from keystone.common import controller
from keystone.common import dependency
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model
from keystone.token.providers import common


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


def authentication_method_generator(request, auth):
    """Given an request return a suitable authentication method.

    This is simply a generator to handle matching an authentication request
    with the appropriate authentication method.

    :param auth: Dictionary containing authentication information from the
                 request.
    :returns: An authentication method class object.
    """
    if auth is None:
        raise exception.ValidationError(attribute='auth',
                                        target='request body')

    if request.environ.get('REMOTE_USER'):
        method = ExternalAuthenticationMethod()
    elif 'token' in auth:
        method = TokenAuthenticationMethod()
    elif 'passwordCredentials' in auth:
        method = LocalAuthenticationMethod()
    else:
        raise exception.ValidationError(attribute='auth',
                                        target='request body')
    return method


class ExternalAuthNotApplicable(Exception):
    """External authentication is not applicable."""

    pass


@dependency.requires('assignment_api', 'catalog_api', 'identity_api',
                     'resource_api', 'role_api', 'token_provider_api',
                     'trust_api')
class Auth(controller.V2Controller):

    @controller.v2_deprecated
    def ca_cert(self, request):
        with open(CONF.signing.ca_certs, 'r') as ca_file:
            data = ca_file.read()
        return data

    @controller.v2_deprecated
    def signing_cert(self, request):
        with open(CONF.signing.certfile, 'r') as cert_file:
            data = cert_file.read()
        return data

    @controller.v2_auth_deprecated
    def authenticate(self, request, auth=None):
        """Authenticate credentials and return a token.

        Accept auth as a dict that looks like::

            {
                "auth":{
                    "passwordCredentials":{
                        "username":"test_user",
                        "password":"mypass"
                    },
                    "tenantName":"customer-x"
                }
            }

        In this case, tenant is optional, if not provided the token will be
        considered "unscoped" and can later be used to get a scoped token.

        Alternatively, this call accepts auth with only a token and tenant
        that will return a token that is scoped to that tenant.
        """
        method = authentication_method_generator(request, auth)
        user_ref, project_id, expiry, bind, audit_id = (
            method.authenticate(request, auth)
        )

        # Ensure the entities provided in the authentication information are
        # valid and not disabled.
        try:
            self.identity_api.assert_user_enabled(
                user_id=user_ref['id'], user=user_ref)
            if project_id:
                try:
                    self.resource_api.get_project(project_id)
                except exception.ProjectNotFound:
                    msg = _(
                        'Project ID not found: %(p_id)s'
                    ) % {'p_id': project_id}
                    raise exception.Unauthorized(msg)
                self.resource_api.assert_project_enabled(project_id)
        except AssertionError as e:
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])
        # NOTE(morganfainberg): Make sure the data is in correct form since it
        # might be consumed external to Keystone and this is a v2.0 controller.
        # The user_ref is encoded into the auth_token_data which is returned as
        # part of the token data. The token provider doesn't care about the
        # format.
        user_ref = self.v3_to_v2_user(user_ref)

        auth_context = {}
        if bind:
            auth_context['bind'] = bind

        trust_ref = None
        if CONF.trust.enabled and 'trust_id' in auth:
            trust_ref = self.trust_api.get_trust(auth['trust_id'])

        (token_id, token_data) = self.token_provider_api.issue_token(
            user_ref['id'], ['password'], expires_at=expiry,
            project_id=project_id, trust=trust_ref, parent_audit_id=audit_id,
            auth_context=auth_context)
        v2_helper = V2TokenDataHelper()
        token_data = v2_helper.v3_to_v2_token(token_data, token_id)

        # NOTE(wanghong): We consume a trust use only when we are using trusts
        # and have successfully issued a token.
        if CONF.trust.enabled and 'trust_id' in auth:
            self.trust_api.consume_use(auth['trust_id'])

        return token_data

    def _get_auth_token_data(self, user, tenant, metadata, expiry, audit_id):
        return dict(user=user,
                    tenant=tenant,
                    metadata=metadata,
                    expires=expiry,
                    parent_audit_id=audit_id)

    def _token_belongs_to(self, token, belongs_to):
        """Check if the token belongs to the right project.

        :param token: token reference
        :param belongs_to: project ID that the token belongs to

        """
        token_data = token['access']['token']
        if ('tenant' not in token_data or
                token_data['tenant']['id'] != belongs_to):
            raise exception.Unauthorized()

    @controller.v2_deprecated
    @controller.protected()
    def validate_token_head(self, request, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Identical to ``validate_token``, except does not return a response.

        The code in ``keystone.common.wsgi.render_response`` will remove
        the content body.

        """
        v3_token_response = self.token_provider_api.validate_token(token_id)
        v2_helper = V2TokenDataHelper()
        token = v2_helper.v3_to_v2_token(v3_token_response, token_id)
        belongs_to = request.params.get('belongsTo')
        if belongs_to:
            self._token_belongs_to(token, belongs_to)
        return token

    @controller.v2_deprecated
    @controller.protected()
    def validate_token(self, request, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Returns metadata about the token along any associated roles.

        """
        # TODO(ayoung) validate against revocation API
        v3_token_response = self.token_provider_api.validate_token(token_id)
        v2_helper = V2TokenDataHelper()
        token = v2_helper.v3_to_v2_token(v3_token_response, token_id)
        belongs_to = request.params.get('belongsTo')
        if belongs_to:
            self._token_belongs_to(token, belongs_to)
        return token

    @controller.v2_deprecated
    def delete_token(self, request, token_id):
        """Delete a token, effectively invalidating it for authz."""
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(request)
        self.token_provider_api.revoke_token(token_id)

    @controller.v2_deprecated
    @controller.protected()
    def revocation_list(self, request):
        if not CONF.token.revoke_by_id:
            raise exception.Gone()
        tokens = self.token_provider_api.list_revoked_tokens()

        for t in tokens:
            expires = t['expires']
            if expires and isinstance(expires, datetime.datetime):
                t['expires'] = utils.isotime(expires)
        data = {'revoked': tokens}
        json_data = jsonutils.dumps(data)
        signed_text = cms.cms_sign_text(json_data,
                                        CONF.signing.certfile,
                                        CONF.signing.keyfile)

        return {'signed': signed_text}

    @controller.v2_deprecated
    def endpoints(self, request, token_id):
        """Return a list of endpoints available to the token."""
        self.assert_admin(request)

        token_data = self.token_provider_api.validate_token(token_id)
        token_ref = token_model.KeystoneToken(token_id, token_data)

        catalog_ref = None
        if token_ref.project_id:
            catalog_ref = self.catalog_api.get_catalog(
                token_ref.user_id,
                token_ref.project_id)

        return Auth.format_endpoint_list(catalog_ref)

    @classmethod
    def format_endpoint_list(cls, catalog_ref):
        """Format a list of endpoints according to Identity API v2.

        The v2.0 API wants an endpoint list to look like::

            {
                'endpoints': [
                    {
                        'id': $endpoint_id,
                        'name': $SERVICE[name],
                        'type': $SERVICE,
                        'tenantId': $tenant_id,
                        'region': $REGION,
                    }
                ],
                'endpoints_links': [],
            }

        """
        if not catalog_ref:
            return {}

        endpoints = []
        for region_name, region_ref in catalog_ref.items():
            for service_type, service_ref in region_ref.items():
                endpoints.append({
                    'id': service_ref.get('id'),
                    'name': service_ref.get('name'),
                    'type': service_type,
                    'region': region_name,
                    'publicURL': service_ref.get('publicURL'),
                    'internalURL': service_ref.get('internalURL'),
                    'adminURL': service_ref.get('adminURL'),
                })

        return {'endpoints': endpoints, 'endpoints_links': []}


@dependency.requires('resource_api', 'identity_api')
class BaseAuthenticationMethod(object):
    """Common utilities/dependencies for all authentication method classes."""

    def _get_project_id_from_auth(self, auth):
        """Extract and normalize project information from auth dict.

        :param auth: Dictionary representing the authentication request.
        :returns: A string representing the project in the authentication
                  request. If project scope isn't present in the request None
                  is returned.
        """
        project_id = auth.get('tenantId')
        project_name = auth.get('tenantName')

        if project_id:
            if len(project_id) > CONF.max_param_size:
                raise exception.ValidationSizeError(
                    attribute='tenantId', size=CONF.max_param_size
                )
        elif project_name:
            if len(project_name) > CONF.max_param_size:
                raise exception.ValidationSizeError(
                    attribute='tenantName', size=CONF.max_param_size
                )
            if (CONF.resource.project_name_url_safe == 'strict' and
                    utils.is_not_url_safe(project_name)):
                msg = _('Tenant name cannot contain reserved characters.')
                raise exception.Unauthorized(message=msg)
            try:
                project_id = self.resource_api.get_project_by_name(
                    project_name, CONF.identity.default_domain_id
                )['id']
            except exception.ProjectNotFound as e:
                raise exception.Unauthorized(e)
        else:
            project_id = None

        return project_id


@dependency.requires('token_provider_api', 'trust_api')
class TokenAuthenticationMethod(BaseAuthenticationMethod):
    """Authenticate using an existing token."""

    def _restrict_scope(self, token_model_ref):
        """Determine if rescoping is allowed based on the token model.

        :param token_model_ref: `keystone.models.token.KeystoneToken` object.
        """
        # A trust token cannot be used to get another token
        if token_model_ref.trust_scoped:
            raise exception.Forbidden()
        if not CONF.token.allow_rescope_scoped_token:
            # Do not allow conversion from scoped tokens.
            if token_model_ref.project_scoped or token_model_ref.domain_scoped:
                raise exception.Forbidden(action=_('rescope a scoped token'))

    def authenticate(self, request, auth):
        """Try to authenticate using an already existing token.

        :param request: A request object.
        :param auth: Dictionary representing the authentication request.
        :returns: A tuple containing the user reference, project identifier,
                  token expiration, bind information, and original audit
                  information.
        """
        if 'token' not in auth:
            raise exception.ValidationError(
                attribute='token', target='auth')

        if 'id' not in auth['token']:
            raise exception.ValidationError(
                attribute='id', target='token')

        old_token = auth['token']['id']
        if len(old_token) > CONF.max_token_size:
            raise exception.ValidationSizeError(attribute='token',
                                                size=CONF.max_token_size)

        try:
            v3_token_data = self.token_provider_api.validate_token(
                old_token
            )
            # NOTE(lbragstad): Even though we are not using the v2.0 token
            # reference after we translate it in v3_to_v2_token(), we still
            # need to perform that check. We have to do this because
            # v3_to_v2_token will ensure we don't use specific tokens only
            # attainable via v3 to get new tokens on v2.0. For example, an
            # exception would be raised if we passed a federated token to
            # v3_to_v2_token, because federated tokens aren't supported by
            # v2.0 (the same applies to OAuth tokens, domain-scoped tokens,
            # etc..).
            v2_helper = V2TokenDataHelper()
            v2_helper.v3_to_v2_token(v3_token_data, old_token)
            token_model_ref = token_model.KeystoneToken(
                token_id=old_token,
                token_data=v3_token_data
            )
        except exception.NotFound as e:
            raise exception.Unauthorized(e)

        wsgi.validate_token_bind(request.context_dict, token_model_ref)

        self._restrict_scope(token_model_ref)
        user_id = token_model_ref.user_id
        project_id = self._get_project_id_from_auth(auth)

        if not CONF.trust.enabled and 'trust_id' in auth:
            raise exception.Forbidden('Trusts are disabled.')
        elif CONF.trust.enabled and 'trust_id' in auth:
            try:
                trust_ref = self.trust_api.get_trust(auth['trust_id'])
            except exception.TrustNotFound:
                raise exception.Forbidden()
            # If a trust is being used to obtain access to another project and
            # the other project doesn't match the project in the trust, we need
            # to bail because trusts are only good up to a single project.
            if (trust_ref['project_id'] and
                    project_id != trust_ref['project_id']):
                raise exception.Forbidden()

        expiry = token_model_ref.expires
        user_ref = self.identity_api.get_user(user_id)
        bind = token_model_ref.bind
        original_audit_id = token_model_ref.audit_chain_id
        return (user_ref, project_id, expiry, bind, original_audit_id)


class LocalAuthenticationMethod(BaseAuthenticationMethod):
    """Authenticate against a local backend using password credentials."""

    def authenticate(self, request, auth):
        """Try to authenticate against the identity backend.

        :param request: A request object.
        :param auth: Dictionary representing the authentication request.
        :returns: A tuple containing the user reference, project identifier,
                  token expiration, bind information, and original audit
                  information.
        """
        if 'password' not in auth['passwordCredentials']:
            raise exception.ValidationError(
                attribute='password', target='passwordCredentials')

        password = auth['passwordCredentials']['password']
        if password and len(password) > CONF.identity.max_password_length:
            raise exception.ValidationSizeError(
                attribute='password', size=CONF.identity.max_password_length)

        if (not auth['passwordCredentials'].get('userId') and
                not auth['passwordCredentials'].get('username')):
            raise exception.ValidationError(
                attribute='username or userId',
                target='passwordCredentials')

        user_id = auth['passwordCredentials'].get('userId')
        if user_id and len(user_id) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='userId',
                                                size=CONF.max_param_size)

        username = auth['passwordCredentials'].get('username', '')

        if username:
            if len(username) > CONF.max_param_size:
                raise exception.ValidationSizeError(attribute='username',
                                                    size=CONF.max_param_size)
            try:
                user_ref = self.identity_api.get_user_by_name(
                    username, CONF.identity.default_domain_id)
                user_id = user_ref['id']
            except exception.UserNotFound as e:
                raise exception.Unauthorized(e)

        try:
            user_ref = self.identity_api.authenticate(
                request,
                user_id=user_id,
                password=password)
        except AssertionError as e:
            raise exception.Unauthorized(e.args[0])

        project_id = self._get_project_id_from_auth(auth)
        expiry = common.default_expire_time()
        bind = None
        audit_id = None
        return (user_ref, project_id, expiry, bind, audit_id)


class ExternalAuthenticationMethod(BaseAuthenticationMethod):
    """Authenticate using an external authentication method."""

    def authenticate(self, request, auth):
        """Try to authenticate an external user via REMOTE_USER variable.

        :param request: A request object.
        :param auth: Dictionary representing the authentication request.
        :returns: A tuple containing the user reference, project identifier,
                  token expiration, bind information, and original audit
                  information.
        """
        username = request.environ.get('REMOTE_USER')

        if not username:
            raise ExternalAuthNotApplicable()

        try:
            user_ref = self.identity_api.get_user_by_name(
                username, CONF.identity.default_domain_id)
        except exception.UserNotFound as e:
            raise exception.Unauthorized(e)

        tenant_id = self._get_project_id_from_auth(auth)
        expiry = common.default_expire_time()
        bind = None
        if ('kerberos' in CONF.token.bind and
                request.environ.get('AUTH_TYPE', '').lower() == 'negotiate'):
            bind = {'kerberos': username}
        audit_id = None
        return (user_ref, tenant_id, expiry, bind, audit_id)


@dependency.requires('catalog_api', 'resource_api', 'assignment_api',
                     'trust_api', 'identity_api')
class V2TokenDataHelper(object):
    """Create V2 token data."""

    def v3_to_v2_token(self, v3_token_data, token_id):
        """Convert v3 token data into v2.0 token data.

        This method expects a dictionary generated from
        V3TokenDataHelper.get_token_data() and converts it to look like a v2.0
        token dictionary.

        :param v3_token_data: dictionary formatted for v3 tokens
        :param token_id: ID of the token being converted
        :returns: dictionary formatted for v2 tokens
        :raises keystone.exception.Unauthorized: If a specific token type is
            not supported in v2.

        """
        token_data = {}
        # Build v2 token
        v3_token = v3_token_data['token']

        # NOTE(lbragstad): Version 2.0 tokens don't know about any domain other
        # than the default domain specified in the configuration.
        domain_id = v3_token.get('domain', {}).get('id')
        if domain_id and CONF.identity.default_domain_id != domain_id:
            msg = ('Unable to validate domain-scoped tokens outside of the '
                   'default domain')
            raise exception.Unauthorized(msg)

        token = {}
        token['expires'] = v3_token.get('expires_at')
        token['issued_at'] = v3_token.get('issued_at')
        token['audit_ids'] = v3_token.get('audit_ids')
        if v3_token.get('bind'):
            token['bind'] = v3_token['bind']
        token['id'] = token_id

        if 'project' in v3_token:
            # v3 token_data does not contain all tenant attributes
            tenant = self.resource_api.get_project(
                v3_token['project']['id'])
            # Drop domain specific fields since v2 calls are not domain-aware.
            token['tenant'] = controller.V2Controller.v3_to_v2_project(
                tenant)
        token_data['token'] = token

        # Build v2 user
        v3_user = v3_token['user']

        user = controller.V2Controller.v3_to_v2_user(v3_user)

        if 'OS-TRUST:trust' in v3_token:
            v3_trust = v3_token['OS-TRUST:trust']
            # if token is scoped to trust, both trustor and trustee must
            # be in the default domain. Furthermore, the delegated project
            # must also be in the default domain
            msg = _('Non-default domain is not supported')
            if CONF.trust.enabled:
                try:
                    trust_ref = self.trust_api.get_trust(v3_trust['id'])
                except exception.TrustNotFound:
                    raise exception.TokenNotFound(token_id=token_id)
                trustee_user_ref = self.identity_api.get_user(
                    trust_ref['trustee_user_id'])
                if (trustee_user_ref['domain_id'] !=
                        CONF.identity.default_domain_id):
                    raise exception.Unauthorized(msg)
                trustor_user_ref = self.identity_api.get_user(
                    trust_ref['trustor_user_id'])
                if (trustor_user_ref['domain_id'] !=
                        CONF.identity.default_domain_id):
                    raise exception.Unauthorized(msg)
                if trust_ref.get('project_id'):
                    project_ref = self.resource_api.get_project(
                        trust_ref['project_id'])
                    if (project_ref['domain_id'] !=
                            CONF.identity.default_domain_id):
                        raise exception.Unauthorized(msg)

            token_data['trust'] = {
                'impersonation': v3_trust['impersonation'],
                'id': v3_trust['id'],
                'trustee_user_id': v3_trust['trustee_user']['id'],
                'trustor_user_id': v3_trust['trustor_user']['id']
            }

        if 'OS-OAUTH1' in v3_token:
            msg = ('Unable to validate Oauth tokens using the version v2.0 '
                   'API.')
            raise exception.Unauthorized(msg)

        if 'OS-FEDERATION' in v3_token['user']:
            msg = _('Unable to validate Federation tokens using the version '
                    'v2.0 API.')
            raise exception.Unauthorized(msg)

        # Set user roles
        user['roles'] = []
        role_ids = []
        for role in v3_token.get('roles', []):
            role_ids.append(role.pop('id'))
            user['roles'].append(role)
        user['roles_links'] = []

        token_data['user'] = user

        # Get and build v2 service catalog
        token_data['serviceCatalog'] = []
        if 'tenant' in token:
            catalog_ref = self.catalog_api.get_catalog(
                user['id'], token['tenant']['id'])
            if catalog_ref:
                token_data['serviceCatalog'] = self.format_catalog(catalog_ref)

        # Build v2 metadata
        metadata = {}
        metadata['roles'] = role_ids
        # Setting is_admin to keep consistency in v2 response
        metadata['is_admin'] = 0
        token_data['metadata'] = metadata

        return {'access': token_data}

    @classmethod
    def format_catalog(cls, catalog_ref):
        """Munge catalogs from internal to output format.

        Internal catalogs look like::

          {$REGION: {
              {$SERVICE: {
                  $key1: $value1,
                  ...
                  }
              }
          }

        The legacy api wants them to look like::

          [{'name': $SERVICE[name],
            'type': $SERVICE,
            'endpoints': [{
                'tenantId': $tenant_id,
                ...
                'region': $REGION,
                }],
            'endpoints_links': [],
           }]

        """
        if not catalog_ref:
            return []

        services = {}
        for region, region_ref in catalog_ref.items():
            for service, service_ref in region_ref.items():
                new_service_ref = services.get(service, {})
                new_service_ref['name'] = service_ref.pop('name')
                new_service_ref['type'] = service
                new_service_ref['endpoints_links'] = []
                service_ref['region'] = region

                endpoints_ref = new_service_ref.get('endpoints', [])
                endpoints_ref.append(service_ref)

                new_service_ref['endpoints'] = endpoints_ref
                services[service] = new_service_ref

        return list(services.values())
