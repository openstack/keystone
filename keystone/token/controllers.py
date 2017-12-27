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

from keystone.common import controller
from keystone.common import provider_api
from keystone.common import utils
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model
from keystone.token.providers import common


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


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


class BaseAuthenticationMethod(provider_api.ProviderAPIMixin, object):
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
                project_id = PROVIDERS.resource_api.get_project_by_name(
                    project_name, CONF.identity.default_domain_id
                )['id']
            except exception.ProjectNotFound as e:
                raise exception.Unauthorized(e)
        else:
            project_id = None

        return project_id


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
            v3_token_data = PROVIDERS.token_provider_api.validate_token(
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
                trust_ref = PROVIDERS.trust_api.get_trust(auth['trust_id'])
            except exception.TrustNotFound:
                raise exception.Forbidden()
            # If a trust is being used to obtain access to another project and
            # the other project doesn't match the project in the trust, we need
            # to bail because trusts are only good up to a single project.
            if (trust_ref['project_id'] and
                    project_id != trust_ref['project_id']):
                raise exception.Forbidden()

        expiry = token_model_ref.expires
        user_ref = PROVIDERS.identity_api.get_user(user_id)
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
                user_ref = PROVIDERS.identity_api.get_user_by_name(
                    username, CONF.identity.default_domain_id)
                user_id = user_ref['id']
            except exception.UserNotFound as e:
                raise exception.Unauthorized(e)

        try:
            user_ref = PROVIDERS.identity_api.authenticate(
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
            user_ref = PROVIDERS.identity_api.get_user_by_name(
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


class V2TokenDataHelper(provider_api.ProviderAPIMixin, object):
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
            tenant = PROVIDERS.resource_api.get_project(
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
                    trust_ref = PROVIDERS.trust_api.get_trust(v3_trust['id'])
                except exception.TrustNotFound:
                    raise exception.TokenNotFound(token_id=token_id)
                trustee_user_ref = PROVIDERS.identity_api.get_user(
                    trust_ref['trustee_user_id'])
                if (trustee_user_ref['domain_id'] !=
                        CONF.identity.default_domain_id):
                    raise exception.Unauthorized(msg)
                trustor_user_ref = PROVIDERS.identity_api.get_user(
                    trust_ref['trustor_user_id'])
                if (trustor_user_ref['domain_id'] !=
                        CONF.identity.default_domain_id):
                    raise exception.Unauthorized(msg)
                if trust_ref.get('project_id'):
                    project_ref = PROVIDERS.resource_api.get_project(
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
            catalog_ref = PROVIDERS.catalog_api.get_catalog(
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
