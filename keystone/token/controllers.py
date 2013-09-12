# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import json

from keystone.common import cms
from keystone.common import controller
from keystone.common import dependency
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging
from keystone.openstack.common import timeutils
from keystone.token import core


CONF = config.CONF
LOG = logging.getLogger(__name__)
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class ExternalAuthNotApplicable(Exception):
    """External authentication is not applicable."""
    pass


@dependency.requires('token_provider_api')
class Auth(controller.V2Controller):
    def ca_cert(self, context, auth=None):
        ca_file = open(CONF.signing.ca_certs, 'r')
        data = ca_file.read()
        ca_file.close()
        return data

    def signing_cert(self, context, auth=None):
        cert_file = open(CONF.signing.certfile, 'r')
        data = cert_file.read()
        cert_file.close()
        return data

    def authenticate(self, context, auth=None):
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

        if auth is None:
            raise exception.ValidationError(attribute='auth',
                                            target='request body')

        auth_token_data = None

        if "token" in auth:
            # Try to authenticate using a token
            auth_info = self._authenticate_token(
                context, auth)
        else:
            # Try external authentication
            try:
                auth_info = self._authenticate_external(
                    context, auth)
            except ExternalAuthNotApplicable:
                # Try local authentication
                auth_info = self._authenticate_local(
                    context, auth)

        user_ref, tenant_ref, metadata_ref, expiry, bind = auth_info
        core.validate_auth_info(self, user_ref, tenant_ref)
        # NOTE(morganfainberg): Make sure the data is in correct form since it
        # might be consumed external to Keystone and this is a v2.0 controller.
        # The user_ref is encoded into the auth_token_data which is returned as
        # part of the token data. The token provider doesn't care about the
        # format.
        user_ref = self.identity_api.v3_to_v2_user(user_ref)
        if tenant_ref:
            tenant_ref = self.filter_domain_id(tenant_ref)
        auth_token_data = self._get_auth_token_data(user_ref,
                                                    tenant_ref,
                                                    metadata_ref,
                                                    expiry)

        if tenant_ref:
            catalog_ref = self.catalog_api.get_catalog(
                user_ref['id'], tenant_ref['id'], metadata_ref)
        else:
            catalog_ref = {}

        auth_token_data['id'] = 'placeholder'
        if bind:
            auth_token_data['bind'] = bind

        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            role_ref = self.identity_api.get_role(role_id)
            roles_ref.append(dict(name=role_ref['name']))

        (token_id, token_data) = self.token_provider_api.issue_v2_token(
            auth_token_data, roles_ref=roles_ref, catalog_ref=catalog_ref)
        return token_data

    def _authenticate_token(self, context, auth):
        """Try to authenticate using an already existing token.

        Returns auth_token_data, (user_ref, tenant_ref, metadata_ref)
        """
        if 'token' not in auth:
            raise exception.ValidationError(
                attribute='token', target='auth')

        if "id" not in auth['token']:
            raise exception.ValidationError(
                attribute="id", target="token")

        old_token = auth['token']['id']
        if len(old_token) > CONF.max_token_size:
            raise exception.ValidationSizeError(attribute='token',
                                                size=CONF.max_token_size)

        try:
            old_token_ref = self.token_api.get_token(old_token)
        except exception.NotFound as e:
            raise exception.Unauthorized(e)

        wsgi.validate_token_bind(context, old_token_ref)

        #A trust token cannot be used to get another token
        if 'trust' in old_token_ref:
            raise exception.Forbidden()
        if 'trust_id' in old_token_ref['metadata']:
            raise exception.Forbidden()

        user_ref = old_token_ref['user']
        user_id = user_ref['id']
        if not CONF.trust.enabled and 'trust_id' in auth:
            raise exception.Forbidden('Trusts are disabled.')
        elif CONF.trust.enabled and 'trust_id' in auth:
            trust_ref = self.trust_api.get_trust(auth['trust_id'])
            if trust_ref is None:
                raise exception.Forbidden()
            if user_id != trust_ref['trustee_user_id']:
                raise exception.Forbidden()
            if ('expires' in trust_ref) and (trust_ref['expires']):
                expiry = trust_ref['expires']
                if expiry < timeutils.parse_isotime(timeutils.isotime()):
                    raise exception.Forbidden()()
            user_id = trust_ref['trustor_user_id']
            trustor_user_ref = self.identity_api.get_user(
                trust_ref['trustor_user_id'])
            if not trustor_user_ref['enabled']:
                raise exception.Forbidden()()
            trustee_user_ref = self.identity_api.get_user(
                trust_ref['trustee_user_id'])
            if not trustee_user_ref['enabled']:
                raise exception.Forbidden()()
            if trust_ref['impersonation'] == 'True':
                current_user_ref = trustor_user_ref
            else:
                current_user_ref = trustee_user_ref

        else:
            current_user_ref = self.identity_api.get_user(user_id)

        metadata_ref = {}
        tenant_id = self._get_project_id_from_auth(auth)
        tenant_ref, metadata_ref['roles'] = self._get_project_roles_and_ref(
            user_id, tenant_id)

        expiry = old_token_ref['expires']
        if CONF.trust.enabled and 'trust_id' in auth:
            trust_id = auth['trust_id']
            trust_roles = []
            for role in trust_ref['roles']:
                if 'roles' not in metadata_ref:
                    raise exception.Forbidden()()
                if role['id'] in metadata_ref['roles']:
                    trust_roles.append(role['id'])
                else:
                    raise exception.Forbidden()
            if 'expiry' in trust_ref and trust_ref['expiry']:
                trust_expiry = timeutils.parse_isotime(trust_ref['expiry'])
                if trust_expiry < expiry:
                    expiry = trust_expiry
            metadata_ref['roles'] = trust_roles
            metadata_ref['trustee_user_id'] = trust_ref['trustee_user_id']
            metadata_ref['trust_id'] = trust_id

        bind = old_token_ref.get('bind', None)

        return (current_user_ref, tenant_ref, metadata_ref, expiry, bind)

    def _authenticate_local(self, context, auth):
        """Try to authenticate against the identity backend.

        Returns auth_token_data, (user_ref, tenant_ref, metadata_ref)
        """
        if 'passwordCredentials' not in auth:
            raise exception.ValidationError(
                attribute='passwordCredentials', target='auth')

        if "password" not in auth['passwordCredentials']:
            raise exception.ValidationError(
                attribute='password', target='passwordCredentials')

        password = auth['passwordCredentials']['password']
        if password and len(password) > CONF.identity.max_password_length:
            raise exception.ValidationSizeError(
                attribute='password', size=CONF.identity.max_password_length)

        if ("userId" not in auth['passwordCredentials'] and
                "username" not in auth['passwordCredentials']):
            raise exception.ValidationError(
                attribute='username or userId',
                target='passwordCredentials')

        user_id = auth['passwordCredentials'].get('userId', None)
        if user_id and len(user_id) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='userId',
                                                size=CONF.max_param_size)

        username = auth['passwordCredentials'].get('username', '')
        if len(username) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='username',
                                                size=CONF.max_param_size)

        if username:
            try:
                user_ref = self.identity_api.get_user_by_name(
                    username, DEFAULT_DOMAIN_ID)
                user_id = user_ref['id']
            except exception.UserNotFound as e:
                raise exception.Unauthorized(e)

        try:
            user_ref = self.identity_api.authenticate(
                user_id=user_id,
                password=password)
        except AssertionError as e:
            raise exception.Unauthorized(e)

        metadata_ref = {}
        tenant_id = self._get_project_id_from_auth(auth)
        tenant_ref, metadata_ref['roles'] = self._get_project_roles_and_ref(
            user_id, tenant_id)

        expiry = core.default_expire_time()
        return (user_ref, tenant_ref, metadata_ref, expiry, None)

    def _authenticate_external(self, context, auth):
        """Try to authenticate an external user via REMOTE_USER variable.

        Returns auth_token_data, (user_ref, tenant_ref, metadata_ref)
        """
        if 'REMOTE_USER' not in context:
            raise ExternalAuthNotApplicable()

        #NOTE(jamielennox): xml and json differ and get confused about what
        # empty auth should look like so just reset it.
        if not auth:
            auth = {}

        username = context['REMOTE_USER']
        try:
            user_ref = self.identity_api.get_user_by_name(
                username, DEFAULT_DOMAIN_ID)
            user_id = user_ref['id']
        except exception.UserNotFound as e:
            raise exception.Unauthorized(e)

        metadata_ref = {}
        tenant_id = self._get_project_id_from_auth(auth)
        tenant_ref, metadata_ref['roles'] = self._get_project_roles_and_ref(
            user_id, tenant_id)

        expiry = core.default_expire_time()
        bind = None
        if ('kerberos' in CONF.token.bind and
                context.get('AUTH_TYPE', '').lower() == 'negotiate'):
            bind = {'kerberos': username}

        return (user_ref, tenant_ref, metadata_ref, expiry, bind)

    def _get_auth_token_data(self, user, tenant, metadata, expiry):
        return dict(user=user,
                    tenant=tenant,
                    metadata=metadata,
                    expires=expiry)

    def _get_project_id_from_auth(self, auth):
        """Extract tenant information from auth dict.

        Returns a valid tenant_id if it exists, or None if not specified.
        """
        tenant_id = auth.get('tenantId', None)
        if tenant_id and len(tenant_id) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='tenantId',
                                                size=CONF.max_param_size)

        tenant_name = auth.get('tenantName', None)
        if tenant_name and len(tenant_name) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='tenantName',
                                                size=CONF.max_param_size)

        if tenant_name:
            try:
                tenant_ref = self.identity_api.get_project_by_name(
                    tenant_name, DEFAULT_DOMAIN_ID)
                tenant_id = tenant_ref['id']
            except exception.ProjectNotFound as e:
                raise exception.Unauthorized(e)
        return tenant_id

    def _get_domain_id_from_auth(self, auth):
        """Extract domain information from v3 auth dict.

        Returns a valid domain_id if it exists, or None if not specified.
        """
        # FIXME(henry-nash): This is a placeholder that needs to be
        # only called in the v3 context, and the auth.get calls
        # converted to the v3 format
        domain_id = auth.get('domainId', None)
        domain_name = auth.get('domainName', None)
        if domain_name:
            try:
                domain_ref = self.identity_api._get_domain_by_name(
                    domain_name)
                domain_id = domain_ref['id']
            except exception.DomainNotFound as e:
                raise exception.Unauthorized(e)
        return domain_id

    def _get_project_roles_and_ref(self, user_id, tenant_id):
        """Returns the project roles for this user, and the project ref."""

        tenant_ref = None
        role_list = []
        if tenant_id:
            try:
                tenant_ref = self.identity_api.get_project(tenant_id)
                role_list = self.identity_api.get_roles_for_user_and_project(
                    user_id, tenant_id)
            except exception.ProjectNotFound:
                pass

            if not role_list:
                msg = _('User %(u_id)s is unauthorized for tenant %(t_id)s')
                msg = msg % {'u_id': user_id, 't_id': tenant_id}
                LOG.warning(msg)
                raise exception.Unauthorized(msg)

        return (tenant_ref, role_list)

    def _get_token_ref(self, token_id, belongs_to=None):
        """Returns a token if a valid one exists.

        Optionally, limited to a token owned by a specific tenant.

        """
        data = self.token_api.get_token(token_id)
        if belongs_to:
            if data.get('tenant') is None:
                raise exception.Unauthorized(
                    _('Token does not belong to specified tenant.'))
            if data['tenant'].get('id') != belongs_to:
                raise exception.Unauthorized(
                    _('Token does not belong to specified tenant.'))
        return data

    @controller.protected()
    def validate_token_head(self, context, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Identical to ``validate_token``, except does not return a response.

        """
        belongs_to = context['query_string'].get('belongsTo')
        self.token_provider_api.check_v2_token(token_id, belongs_to)

    @controller.protected()
    def validate_token(self, context, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Returns metadata about the token along any associated roles.

        """
        belongs_to = context['query_string'].get('belongsTo')
        return self.token_provider_api.validate_v2_token(token_id, belongs_to)

    def delete_token(self, context, token_id):
        """Delete a token, effectively invalidating it for authz."""
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        self.token_api.delete_token(token_id)

    @controller.protected()
    def revocation_list(self, context, auth=None):
        tokens = self.token_api.list_revoked_tokens()

        for t in tokens:
            expires = t['expires']
            if not (expires and isinstance(expires, unicode)):
                    t['expires'] = timeutils.isotime(expires)
        data = {'revoked': tokens}
        json_data = json.dumps(data)
        signed_text = cms.cms_sign_text(json_data,
                                        CONF.signing.certfile,
                                        CONF.signing.keyfile)

        return {'signed': signed_text}

    def endpoints(self, context, token_id):
        """Return a list of endpoints available to the token."""
        self.assert_admin(context)

        token_ref = self._get_token_ref(token_id)

        catalog_ref = None
        if token_ref.get('tenant'):
            catalog_ref = self.catalog_api.get_catalog(
                token_ref['user']['id'],
                token_ref['tenant']['id'],
                token_ref['metadata'])

        return Auth.format_endpoint_list(catalog_ref)

    @classmethod
    def format_endpoint_list(cls, catalog_ref):
        """Formats a list of endpoints according to Identity API v2.

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
        for region_name, region_ref in catalog_ref.iteritems():
            for service_type, service_ref in region_ref.iteritems():
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
