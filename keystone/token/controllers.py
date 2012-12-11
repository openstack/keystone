import uuid
import json

from keystone import config
from keystone.common import cms
from keystone.common import controller
from keystone.common import logging
from keystone import exception
from keystone.openstack.common import timeutils


LOG = logging.getLogger(__name__)


class ExternalAuthNotApplicable(Exception):
    """External authentication is not applicable"""
    pass


class Auth(controller.V2Controller):
    def ca_cert(self, context, auth=None):
        ca_file = open(config.CONF.signing.ca_certs, 'r')
        data = ca_file.read()
        ca_file.close()
        return data

    def signing_cert(self, context, auth=None):
        cert_file = open(config.CONF.signing.certfile, 'r')
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
            auth_token_data, auth_info = self._authenticate_token(
                context, auth)
        else:
            # Try external authentication
            try:
                auth_token_data, auth_info = self._authenticate_external(
                    context, auth)
            except ExternalAuthNotApplicable:
                # Try local authentication
                auth_token_data, auth_info = self._authenticate_local(
                    context, auth)

        user_ref, tenant_ref, metadata_ref = auth_info

        # If the user is disabled don't allow them to authenticate
        if not user_ref.get('enabled', True):
            msg = 'User is disabled: %s' % user_ref['id']
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

        # If the tenant is disabled don't allow them to authenticate
        if tenant_ref and not tenant_ref.get('enabled', True):
            msg = 'Tenant is disabled: %s' % tenant_ref['id']
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

        if tenant_ref:
            catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'],
                metadata=metadata_ref)
        else:
            catalog_ref = {}

        auth_token_data['id'] = 'placeholder'

        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            role_ref = self.identity_api.get_role(context, role_id)
            roles_ref.append(dict(name=role_ref['name']))

        token_data = Auth.format_token(auth_token_data, roles_ref)

        service_catalog = Auth.format_catalog(catalog_ref)
        token_data['access']['serviceCatalog'] = service_catalog

        if config.CONF.signing.token_format == 'UUID':
            token_id = uuid.uuid4().hex
        elif config.CONF.signing.token_format == 'PKI':
            token_id = cms.cms_sign_token(json.dumps(token_data),
                                          config.CONF.signing.certfile,
                                          config.CONF.signing.keyfile)
        else:
            raise exception.UnexpectedError(
                'Invalid value for token_format: %s.'
                '  Allowed values are PKI or UUID.' %
                config.CONF.signing.token_format)
        try:
            self.token_api.create_token(
                context, token_id, dict(key=token_id,
                                        id=token_id,
                                        expires=auth_token_data['expires'],
                                        user=user_ref,
                                        tenant=tenant_ref,
                                        metadata=metadata_ref))
        except Exception as e:
            # an identical token may have been created already.
            # if so, return the token_data as it is also identical
            try:
                self.token_api.get_token(context=context,
                                         token_id=token_id)
            except exception.TokenNotFound:
                raise e

        token_data['access']['token']['id'] = token_id

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

        try:
            old_token_ref = self.token_api.get_token(context=context,
                                                     token_id=old_token)
        except exception.NotFound as e:
            raise exception.Unauthorized(e)

        user_ref = old_token_ref['user']
        user_id = user_ref['id']

        current_user_ref = self.identity_api.get_user(context=context,
                                                      user_id=user_id)

        tenant_id = self._get_tenant_id_from_auth(context, auth)

        tenant_ref = self._get_tenant_ref(context, user_id, tenant_id)
        metadata_ref = self._get_metadata_ref(context, user_id, tenant_id)

        expiry = old_token_ref['expires']
        auth_token_data = self._get_auth_token_data(current_user_ref,
                                                    tenant_ref,
                                                    metadata_ref,
                                                    expiry)

        return auth_token_data, (current_user_ref, tenant_ref, metadata_ref)

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

        if ("userId" not in auth['passwordCredentials'] and
                "username" not in auth['passwordCredentials']):
            raise exception.ValidationError(
                attribute='username or userId',
                target='passwordCredentials')

        user_id = auth['passwordCredentials'].get('userId', None)
        username = auth['passwordCredentials'].get('username', '')

        if username:
            try:
                user_ref = self.identity_api.get_user_by_name(
                    context=context, user_name=username)
                user_id = user_ref['id']
            except exception.UserNotFound as e:
                raise exception.Unauthorized(e)

        tenant_id = self._get_tenant_id_from_auth(context, auth)

        try:
            auth_info = self.identity_api.authenticate(
                context=context,
                user_id=user_id,
                password=password,
                tenant_id=tenant_id)
        except AssertionError as e:
            raise exception.Unauthorized(e)
        (user_ref, tenant_ref, metadata_ref) = auth_info

        expiry = self.token_api._get_default_expire_time(context=context)
        auth_token_data = self._get_auth_token_data(user_ref,
                                                    tenant_ref,
                                                    metadata_ref,
                                                    expiry)

        return auth_token_data, (user_ref, tenant_ref, metadata_ref)

    def _authenticate_external(self, context, auth):
        """Try to authenticate an external user via REMOTE_USER variable.

        Returns auth_token_data, (user_ref, tenant_ref, metadata_ref)
        """
        if 'REMOTE_USER' not in context:
            raise ExternalAuthNotApplicable()

        username = context['REMOTE_USER']
        try:
            user_ref = self.identity_api.get_user_by_name(
                context=context, user_name=username)
            user_id = user_ref['id']
        except exception.UserNotFound as e:
            raise exception.Unauthorized(e)

        tenant_id = self._get_tenant_id_from_auth(context, auth)

        tenant_ref = self._get_tenant_ref(context, user_id, tenant_id)
        metadata_ref = self._get_metadata_ref(context, user_id, tenant_id)

        expiry = self.token_api._get_default_expire_time(context=context)
        auth_token_data = self._get_auth_token_data(user_ref,
                                                    tenant_ref,
                                                    metadata_ref,
                                                    expiry)

        return auth_token_data, (user_ref, tenant_ref, metadata_ref)

    def _get_auth_token_data(self, user, tenant, metadata, expiry):
        return dict(dict(user=user,
                         tenant=tenant,
                         metadata=metadata,
                         expires=expiry))

    def _get_tenant_id_from_auth(self, context, auth):
        """Extract tenant information from auth dict.

        Returns a valid tenant_id if it exists, or None if not specified.
        """
        tenant_id = auth.get('tenantId', None)
        tenant_name = auth.get('tenantName', None)
        if tenant_name:
            try:
                tenant_ref = self.identity_api.get_tenant_by_name(
                    context=context, tenant_name=tenant_name)
                tenant_id = tenant_ref['id']
            except exception.TenantNotFound as e:
                raise exception.Unauthorized(e)
        return tenant_id

    def _get_tenant_ref(self, context, user_id, tenant_id):
        """Returns the tenant_ref for the user's tenant"""
        tenant_ref = None
        if tenant_id:
            tenants = self.identity_api.get_tenants_for_user(context, user_id)
            if tenant_id not in tenants:
                msg = 'User %s is unauthorized for tenant %s' % (
                    user_id, tenant_id)
                LOG.warning(msg)
                raise exception.Unauthorized(msg)

            try:
                tenant_ref = self.identity_api.get_tenant(context=context,
                                                          tenant_id=tenant_id)
            except exception.TenantNotFound as e:
                exception.Unauthorized(e)
        return tenant_ref

    def _get_metadata_ref(self, context, user_id, tenant_id):
        """Returns the metadata_ref for a user in a tenant"""
        metadata_ref = {}
        if tenant_id:
            try:
                metadata_ref = self.identity_api.get_metadata(
                    context=context,
                    user_id=user_id,
                    tenant_id=tenant_id)
            except exception.MetadataNotFound:
                metadata_ref = {}

        return metadata_ref

    def _get_token_ref(self, context, token_id, belongs_to=None):
        """Returns a token if a valid one exists.

        Optionally, limited to a token owned by a specific tenant.

        """
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)

        if cms.is_ans1_token(token_id):
            data = json.loads(cms.cms_verify(cms.token_to_cms(token_id),
                                             config.CONF.signing.certfile,
                                             config.CONF.signing.ca_certs))
            data['access']['token']['user'] = data['access']['user']
            data['access']['token']['metadata'] = data['access']['metadata']
            if belongs_to:
                assert data['access']['token']['tenant']['id'] == belongs_to
            token_ref = data['access']['token']
        else:
            token_ref = self.token_api.get_token(context=context,
                                                 token_id=token_id)
        return token_ref

    # admin only
    def validate_token_head(self, context, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Identical to ``validate_token``, except does not return a response.

        """
        belongs_to = context['query_string'].get('belongsTo')
        assert self._get_token_ref(context, token_id, belongs_to)

    # admin only
    def validate_token(self, context, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Returns metadata about the token along any associated roles.

        """
        belongs_to = context['query_string'].get('belongsTo')
        token_ref = self._get_token_ref(context, token_id, belongs_to)

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for metadata
        # fill out the roles in the metadata
        metadata_ref = token_ref['metadata']
        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))

        # Get a service catalog if possible
        # This is needed for on-behalf-of requests
        catalog_ref = None
        if token_ref.get('tenant'):
            catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=token_ref['user']['id'],
                tenant_id=token_ref['tenant']['id'],
                metadata=metadata_ref)
        return Auth.format_token(token_ref, roles_ref, catalog_ref)

    def delete_token(self, context, token_id):
        """Delete a token, effectively invalidating it for authz."""
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        self.token_api.delete_token(context=context, token_id=token_id)

    def revocation_list(self, context, auth=None):
        self.assert_admin(context)
        tokens = self.token_api.list_revoked_tokens(context)

        for t in tokens:
            expires = t['expires']
            if not (expires and isinstance(expires, unicode)):
                    t['expires'] = timeutils.isotime(expires)
        data = {'revoked': tokens}
        json_data = json.dumps(data)
        signed_text = cms.cms_sign_text(json_data,
                                        config.CONF.signing.certfile,
                                        config.CONF.signing.keyfile)

        return {'signed': signed_text}

    def endpoints(self, context, token_id):
        """Return a list of endpoints available to the token."""
        self.assert_admin(context)

        token_ref = self._get_token_ref(context, token_id)

        catalog_ref = None
        if token_ref.get('tenant'):
            catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=token_ref['user']['id'],
                tenant_id=token_ref['tenant']['id'],
                metadata=token_ref['metadata'])

        return Auth.format_endpoint_list(catalog_ref)

    @classmethod
    def format_authenticate(cls, token_ref, roles_ref, catalog_ref):
        o = Auth.format_token(token_ref, roles_ref)
        o['access']['serviceCatalog'] = Auth.format_catalog(catalog_ref)
        return o

    @classmethod
    def format_token(cls, token_ref, roles_ref, catalog_ref=None):
        user_ref = token_ref['user']
        metadata_ref = token_ref['metadata']
        expires = token_ref['expires']
        if expires is not None:
            if not isinstance(expires, unicode):
                expires = timeutils.isotime(expires)
        o = {'access': {'token': {'id': token_ref['id'],
                                  'expires': expires,
                                  'issued_at': timeutils.strtime()
                                  },
                        'user': {'id': user_ref['id'],
                                 'name': user_ref['name'],
                                 'username': user_ref['name'],
                                 'roles': roles_ref,
                                 'roles_links': metadata_ref.get('roles_links',
                                                                 [])
                                 }
                        }
             }
        if 'tenant' in token_ref and token_ref['tenant']:
            token_ref['tenant']['enabled'] = True
            o['access']['token']['tenant'] = token_ref['tenant']
        if catalog_ref is not None:
            o['access']['serviceCatalog'] = Auth.format_catalog(catalog_ref)
        if metadata_ref:
            if 'is_admin' in metadata_ref:
                o['access']['metadata'] = {'is_admin':
                                           metadata_ref['is_admin']}
            else:
                o['access']['metadata'] = {'is_admin': 0}
        if 'roles' in metadata_ref:
                o['access']['metadata']['roles'] = metadata_ref['roles']
        return o

    @classmethod
    def format_catalog(cls, catalog_ref):
        """Munge catalogs from internal to output format
        Internal catalogs look like:

        {$REGION: {
            {$SERVICE: {
                $key1: $value1,
                ...
                }
            }
        }

        The legacy api wants them to look like

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
        for region, region_ref in catalog_ref.iteritems():
            for service, service_ref in region_ref.iteritems():
                new_service_ref = services.get(service, {})
                new_service_ref['name'] = service_ref.pop('name')
                new_service_ref['type'] = service
                new_service_ref['endpoints_links'] = []
                service_ref['region'] = region

                endpoints_ref = new_service_ref.get('endpoints', [])
                endpoints_ref.append(service_ref)

                new_service_ref['endpoints'] = endpoints_ref
                services[service] = new_service_ref

        return services.values()

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
