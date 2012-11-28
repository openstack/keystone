# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import uuid
import routes
import json

from keystone import config
from keystone import catalog
from keystone.common import cms
from keystone.common import logging
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone.openstack.common import timeutils
from keystone import policy
from keystone import token


LOG = logging.getLogger(__name__)


class V3Router(wsgi.ComposingRouter):
    def crud_routes(self, mapper, controller, collection_key, key):
        collection_path = '/%(collection_key)s' % {
            'collection_key': collection_key}
        entity_path = '/%(collection_key)s/{%(key)s_id}' % {
            'collection_key': collection_key,
            'key': key}

        mapper.connect(
            collection_path,
            controller=controller,
            action='create_%s' % key,
            conditions=dict(method=['POST']))
        mapper.connect(
            collection_path,
            controller=controller,
            action='list_%s' % collection_key,
            conditions=dict(method=['GET']))
        mapper.connect(
            entity_path,
            controller=controller,
            action='get_%s' % key,
            conditions=dict(method=['GET']))
        mapper.connect(
            entity_path,
            controller=controller,
            action='update_%s' % key,
            conditions=dict(method=['PATCH']))
        mapper.connect(
            entity_path,
            controller=controller,
            action='delete_%s' % key,
            conditions=dict(method=['DELETE']))

    def __init__(self):
        mapper = routes.Mapper()

        apis = dict(
            catalog_api=catalog.Manager(),
            identity_api=identity.Manager(),
            policy_api=policy.Manager(),
            token_api=token.Manager())

        # Catalog

        self.crud_routes(
            mapper,
            catalog.ServiceControllerV3(**apis),
            'services',
            'service')

        self.crud_routes(
            mapper,
            catalog.EndpointControllerV3(**apis),
            'endpoints',
            'endpoint')

        # Identity

        self.crud_routes(
            mapper,
            identity.DomainControllerV3(**apis),
            'domains',
            'domain')

        project_controller = identity.ProjectControllerV3(**apis)
        self.crud_routes(
            mapper,
            project_controller,
            'projects',
            'project')
        mapper.connect(
            '/users/{user_id}/projects',
            controller=project_controller,
            action='list_user_projects',
            conditions=dict(method=['GET']))

        self.crud_routes(
            mapper,
            identity.UserControllerV3(**apis),
            'users',
            'user')

        self.crud_routes(
            mapper,
            identity.CredentialControllerV3(**apis),
            'credentials',
            'credential')

        role_controller = identity.RoleControllerV3(**apis)
        self.crud_routes(
            mapper,
            role_controller,
            'roles',
            'role')
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='create_grant',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='check_grant',
            conditions=dict(method=['HEAD']))
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles',
            controller=role_controller,
            action='list_grants',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='revoke_grant',
            conditions=dict(method=['DELETE']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='create_grant',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='check_grant',
            conditions=dict(method=['HEAD']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles',
            controller=role_controller,
            action='list_grants',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='revoke_grant',
            conditions=dict(method=['DELETE']))

        # Policy

        policy_controller = policy.PolicyControllerV3(**apis)
        self.crud_routes(
            mapper,
            policy_controller,
            'policies',
            'policy')

        # Token

        """
        # v2.0 LEGACY
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token_head',
                       conditions=dict(method=['HEAD']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='delete_token',
                       conditions=dict(method=['DELETE']))
        mapper.connect('/tokens/{token_id}/endpoints',
                       controller=auth_controller,
                       action='endpoints',
                       conditions=dict(method=['GET']))
        """

        super(V3Router, self).__init__(mapper, [])


class AdminRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        version_controller = VersionController('admin')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version')

        # Token Operations
        auth_controller = TokenController()
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/tokens/revoked',
                       controller=auth_controller,
                       action='revocation_list',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token_head',
                       conditions=dict(method=['HEAD']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='delete_token',
                       conditions=dict(method=['DELETE']))
        mapper.connect('/tokens/{token_id}/endpoints',
                       controller=auth_controller,
                       action='endpoints',
                       conditions=dict(method=['GET']))

        # Certificates used to verify auth tokens
        mapper.connect('/certificates/ca',
                       controller=auth_controller,
                       action='ca_cert',
                       conditions=dict(method=['GET']))

        mapper.connect('/certificates/signing',
                       controller=auth_controller,
                       action='signing_cert',
                       conditions=dict(method=['GET']))

        # Miscellaneous Operations
        extensions_controller = AdminExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))
        mapper.connect('/extensions/{extension_alias}',
                       controller=extensions_controller,
                       action='get_extension_info',
                       conditions=dict(method=['GET']))
        identity_router = identity.AdminRouter()
        routers = [identity_router]
        super(AdminRouter, self).__init__(mapper, routers)


class PublicRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        version_controller = VersionController('public')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version')

        # Token Operations
        auth_controller = TokenController()
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))

        mapper.connect('/certificates/ca',
                       controller=auth_controller,
                       action='ca_cert',
                       conditions=dict(method=['GET']))

        mapper.connect('/certificates/signing',
                       controller=auth_controller,
                       action='signing_cert',
                       conditions=dict(method=['GET']))

        # Miscellaneous
        extensions_controller = PublicExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))
        mapper.connect('/extensions/{extension_alias}',
                       controller=extensions_controller,
                       action='get_extension_info',
                       conditions=dict(method=['GET']))

        identity_router = identity.PublicRouter()
        routers = [identity_router]

        super(PublicRouter, self).__init__(mapper, routers)


class PublicVersionRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()
        version_controller = VersionController('public')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_versions')
        routers = []
        super(PublicVersionRouter, self).__init__(mapper, routers)


class AdminVersionRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()
        version_controller = VersionController('admin')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_versions')
        routers = []
        super(AdminVersionRouter, self).__init__(mapper, routers)


class VersionController(wsgi.Application):
    def __init__(self, version_type):
        self.catalog_api = catalog.Manager()
        self.url_key = '%sURL' % version_type

        super(VersionController, self).__init__()

    def _get_identity_url(self, context):
        catalog_ref = self.catalog_api.get_catalog(context=context,
                                                   user_id=None,
                                                   tenant_id=None)
        for region, region_ref in catalog_ref.iteritems():
            for service, service_ref in region_ref.iteritems():
                if service == 'identity':
                    return service_ref[self.url_key]

        raise exception.NotImplemented()

    def _get_versions_list(self, context):
        """The list of versions is dependent on the context."""
        identity_url = self._get_identity_url(context)
        if not identity_url.endswith('/'):
            identity_url = identity_url + '/'

        versions = {}
        versions['v2.0'] = {
            'id': 'v2.0',
            'status': 'beta',
            'updated': '2011-11-19T00:00:00Z',
            'links': [
                {
                    'rel': 'self',
                    'href': identity_url,
                }, {
                    'rel': 'describedby',
                    'type': 'text/html',
                    'href': 'http://docs.openstack.org/api/openstack-'
                            'identity-service/2.0/content/'
                }, {
                    'rel': 'describedby',
                    'type': 'application/pdf',
                    'href': 'http://docs.openstack.org/api/openstack-'
                            'identity-service/2.0/identity-dev-guide-'
                            '2.0.pdf'
                }
            ],
            'media-types': [
                {
                    'base': 'application/json',
                    'type': 'application/vnd.openstack.identity-v2.0'
                            '+json'
                }, {
                    'base': 'application/xml',
                    'type': 'application/vnd.openstack.identity-v2.0'
                            '+xml'
                }
            ]
        }

        return versions

    def get_versions(self, context):
        versions = self._get_versions_list(context)
        return wsgi.render_response(status=(300, 'Multiple Choices'), body={
            'versions': {
                'values': versions.values()
            }
        })

    def get_version(self, context):
        versions = self._get_versions_list(context)
        return wsgi.render_response(body={
            'version': versions['v2.0']
        })


class NoopController(wsgi.Application):
    def __init__(self):
        super(NoopController, self).__init__()

    def noop(self, context):
        return {}


class ExternalAuthNotApplicable(Exception):
    """External authentication is not applicable"""


class TokenController(wsgi.Application):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(TokenController, self).__init__()

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

        token_data = self._format_token(auth_token_data, roles_ref)

        service_catalog = self._format_catalog(catalog_ref)
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
        return self._format_token(token_ref, roles_ref, catalog_ref)

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

        return self._format_endpoint_list(catalog_ref)

    def _format_authenticate(self, token_ref, roles_ref, catalog_ref):
        o = self._format_token(token_ref, roles_ref)
        o['access']['serviceCatalog'] = self._format_catalog(catalog_ref)
        return o

    def _format_token(self, token_ref, roles_ref, catalog_ref=None):
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
            o['access']['serviceCatalog'] = self._format_catalog(catalog_ref)
        if metadata_ref:
            if 'is_admin' in metadata_ref:
                o['access']['metadata'] = {'is_admin':
                                           metadata_ref['is_admin']}
            else:
                o['access']['metadata'] = {'is_admin': 0}
        if 'roles' in metadata_ref:
                o['access']['metadata']['roles'] = metadata_ref['roles']
        return o

    def _format_catalog(self, catalog_ref):
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
            return {}

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

    def _format_endpoint_list(self, catalog_ref):
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


class ExtensionsController(wsgi.Application):
    """Base extensions controller to be extended by public and admin API's."""

    def __init__(self, extensions=None):
        super(ExtensionsController, self).__init__()

        self.extensions = extensions or {}

    def get_extensions_info(self, context):
        return {'extensions': {'values': self.extensions.values()}}

    def get_extension_info(self, context, extension_alias):
        try:
            return {'extension': self.extensions[extension_alias]}
        except KeyError:
            raise exception.NotFound(target=extension_alias)


class PublicExtensionsController(ExtensionsController):
    pass


class AdminExtensionsController(ExtensionsController):
    def __init__(self, *args, **kwargs):
        super(AdminExtensionsController, self).__init__(*args, **kwargs)

        # TODO(dolph): Extensions should obviously provide this information
        #               themselves, but hardcoding it here allows us to match
        #               the API spec in the short term with minimal complexity.
        self.extensions['OS-KSADM'] = {
            'name': 'Openstack Keystone Admin',
            'namespace': 'http://docs.openstack.org/identity/api/ext/'
                         'OS-KSADM/v1.0',
            'alias': 'OS-KSADM',
            'updated': '2011-08-19T13:25:27-06:00',
            'description': 'Openstack extensions to Keystone v2.0 API '
                           'enabling Admin Operations.',
            'links': [
                {
                    'rel': 'describedby',
                    # TODO(dolph): link needs to be revised after
                    #              bug 928059 merges
                    'type': 'text/html',
                    'href': 'https://github.com/openstack/identity-api',
                }
            ]
        }


@logging.fail_gracefully
def public_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return PublicRouter()


@logging.fail_gracefully
def admin_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AdminRouter()


@logging.fail_gracefully
def public_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return PublicVersionRouter()


@logging.fail_gracefully
def admin_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AdminVersionRouter()


@logging.fail_gracefully
def v3_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return V3Router()
