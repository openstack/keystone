# vim: tabstop=4 shiftwidth=4 softtabstop=4

import json
import urllib
import urlparse
import uuid

import routes
import webob.dec
import webob.exc

from keystone import catalog
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import token
from keystone.common import logging
from keystone.common import utils
from keystone.common import wsgi


class AdminRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        # Token Operations
        auth_controller = TokenController()
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='delete_token',
                       conditions=dict(method=['DELETE']))
        mapper.connect('/tokens/{token_id}/endpoints',
                       controller=auth_controller,
                       action='endpoints',
                       conditions=dict(method=['GET']))

        # Miscellaneous Operations
        version_controller = VersionController()
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version_info', module='admin/version',
                       conditions=dict(method=['GET']))

        extensions_controller = ExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))
        identity_router = identity.AdminRouter()
        routers = [identity_router]
        super(AdminRouter, self).__init__(mapper, routers)


class PublicRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        noop_controller = NoopController()
        mapper.connect('/',
                       controller=noop_controller,
                       action='noop')

        # Token Operations
        auth_controller = TokenController()
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))

        # Miscellaneous
        version_controller = VersionController()
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version_info',
                       module='service/version',
                       conditions=dict(method=['GET']))

        extensions_controller = ExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))

        identity_router = identity.PublicRouter()
        routers = [identity_router]

        super(PublicRouter, self).__init__(mapper, routers)


class NoopController(wsgi.Application):
    def __init__(self):
        super(NoopController, self).__init__()

    def noop(self, context):
        return {}


class TokenController(wsgi.Application):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(TokenController, self).__init__()

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

        token_id = uuid.uuid4().hex
        if 'passwordCredentials' in auth:
            username = auth['passwordCredentials'].get('username', '')
            password = auth['passwordCredentials'].get('password', '')
            tenant_name = auth.get('tenantName', None)

            if username:
                user_ref = self.identity_api.get_user_by_name(
                        context=context, user_name=username)
                user_id = user_ref['id']
            else:
                user_id = auth['passwordCredentials'].get('userId', None)

            # more compat
            if tenant_name:
                tenant_ref = self.identity_api.get_tenant_by_name(
                        context=context, tenant_name=tenant_name)
                tenant_id = tenant_ref['id']
            else:
                tenant_id = auth.get('tenantId', None)

            try:
                (user_ref, tenant_ref, metadata_ref) = \
                        self.identity_api.authenticate(context=context,
                                                       user_id=user_id,
                                                       password=password,
                                                       tenant_id=tenant_id)

                # If the user is disabled don't allow them to authenticate
                if not user_ref.get('enabled', True):
                    raise webob.exc.HTTPForbidden('User has been disabled')
            except AssertionError as e:
                raise webob.exc.HTTPForbidden(e.message)

            token_ref = self.token_api.create_token(
                    context, token_id, dict(expires='',
                                            id=token_id,
                                            user=user_ref,
                                            tenant=tenant_ref,
                                            metadata=metadata_ref))
            if tenant_ref:
                catalog_ref = self.catalog_api.get_catalog(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'],
                        metadata=metadata_ref)
            else:
                catalog_ref = {}

        elif 'token' in auth:
            token = auth['token'].get('id', None)

            tenant_name = auth.get('tenantName')

            # more compat
            if tenant_name:
                tenant_ref = self.identity_api.get_tenant_by_name(
                        context=context, tenant_name=tenant_name)
                tenant_id = tenant_ref['id']
            else:
                tenant_id = auth.get('tenantId', None)

            old_token_ref = self.token_api.get_token(context=context,
                                                     token_id=token)

            if old_token_ref is None:
                raise exception.Unauthorized()

            user_ref = old_token_ref['user']

            tenants = self.identity_api.get_tenants_for_user(context,
                                                             user_ref['id'])
            if tenant_id:
                assert tenant_id in tenants

            tenant_ref = self.identity_api.get_tenant(context=context,
                                                      tenant_id=tenant_id)
            if tenant_ref:
                metadata_ref = self.identity_api.get_metadata(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'])
                catalog_ref = self.catalog_api.get_catalog(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'],
                        metadata=metadata_ref)
            else:
                metadata_ref = {}
                catalog_ref = {}

            token_ref = self.token_api.create_token(
                    context, token_id, dict(expires='',
                                            id=token_id,
                                            user=user_ref,
                                            tenant=tenant_ref,
                                            metadata=metadata_ref))

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for metadata
        # fill out the roles in the metadata
        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))
        logging.debug('TOKEN_REF %s', token_ref)
        return self._format_authenticate(token_ref, roles_ref, catalog_ref)

    # admin only
    def validate_token(self, context, token_id, belongs_to=None):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        """
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)

        token_ref = self.token_api.get_token(context=context,
                                             token_id=token_id)

        if token_ref is None:
            raise exception.NotFound(target='token')

        if belongs_to:
            assert token_ref['tenant']['id'] == belongs_to

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for metadata
        # fill out the roles in the metadata
        metadata_ref = token_ref['metadata']
        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))
        return self._format_token(token_ref, roles_ref)

    def delete_token(self, context, token_id):
        """Delete a token, effectively invalidating it for authz."""
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)

        self.token_api.delete_token(context=context, token_id=token_id)

    def endpoints(self, context, token_id):
        """Return service catalog endpoints."""
        token_ref = self.token_api.get_token(context=context,
                                             token_id=token_id)
        catalog_ref = self.catalog_api.get_catalog(context,
                                                   token_ref['user']['id'],
                                                   token_ref['tenant']['id'])
        return {'token': {'serviceCatalog': self._format_catalog(catalog_ref)}}

    def _format_authenticate(self, token_ref, roles_ref, catalog_ref):
        o = self._format_token(token_ref, roles_ref)
        o['access']['serviceCatalog'] = self._format_catalog(catalog_ref)
        return o

    def _format_token(self, token_ref, roles_ref):
        user_ref = token_ref['user']
        metadata_ref = token_ref['metadata']
        o = {'access': {'token': {'id': token_ref['id'],
                                  'expires': token_ref['expires']
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


class VersionController(wsgi.Application):
    def __init__(self):
        super(VersionController, self).__init__()

    def get_version_info(self, context, module='version'):
        raise NotImplemented()


class ExtensionsController(wsgi.Application):
    def __init__(self):
        super(ExtensionsController, self).__init__()

    def get_extensions_info(self, context):
        raise NotImplemented()


def public_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return PublicRouter()


def admin_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AdminRouter()
