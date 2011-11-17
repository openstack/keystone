# vim: tabstop=4 shiftwidth=4 softtabstop=4

# this is the web service frontend that emulates keystone
import logging

import routes

from keystonelight import catalog
from keystonelight import identity
from keystonelight import policy
from keystonelight import service
from keystonelight import token
from keystonelight import wsgi


class KeystoneRouter(wsgi.Router):
    def __init__(self, options):
        self.options = options
        self.keystone_controller = KeystoneController(options)

        mapper = routes.Mapper()
        mapper.connect('/',
                       controller=self.keystone_controller,
                       action='noop')
        mapper.connect('/tokens',
                       controller=self.keystone_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/tokens/{token_id}',
                       controller=self.keystone_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tenants',
                       controller=self.keystone_controller,
                       action='tenants_for_token',
                       conditions=dict(method=['GET']))
        super(KeystoneRouter, self).__init__(mapper)


class KeystoneController(service.BaseApplication):
    def __init__(self, options):
        self.options = options
        self.catalog_api = catalog.Manager(options)
        self.identity_api = identity.Manager(options)
        self.token_api = token.Manager(options)
        self.policy_api = policy.Manager(options)
        pass

    def noop(self, context):
        return {}

    def authenticate(self, context, auth=None):
        """Authenticate credentials and return a token.

        Keystone accepts auth as a dict that looks like:

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

            (user_ref, tenant_ref, extras_ref) = \
                    self.identity_api.authenticate(context=context,
                                                   user_id=user_id,
                                                   password=password,
                                                   tenant_id=tenant_id)
            token_ref = self.token_api.create_token(context,
                                                    dict(expires='',
                                                         user=user_ref,
                                                         tenant=tenant_ref,
                                                         extras=extras_ref))
            if tenant_ref:
                catalog_ref = self.catalog_api.get_catalog(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'],
                        extras=extras_ref)
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
            user_ref = old_token_ref['user']

            assert tenant_id in user_ref['tenants']

            tenant_ref = self.identity_api.get_tenant(context=context,
                                                      tenant_id=tenant_id)
            extras_ref = self.identity_api.get_extras(
                    context=context,
                    user_id=user_ref['id'],
                    tenant_id=tenant_ref['id'])
            token_ref = self.token_api.create_token(context,
                                                    dict(expires='',
                                                         user=user_ref,
                                                         tenant=tenant_ref,
                                                         extras=extras_ref))
            catalog_ref = self.catalog_api.get_catalog(
                    context=context,
                    user_id=user_ref['id'],
                    tenant_id=tenant_ref['id'],
                    extras=extras_ref)

        return self._format_authenticate(token_ref, catalog_ref)

    #admin-only
    def validate_token(self, context, token_id, belongs_to=None):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        """
        assert context['is_admin']

        token_ref = self.token_api.get_token(context=context,
                                             token_id=token_id)
        if belongs_to:
            assert token_ref['tenant']['id'] == belongs_to
        return self._format_token(token_ref)

    def tenants_for_token(self, context):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        token_ref = self.token_api.get_token(context=context,
                                             token_id=context['token_id'])
        assert token_ref is not None

        user_ref = token_ref['user']
        tenant_refs = []
        for tenant_id in user_ref['tenants']:
            tenant_refs.append(self.identity_api.get_tenant(
                    context=context,
                    tenant_id=tenant_id))
        return self._format_tenants_for_token(tenant_refs)

    def _format_token(self, token_ref):
        user_ref = token_ref['user']
        extras_ref = token_ref['extras']
        roles = extras_ref.get('roles', [])
        roles_ref = [{'id': 1, 'name': x} for x in roles]
        o = {'access': {'token': {'id': token_ref['id'],
                                  'expires': token_ref['expires']
                                  },
                        'user': {'id': user_ref['id'],
                                 'name': user_ref['name'],
                                 'username': user_ref['name'],
                                 'roles': roles_ref,
                                 'roles_links': extras_ref.get('roles_links',
                                                               [])
                                 }
                        }
             }
        if 'tenant' in token_ref and token_ref['tenant']:
            token_ref['tenant']['enabled'] = True
            o['access']['token']['tenant'] = token_ref['tenant']
        return o

    def _format_authenticate(self, token_ref, catalog_ref):
        o = self._format_token(token_ref)
        o['access']['serviceCatalog'] = self._format_catalog(catalog_ref)
        return o

    def _format_catalog(self, catalog_ref):
        """KeystoneLight catalogs look like:

        {$REGION: {
            {$SERVICE: {
                $key1: $value1,
                ...
                }
            }
        }

        Keystone's look like

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

    def _format_tenants_for_token(self, tenant_refs):
        for x in tenant_refs:
            x['enabled'] = True
        o = {'tenants': tenant_refs,
             'tenants_links': []}
        return o


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return KeystoneRouter(conf)
