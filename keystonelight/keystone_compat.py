# vim: tabstop=4 shiftwidth=4 softtabstop=4

# this is the web service frontend that emulates keystone
import logging

import routes

from keystonelight import catalog
from keystonelight import identity
from keystonelight import service
from keystonelight import token
from keystonelight import wsgi


class KeystoneRouter(wsgi.Router):
    def __init__(self, options):
        self.options = options
        self.keystone_controller = KeystoneController(options)


        mapper = routes.Mapper()
        mapper.connect('/v2.0/tokens',
                       controller=self.keystone_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/v2.0/tokens/{token_id}',
                       controller=self.keystone_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/v2.0/tenants',
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
        pass

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
            tenant = auth.get('tenantName', None)

            (user_ref, tenant_ref, extras) = \
                    self.identity_api.authenticate(context=context,
                                                   user_id=username,
                                                   password=password,
                                                   tenant_id=tenant)
            token_ref = self.token_api.create_token(context=context,
                                                    user=user_ref,
                                                    tenant=tenant_ref,
                                                    extras=extras)
            catalog_ref = self.catalog_api.get_catalog(context=context,
                                                       user=user_ref,
                                                       tenant=tenant_ref,
                                                       extras=extras)

        elif 'tokenCredentials' in auth:
            token = auth['tokenCredentials'].get('token', None)
            tenant = auth.get('tenantName')

            old_token_ref = self.token_api.get_token(context=context,
                                                     token_id=token)
            user_ref = old_token_ref['user']

            assert tenant in user_ref['tenants']

            tenant_ref = self.identity_api.get_tenant(context=context,
                                                      tenant_id=tenant)
            extras = self.identity_api.get_extras(
                    context=context,
                    user_id=user_ref['id'],
                    tenant_id=tenant_ref['tenant']['id'])
            token_ref = self.token_api.create_token(context=context,
                                                    user=user_ref,
                                                    tenant=tenant_ref,
                                                    extras=extras)
            catalog_ref = self.catalog_api.get_catalog(context=context,
                                                       user=user_ref,
                                                       tenant=tenant_ref,
                                                       extras=extras)

        return self._format_authenticate(token_ref, catalog_ref)

    def _format_authenticate(sef, token_ref, catalog_ref):
        return {}

    #admin-only
    def validate_token(self, context, token_id, belongs_to=None):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        """
        token_ref = self.token_api.get_token(context=context,
                                             token_id=token_id)
        if belongs_to:
            assert token_ref['tenant']['id'] == belongs_to
        return self._format_token(token_ref)

    def _format_token(self, token_ref):
        return {}

    def tenants_for_token(self, context):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        token_ref = self.token_api.get_token(context=context,
                                             token_id=context['token_id'])
        user_ref = token_ref['user']
        tenant_refs = []
        for tenant_id in user_ref['tenants']:
            tenant_refs.append(self.identity_api.get_tenant(
                    context=context,
                    tenant_id=tenant_id))
        return self._format_tenants_for_token(tenant_refs)

    def _format_tenants_for_token(self, tenant_refs):
        return [{}]


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return KeystoneRouter(conf)
