# vim: tabstop=4 shiftwidth=4 softtabstop=4

# this is the web service frontend

import json
import logging

import routes
import webob.dec
import webob.exc

from keystonelight import identity
from keystonelight import token
from keystonelight import utils
from keystonelight import wsgi


class BaseApplication(wsgi.Application):
    @webob.dec.wsgify
    def __call__(self, req):
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict['action']
        del arg_dict['action']
        del arg_dict['controller']
        logging.debug('arg_dict: %s', arg_dict)

        context = req.environ.get('openstack.context', {})
        # allow middleware up the stack to override the params
        params = {}
        if 'openstack.params' in req.environ:
            params = req.environ['openstack.params']
        params.update(arg_dict)

        # TODO(termie): do some basic normalization on methods
        method = getattr(self, action)

        # NOTE(vish): make sure we have no unicode keys for py2.6.
        params = dict([(str(k), v) for (k, v) in params.iteritems()])
        result = method(context, **params)

        if result is None or type(result) is str or type(result) is unicode:
            return result

        return json.dumps(result)


class TokenController(BaseApplication):
    """Validate and pass through calls to TokenManager."""

    def __init__(self, options):
        self.token_api = token.Manager(options=options)
        self.options = options

    def validate_token(self, context, token_id):
        token_info = self.token_api.validate_token(context, token_id)
        if not token_info:
            raise webob.exc.HTTPUnauthorized()
        return token_info


class IdentityController(BaseApplication):
    """Validate and pass calls through to IdentityManager.

    IdentityManager will also pretty much just pass calls through to
    a specific driver.
    """

    def __init__(self, options):
        self.identity_api = identity.Manager(options=options)
        self.token_api = token.Manager(options=options)
        self.options = options

    def authenticate(self, context, **kwargs):
        user_ref, tenant_ref, extras_ref = self.identity_api.authenticate(
                context, **kwargs)
        # TODO(termie): strip password from return values
        token_ref = self.token_api.create_token(context,
                                                dict(tenant=tenant_ref,
                                                     user=user_ref,
                                                     extras=extras_ref))
        logging.debug('TOKEN: %s', token_ref)
        return token_ref

    def get_tenants(self, context):
        token_id = context.get('token_id')
        token_ref = self.token_api.get_token(context, token_id)
        assert token_ref
        tenants_ref = []
        for tenant_id in token_ref['user']['tenants']:
            tenants_ref.append(self.identity_api.get_tenant(context,
                                                            tenant_id))

        return tenants_ref


class Router(wsgi.Router):
    def __init__(self, options):
        self.options = options
        self.identity_controller = IdentityController(options)
        self.token_controller = TokenController(options)
        mapper = routes.Mapper()
        mapper.connect('/tokens',
                       controller=self.identity_controller,
                       action='authenticate')
        mapper.connect('/tokens/{token_id}',
                       controller=self.token_controller,
                       action='revoke_token',
                       conditions=dict(method=['DELETE']))
        mapper.connect("/tenants",
                       controller=self.identity_controller,
                       action="get_tenants",
                       conditions=dict(method=["GET"]))
        super(Router, self).__init__(mapper)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return Router(conf)
