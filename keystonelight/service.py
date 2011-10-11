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
        logging.info('arg_dict: %s', arg_dict)

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


class TokenAuthMiddleware(wsgi.Middleware):
    def process_request(self, request):
        logging.info('GOT HEADERS %s', request.headers)
        token = request.headers.get('X-Auth-Token')
        logging.info('GOT TOKEN %s', token)
        request.environ['openstack.context'] = {'token': token}


class PostParamsMiddleware(wsgi.Middleware):
    """Middleware to allow method arguments to be passed as POST parameters.

    Filters out the parameters `self`, `context` and anything beginning with
    an underscore.

    """

    def process_request(self, request):
        params_parsed = request.params
        params = {}
        for k, v in params_parsed.iteritems():
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v

        request.environ['openstack.params'] = params


class JsonBodyMiddleware(wsgi.Middleware):
    """Middleware to allow method arguments to be passed as serialized JSON.

    Accepting arguments as JSON is useful for accepting data that may be more
    complex than simple primitives.

    In this case we accept it as urlencoded data under the key 'json' as in
    json=<urlencoded_json> but this could be extended to accept raw JSON
    in the POST body.

    Filters out the parameters `self`, `context` and anything beginning with
    an underscore.

    """

    def process_request(self, request):
        #if 'json' not in request.params:
        #    return

        params_json = request.body
        if not params_json:
            return

        params_parsed = json.loads(params_json)
        params = {}
        for k, v in params_parsed.iteritems():
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v

        request.environ['openstack.params'] = params


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
        tenant, user, extras = self.identity_api.authenticate(context, **kwargs)
        token = self.token_api.create_token(context,
                                            dict(tenant=tenant,
                                                 user=user,
                                                 extras=extras))
        logging.info(token)
        return token

    def get_tenants(self, context):
        token_id = context.get('token')
        logging.info("GET TENANTS %s", token_id)
        token = self.token_api.validate_token(context, token_id)

        return self.identity_api.get_tenants(context,
                                             user_id=token['user'])


class Router(wsgi.Router):
    def __init__(self, options):
        self.options = options
        token_controller = utils.import_object(
                options['token_controller'],
                options=options)
        identity_controller = utils.import_object(
                options['identity_controller'],
                options=options)
        mapper = routes.Mapper()
        mapper.connect('/v2.0/tokens', controller=identity_controller,
                       action='authenticate')
        mapper.connect('/v2.0/tokens/{token_id}', controller=token_controller,
                       action='revoke_token',
                       conditions=dict(method=['DELETE']))
        mapper.connect("/v2.0/tenants", controller=identity_controller,
                    action="get_tenants", conditions=dict(method=["GET"]))
        super(Router, self).__init__(mapper)


class AdminRouter(wsgi.Router):
    def __init__(self, options):
        self.options = options
        token_controller = utils.import_object(
                options['token_controller'],
                options=options)
        identity_controller = utils.import_object(
                options['identity_controller'],
                options=options)
        mapper = routes.Mapper()

        mapper.connect('/v2.0/tokens', controller=identity_controller,
                       action='authenticate')
        mapper.connect('/v2.0/tokens/{token_id}', controller=token_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/v2.0/tokens/{token_id}', controller=token_controller,
                       action='revoke_token',
                       conditions=dict(method=['DELETE']))
        super(AdminRouter, self).__init__(mapper)


def identity_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return Router(conf)

