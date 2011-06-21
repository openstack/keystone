# vim: tabstop=4 shiftwidth=4 softtabstop=4

# this is the web service frontend

import hflags as flags

from keystonelight import wsgi


FLAGS = flags.FLAGS


class TokenController(wsgi.Controller):
    """Validate and pass through calls to TokenManager."""

    def __init__(self):
        self.token_api = token.Manager()

    def validate_token(self, context, token_id):
        token = self.validate_token(context, token_id)
        return token


class IdentityController(wsgi.Controller):
    """Validate and pass calls through to IdentityManager.

    IdentityManager will also pretty much just pass calls through to
    a specific driver.
    """

    def __init__(self):
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()

    def authenticate(self, context, **kwargs):
        tenant, user, extras = self.identity_api.authenticate(context, **kwargs)
        token = self.token_api.create_token(context,
                                            tenant=tenant,
                                            user=user,
                                            extras=extras)
        return token



class Router(object):
    def __init__(self):
        token_controller = TokenController()
        identity_controller = IdentityController()

        mapper.connect('/v2.0/token', controller=identity_controller,
                       action='authenticate')
        mapper.connect('/v2.0/token/{token_id}', controller=token_controller,
                       action='revoke_token',
                       conditions=dict(method=['DELETE']))


class AdminRouter(object):
    def __init__(self):
        token_controller = TokenController()
        identity_controller = IdentityController()

        mapper.connect('/v2.0/token', controller=identity_controller,
                       action='authenticate')
        mapper.connect('/v2.0/token/{token_id}', controller=token_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/v2.0/token/{token_id}', controller=token_controller,
                       action='revoke_token',
                       conditions=dict(method=['DELETE']))

