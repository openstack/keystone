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

from __future__ import absolute_import

import collections
import functools
import itertools
import sys

import flask
from oslo_log import log
from oslo_middleware import healthcheck
import routes
import werkzeug.wsgi

import keystone.api
from keystone.application_credential import routers as app_cred_routers
from keystone.assignment import routers as assignment_routers
from keystone.auth import routers as auth_routers
from keystone.catalog import routers as catalog_routers
from keystone.common import wsgi as keystone_wsgi
from keystone.contrib.ec2 import routers as ec2_routers
from keystone.contrib.s3 import routers as s3_routers
from keystone.endpoint_policy import routers as endpoint_policy_routers
from keystone.federation import routers as federation_routers
from keystone.identity import routers as identity_routers
from keystone.oauth1 import routers as oauth1_routers
from keystone.policy import routers as policy_routers
from keystone.resource import routers as resource_routers
from keystone.token import _simple_cert as simple_cert_ext

# TODO(morgan): _MOVED_API_PREFIXES to be removed when the legacy dispatch
# support is removed.
_MOVED_API_PREFIXES = frozenset(['credentials', 'OS-OAUTH1', 'OS-REVOKE',
                                 'OS-TRUST', 'limits', 'registered_limits'])
LOG = log.getLogger(__name__)


ALL_API_ROUTERS = [auth_routers,
                   assignment_routers,
                   catalog_routers,
                   identity_routers,
                   app_cred_routers,
                   policy_routers,
                   resource_routers,
                   federation_routers,
                   oauth1_routers,
                   endpoint_policy_routers,
                   ec2_routers,
                   s3_routers,
                   # TODO(morganfainberg): Remove the simple_cert router
                   simple_cert_ext]


def fail_gracefully(f):
    """Log exceptions and aborts."""
    @functools.wraps(f)
    def wrapper(*args, **kw):
        try:
            return f(*args, **kw)
        except Exception as e:
            LOG.debug(e, exc_info=True)

            # exception message is printed to all logs
            LOG.critical(e)
            sys.exit(1)

    return wrapper


class KeystoneDispatcherMiddleware(werkzeug.wsgi.DispatcherMiddleware):
    """Allows one to mount middlewares or applications in a WSGI application.

    This is useful if you want to combine multiple WSGI applications::

        app = DispatcherMiddleware(app, {
            '/app2':        app2,
            '/app3':        app3
        })

    This is a modified version of the werkzeurg.wsgi.DispatchMiddleware to
    handle the "SCRIPT_NAME" and "PATH_INFO" mangling in a way that is
    compatible with the way paste.deploy and routes.Mapper works. For
    Migration from legacy routes.Mapper to native flask blueprints, we are
    treating each subsystem as their own "app".

    This Dispatcher also logs (debug) if we are dispatching a request to
    a non-native flask Mapper.
    """

    @property
    def config(self):
        return self.app.config

    def __call__(self, environ, start_response):
        script = environ.get('PATH_INFO', '')
        original_script_name = environ.get('SCRIPT_NAME', '')
        last_element = ''
        path_info = ''
        while '/' in script:
            if script in self.mounts:
                LOG.debug('Dispatching request to legacy mapper: %s',
                          script)
                app = self.mounts[script]
                # NOTE(morgan): Simply because we're doing something "odd"
                # here and internally routing magically to another "wsgi"
                # router even though we're already deep in the stack we
                # need to re-add the last element pulled off. This is 100%
                # legacy and only applies to the "apps" that make up each
                # keystone subsystem.
                #
                # This middleware is only used in support of the transition
                # process from webob and home-rolled WSGI framework to
                # Flask
                if script.rindex('/') > 0:
                    script, last_element = script.rsplit('/', 1)
                    last_element = '/%s' % last_element
                environ['SCRIPT_NAME'] = original_script_name + script
                # Ensure there is only 1 slash between these items, the
                # mapper gets horribly confused if we have // in there,
                # which occasionally. As this is temporary to dispatch
                # to the Legacy mapper, fix the string until we no longer
                # need this logic.
                environ['PATH_INFO'] = '%s/%s' % (last_element.rstrip('/'),
                                                  path_info.strip('/'))
                break
            script, last_item = script.rsplit('/', 1)
            path_info = '/%s%s' % (last_item, path_info)
        else:
            app = self.mounts.get(script, self.app)
            if app != self.app:
                LOG.debug('Dispatching (fallthrough) request to legacy '
                          'mapper: %s', script)
            else:
                LOG.debug('Dispatching back to Flask native app.')
            environ['SCRIPT_NAME'] = original_script_name + script
            environ['PATH_INFO'] = path_info

        # NOTE(morgan): remove extra trailing slashes so the mapper can do the
        # right thing and get the requests mapped to the right place. For
        # example, "/v3/projects/" is not the same as "/v3/projects". We do not
        # want to blindly rstrip for the case of '/'.
        if environ['PATH_INFO'][-1] == '/' and len(environ['PATH_INFO']) > 1:
            environ['PATH_INFO'] = environ['PATH_INFO'][0:-1]
        LOG.debug('SCRIPT_NAME: `%s`, PATH_INFO: `%s`',
                  environ['SCRIPT_NAME'], environ['PATH_INFO'])
        return app(environ, start_response)


class _ComposibleRouterStub(keystone_wsgi.ComposableRouter):
    def __init__(self, routers):
        self._routers = routers


def _add_vary_x_auth_token_header(response):
    # Add the expected Vary Header, this is run after every request in the
    # response-phase
    response.headers['Vary'] = 'X-Auth-Token'
    return response


@fail_gracefully
def application_factory(name='public'):
    if name not in ('admin', 'public'):
        raise RuntimeError('Application name (for base_url lookup) must be '
                           'either `admin` or `public`.')

    # NOTE(morgan): The Flask App actually dispatches nothing until we migrate
    # some routers to Flask-Blueprints, it is simply a placeholder.
    app = flask.Flask(name)
    app.after_request(_add_vary_x_auth_token_header)

    # NOTE(morgan): Configure the Flask Environment for our needs.
    app.config.update(
        # We want to bubble up Flask Exceptions (for now)
        PROPAGATE_EXCEPTIONS=True)

    # TODO(morgan): Convert Subsystems over to Flask-Native, for now, we simply
    # dispatch to another "application" [e.g "keystone"]
    # NOTE(morgan): as each router is converted to flask-native blueprint,
    # remove from this list. WARNING ORDER MATTERS; ordered dict used to
    # ensure sane ordering of the routers in the legacy-dispatch model.
    dispatch_map = collections.OrderedDict()

    # Load in Healthcheck and map it to /healthcheck
    hc_app = healthcheck.Healthcheck.app_factory(
        {}, oslo_config_project='keystone')
    dispatch_map['/healthcheck'] = hc_app

    # More legacy code to instantiate all the magic for the dispatchers.
    # The move to blueprints (FLASK) will allow this to be eliminated.
    _routers = []
    sub_routers = []
    mapper = routes.Mapper()
    for api_routers in ALL_API_ROUTERS:
        moved_found = [pfx for
                       pfx in getattr(api_routers, '_path_prefixes', [])
                       if pfx in _MOVED_API_PREFIXES]
        if moved_found:
            raise RuntimeError('An API Router is trying to register path '
                               'prefix(s) `%(pfx)s` that is handled by the '
                               'native Flask app. Keystone cannot '
                               'start.' %
                               {'pfx': ', '.join([p for p in moved_found])})

        routers_instance = api_routers.Routers()
        _routers.append(routers_instance)
        routers_instance.append_v3_routers(mapper, sub_routers)

    # TODO(morgan): Remove "API version registration". For now this is kept
    # for ease of conversion (minimal changes)
    keystone.api.discovery.register_version('v3')

    # NOTE(morgan): We add in all the keystone.api blueprints here, this
    # replaces (as they are implemented) the legacy dispatcher work.
    for api in keystone.api.__apis__:
        for api_bp in api.APIs:
            api_bp.instantiate_and_register_to_app(app)

    # Build and construct the dispatching for the Legacy dispatching model
    sub_routers.append(_ComposibleRouterStub(_routers))
    legacy_dispatcher = keystone_wsgi.ComposingRouter(mapper, sub_routers)

    for pfx in itertools.chain(*[rtr.Routers._path_prefixes for
                                 rtr in ALL_API_ROUTERS]):
        dispatch_map['/v3/%s' % pfx] = legacy_dispatcher

    app.wsgi_app = KeystoneDispatcherMiddleware(
        app.wsgi_app,
        dispatch_map)
    return app
