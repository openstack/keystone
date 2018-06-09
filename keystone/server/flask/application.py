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


from keystone.application_credential import routers as app_cred_routers
from keystone.assignment import routers as assignment_routers
from keystone.auth import routers as auth_routers
from keystone.catalog import routers as catalog_routers
from keystone.common import wsgi as keystone_wsgi
from keystone.contrib.ec2 import routers as ec2_routers
from keystone.contrib.s3 import routers as s3_routers
from keystone.credential import routers as credential_routers
from keystone.endpoint_policy import routers as endpoint_policy_routers
from keystone.federation import routers as federation_routers
from keystone.identity import routers as identity_routers
from keystone.limit import routers as limit_routers
from keystone.oauth1 import routers as oauth1_routers
from keystone.policy import routers as policy_routers
from keystone.resource import routers as resource_routers
from keystone.revoke import routers as revoke_routers
from keystone.token import _simple_cert as simple_cert_ext
from keystone.trust import routers as trust_routers
from keystone.version import controllers as version_controllers
from keystone.version import routers as version_routers


LOG = log.getLogger(__name__)


ALL_API_ROUTERS = [auth_routers,
                   assignment_routers,
                   catalog_routers,
                   credential_routers,
                   identity_routers,
                   app_cred_routers,
                   limit_routers,
                   policy_routers,
                   resource_routers,
                   trust_routers,
                   revoke_routers,
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

    def __call__(self, environ, start_response):
        script = environ.get('PATH_INFO', '')
        original_script_name = environ.get('SCRIPT_NAME', '')
        last_element = ''
        path_info = ''
        # NOTE(morgan): Special Case root documents per version, these *are*
        # special and should never fall through to the legacy dispatcher, they
        # must be handled by the version dispatchers.
        if script not in ('/v3', '/', '/v2.0'):
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
        else:
            # Special casing for version discovery docs.
            # REMOVE THIS SPECIAL CASE WHEN VERSION DISCOVERY GOES FLASK NATIVE
            app = self.mounts.get(script, self.app)
            if script == '/':
                # ROOT Version Discovery Doc
                LOG.debug('Dispatching to legacy root mapper for root version '
                          'discovery document: `%s`', script)
                environ['SCRIPT_NAME'] = '/'
                environ['PATH_INFO'] = '/'
            elif script == '/v3':
                LOG.debug('Dispatching to legacy mapper for v3 version '
                          'discovery document: `%s`', script)
                # V3 Version Discovery Doc
                environ['SCRIPT_NAME'] = '/v3'
                environ['PATH_INFO'] = '/'
            else:
                LOG.debug('Dispatching to flask native app for version '
                          'discovery document: `%s`', script)

        # NOTE(morgan): remove extra trailing slashes so the mapper can do the
        # right thing and get the requests mapped to the right place. For
        # example, "/v3/projects/" is not the same as "/v3/projects". We do not
        # want to blindly rstrip for the case of '/'.
        if environ['PATH_INFO'][-1] == '/' and len(environ['PATH_INFO']) > 1:
            environ['PATH_INFO'] = environ['PATH_INFO'][0:-1]
        LOG.debug('SCRIPT_NAME: `%s`, PATH_INFO: `%s`',
                  environ['SCRIPT_NAME'], environ['PATH_INFO'])
        return app(environ, start_response)


@fail_gracefully
def application_factory(name='public'):
    if name not in ('admin', 'public'):
        raise RuntimeError('Application name (for base_url lookup) must be '
                           'either `admin` or `public`.')

    # NOTE(morgan): The Flask App actually dispatches nothing until we migrate
    # some routers to Flask-Blueprints, it is simply a placeholder.
    app = flask.Flask(name)

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
        routers_instance = api_routers.Routers()
        _routers.append(routers_instance)
        routers_instance.append_v3_routers(mapper, sub_routers)

    # Add in the v3 version api
    sub_routers.append(version_routers.VersionV3('public', _routers))
    version_controllers.register_version('v3')
    legacy_dispatcher = keystone_wsgi.ComposingRouter(mapper, sub_routers)

    for pfx in itertools.chain(*[rtr.Routers._path_prefixes for
                                 rtr in ALL_API_ROUTERS]):
        dispatch_map['/v3/%s' % pfx] = legacy_dispatcher

    # NOTE(morgan) Move the version routers to Flask Native First! It will
    # not work well due to how the dispatcher works unless this is first,
    # otherwise nothing falls through to the native flask app.
    dispatch_map['/v3'] = legacy_dispatcher

    # NOTE(morgan): The Root Version Discovery Document is special and needs
    # it's own mapper/router since the v3 one assumes it owns the root due
    # to legacy paste-isms where /v3 would be routed to APP=/v3, PATH=/
    root_version_disc_mapper = routes.Mapper()
    root_version_disc_router = version_routers.Versions(name)
    root_dispatcher = keystone_wsgi.ComposingRouter(
        root_version_disc_mapper, [root_version_disc_router])
    dispatch_map['/'] = root_dispatcher

    application = KeystoneDispatcherMiddleware(
        app,
        dispatch_map)
    return application
