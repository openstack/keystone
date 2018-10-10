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

import functools
import sys

import flask
from oslo_log import log
from oslo_middleware import healthcheck
import werkzeug.wsgi

import keystone.api
from keystone.server.flask.request_processing import json_body
from keystone.server.flask.request_processing import req_logging

LOG = log.getLogger(__name__)


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

    app = flask.Flask(name)

    # Add core before request functions
    app.before_request(req_logging.log_request_info)
    app.before_request(json_body.json_body_before_request)

    # Add core after request functions
    app.after_request(_add_vary_x_auth_token_header)

    # NOTE(morgan): Configure the Flask Environment for our needs.
    app.config.update(
        # We want to bubble up Flask Exceptions (for now)
        PROPAGATE_EXCEPTIONS=True)

    # TODO(morgan): Remove "API version registration". For now this is kept
    # for ease of conversion (minimal changes)
    keystone.api.discovery.register_version('v3')

    for api in keystone.api.__apis__:
        for api_bp in api.APIs:
            api_bp.instantiate_and_register_to_app(app)

    # Load in Healthcheck and map it to /healthcheck
    hc_app = healthcheck.Healthcheck.app_factory(
        {}, oslo_config_project='keystone')

    # Use the simple form of the dispatch middleware, no extra logic needed
    # for legacy dispatching. This is to mount /healthcheck at a consistent
    # place
    app.wsgi_app = werkzeug.wsgi.DispatcherMiddleware(
        app.wsgi_app,
        {'/healthcheck': hc_app})
    return app
