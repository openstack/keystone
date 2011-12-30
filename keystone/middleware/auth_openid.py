#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
OPENID AUTH MIDDLEWARE - STUB

This WSGI component should perform multiple jobs:
- validate incoming openid claims
- perform all openid interactions with clients
- collect and forward identity information from the openid authentication
    such as user name, groups, etc...

This is an Auth component as per: http://wiki.openstack.org/openstack-authn
"""

import logging
import eventlet
from eventlet import wsgi
import os
from paste.deploy import loadapp
import urlparse
from webob.exc import Request, Response

from keystone.common.bufferedhttp import http_connect_raw as http_connect

logger = logging.getLogger(__name__)  # pylint: disable=C0103

PROTOCOL_NAME = "OpenID Authentication"


class AuthProtocol(object):
    """Auth Middleware that handles authenticating client calls"""

    def __init__(self, app, conf):
        logger.info("Starting the %s component", PROTOCOL_NAME)

        self.conf = conf
        self.app = app
        #if app is set, then we are in a WSGI pipeline and requests get passed
        # on to app. If it is not set, this component should forward requests

        # where to find the OpenStack service (if not in local WSGI chain)
        # these settings are only used if this component is acting as a proxy
        # and the OpenSTack service is running remotely
        self.service_protocol = conf.get('service_protocol', 'http')
        self.service_host = conf.get('service_host', '127.0.0.1')
        self.service_port = int(conf.get('service_port', 8090))
        self.service_url = '%s://%s:%s' % (self.service_protocol,
                                           self.service_host,
                                           self.service_port)
        # used to verify this component with the OpenStack service or PAPIAuth
        self.service_pass = conf.get('service_pass', 'dTpw')

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self.delay_auth_decision = int(conf.get('delay_auth_decision', 0))

    def __call__(self, env, start_response):
        def custom_start_response(status, headers):
            if self.delay_auth_decision:
                headers.append(('WWW-Authenticate', "Basic realm='API Realm'"))
            return start_response(status, headers)

        #TODO(Rasib): PERFORM OPENID AUTH

        #Auth processed, headers added now decide how to pass on the call
        if self.app:
            # Pass to downstream WSGI component
            env['HTTP_AUTHORIZATION'] = "Basic %s" % self.service_pass
            return self.app(env, custom_start_response)

        proxy_headers = []
        proxy_headers['AUTHORIZATION'] = "Basic %s" % self.service_pass
        # We are forwarding to a remote service (no downstream WSGI app)
        req = Request(proxy_headers)
        parsed = urlparse(req.url)
        conn = http_connect(self.service_host, self.service_port, \
             req.method, parsed.path, \
             proxy_headers, \
             ssl=(self.service_protocol == 'https'))
        resp = conn.getresponse()
        data = resp.read()
        #TODO(ziad): use a more sophisticated proxy
        # we are rewriting the headers now
        return Response(status=resp.status, body=data)(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthProtocol(app, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AuthProtocol(None, conf)

if __name__ == "__main__":
    app = loadapp("config:" + \
        os.path.join(os.path.abspath(os.path.dirname(__file__)),
                     os.pardir,
                     os.pardir,
                    "examples/paste/auth_openid.ini"),
                    global_conf={"log_name": "auth_openid.log"})
    wsgi.server(eventlet.listen(('', 8090)), app)
