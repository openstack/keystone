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
# Not Yet PEP8 standardized


"""
TOKEN-BASED AUTH MIDDLEWARE

This WSGI component performs multiple jobs:
- it verifies that incoming client requests have valid tokens by verifying
    tokens with the auth service.
- it will reject unauthenticated requests UNLESS it is in 'delegated' mode,
    which means the final decision is delegated to the service
- it will collect and forward identity information from a valid token
    such as user name, groups, etc...

Refer to: http://wiki.openstack.org/openstack-authn


HEADERS
-------
www-authenticate    : only used if this component is being used remotely
HTTP_AUTHORIZATION  : basic auth password used to validate the connection
HTTP_X_AUTHORIZATION: the client identity being passed in
HTTP_X_AUTH_TOKEN   : the client token being passed in
HTTP_X_STORAGE_TOKEN: the client token being passed in (legacy Rackspace use)
                      to support cloud files

"""

import eventlet
from eventlet import wsgi
import json
import os
from paste.deploy import loadapp
import sys
from webob.exc import HTTPUnauthorized, Request


import httplib
import json
from webob.exc import HTTPUnauthorized

from keystone.common.bufferedhttp import http_connect_raw as http_connect


class TokenAuth(object):
    """Auth Middleware that handles token authentication with an auth service"""

    def __init__(self, app, conf):
        print "Starting the Token Auth component"

        self.conf = conf
        self.app = app #if app is not set, this should forward requests

        # where to find the OpenStack service (if not in local WSGI chain)
        self.service_protocol = conf.get('service_protocol', 'http')
        self.service_host = conf.get('service_host', '127.0.0.1')
        self.service_port = int(conf.get('service_port', 8090))
        # used to verify this component with the OpenStack service (or PAPIAuth)
        self.service_pass = conf.get('service_pass', 'dTpw')

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_ip', '127.0.0.1')
        self.auth_port = int(conf.get('auth_port', 8080))
        # used to verify this component with the Auth service
        self.auth_token = conf.get('auth_token', 'dTpw')

        # delegated means we still allow unauthenticated requests through
        self.delegated = int(conf.get('delegated', 0))
        

    def get_admin_auth_token(self, username, password, tenant):
        """
            This function gets an admin auth token to be used by this service to
            validate a user's token.
        """
        headers = {"Content-type": "application/json", "Accept": "text/json"}
        params = {"passwordCredentials": {"username": username,
                                          "password": password,
                                          "tenantId": "1"}}
        conn = httplib.HTTPConnection("%s:%s" \
            % (self.auth_host, self.auth_port))
        conn.request("POST", "/v1.0/token", json.dumps(params), \
            headers=headers)
        response = conn.getresponse()
        data = response.read()
        ret = data
        return ret


    def __call__(self, env, start_response):
        def custom_start_response(status, headers):
            if self.delegated:
                headers.append(('WWW-Authenticate', "Basic realm='API Realm'"))
            return start_response(status, headers)

        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        if token:
            # this request is claiming it has a valid token, let's check
            # with the auth service
            # Step1: Get an admin token
            auth = self.get_admin_auth_token("admin", "secrete", "1")
            admin_token = json.loads(auth)["auth"]["token"]["id"]

            # Step2: validate the user's token using the admin token
            headers = {"Content-type": "application/json",
                        "Accept": "text/json",
                        "X-Auth-Token": self.auth_token}
                        #Khaled's version: "X-Auth-Token": admin_token}
            conn = http_connect(self.auth_host, self.auth_port, 'GET',
                                '/v1.0/token/%s' % token, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            conn.close()

            if not str(resp.status).startswith('20'):
                if self.delegated:
                    env['HTTP_X_IDENTITY_STATUS'] = "Invalid"
                else:
                    # Reject the response & send back the error (not delegated)
                    headers = [('www-authenticate', 'Token realm="Token Auth"')]
                    return HTTPUnauthorized(headers=headers)(env, start_response)
            else:
                # Get user data and return it to service
                dict_response = json.loads(data)
                user = dict_response['auth']['user']['username']
                env['HTTP_X_AUTHORIZATION'] = "Proxy " + user
                if self.delegated:
                    env['HTTP_X_IDENTITY_STATUS'] = "Confirmed"

        if self.app is None:
            req = Request(env)
            # We are forwarding to a remote service
            forward = Request.copy(req)
            forward.host = '%s:%s' % (self.service_host, self.service_port)
            # we need to tell the service who we are by authenticating to it
            if self.delegated:
                env['HTTP_X_IDENTITY_STATUS'] = "Confirmed"
            forward.environ['HTTP_AUTHORIZATION'] = "Basic dTpw"
            service_resp = forward.get_response()
            data = service_resp.read()
            start_response(service_resp.status, service_resp.getheaders())
            return data
        else:
            env['HTTP_AUTHORIZATION'] = "Basic dTpw"
            return self.app(env, custom_start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return TokenAuth(app, conf)
    return auth_filter

def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return TokenAuth(None, conf)

if __name__ == "__main__":
    app = loadapp("config:" + \
        os.path.join(os.path.abspath(os.path.dirname(__file__)),
        "auth_protocol_token.ini"), global_conf={"log_name": "echo.log"})
    wsgi.server(eventlet.listen(('', 8090)), app)
