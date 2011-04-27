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
- it will reject unauthenticated requests UNLESS it is in 'delay_auth_decision'
    mode, which means the final decision is delegated to the downstream WSGI
    component (usually the OpenStack service)
- it will collect and forward identity information from a valid token
    such as user name, groups, etc...

Refer to: http://wiki.openstack.org/openstack-authn


HEADERS
-------
Headers starting with HTTP_ is a standard http header
Headers starting with HTTP_X is an extended http header

> Coming in from initial call from client or customer
HTTP_X_AUTH_TOKEN   : the client token being passed in
HTTP_X_STORAGE_TOKEN: the client token being passed in (legacy Rackspace use)
                      to support cloud files
> Used for communication between components
www-authenticate    : only used if this component is being used remotely
HTTP_AUTHORIZATION  : basic auth password used to validate the connection

> What we add to the request for use by the OpenStack service
HTTP_X_AUTHORIZATION: the client identity being passed in

"""

import eventlet
from eventlet import wsgi
import json
import os
from paste.deploy import loadapp
from urlparse import urlparse
from webob.exc import HTTPUnauthorized
from webob.exc import Request, Response
import httplib

from keystone.common.bufferedhttp import http_connect_raw as http_connect

PROTOCOL_NAME = "Token Authentication"


def _decorate_request_headers(header, value, proxy_headers, env):
        proxy_headers[header] = value
        env["HTTP_%s" % header] = value

class AuthProtocol(object):
    """Auth Middleware that handles authenticating client calls"""

    def _init_protocol_common(self, app, conf):
        """ Common initialization code"""
        print "Starting the %s component" % PROTOCOL_NAME

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
        # used to verify this component with the OpenStack service (or PAPIAuth)
        self.service_pass = conf.get('service_pass', 'dTpw')

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self.delay_auth_decision = int(conf.get('delay_auth_decision', 0))


    def _init_protocol(self, app, conf):
        """ Protocol specific initialization """

         # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_ip', '127.0.0.1')
        self.auth_port = int(conf.get('auth_port', 8080))

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a priviledged call
        self.auth_token = conf.get('auth_token', 'dTpw')


    def __init__(self, app, conf):
        """ Common initialization code """

        #TODO: maybe we rafactor this into a superclass
        self._init_protocol_common(app, conf) #Applies to all protocols
        self._init_protocol(app, conf) #Specific to this protocol


    def get_admin_auth_token(self, username, password, tenant):
        """
            This function gets an admin auth token to be used by this service to
            validate a user's token. Validate_token is a priviledged call so
            it needs to be authenticated by a service that is calling it
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
            if self.delay_auth_decision:
                headers.append(('WWW-Authenticate', "Basic realm='API Realm'"))
            return start_response(status, headers)

        #Prep headers to proxy request to remote service
        proxy_headers = env.copy()
        user = ''

        #Look for token in request
        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        if not token:
            #No token was provided
            if self.delay_auth_decision:
                _decorate_request_headers("X_IDENTITY_STATUS", "Invalid", proxy_headers, env)
            else:
                return HTTPUnauthorized()
        else:
            # this request is claiming it has a valid token, let's check
            # with the auth service
            # Step 1: We need to auth with the keystone service, so get an
            # admin token
            #TODO: Need to properly implement this, where to store creds
            # for now using token from ini
            #auth = self.get_admin_auth_token("admin", "secrete", "1")
            #admin_token = json.loads(auth)["auth"]["token"]["id"]

            # Step 2: validate the user's token with the auth service
            # since this is a priviledged op,m we need to auth ourselves
            # by using an admin token
            headers = {"Content-type": "application/json",
                        "Accept": "text/json",
                        "X-Auth-Token": self.auth_token}
                        ##TODO:we need to figure out how to auth to keystone
                        #since validate_token is a priviledged call
                        #Khaled's version uses creds to get a token
                        # "X-Auth-Token": admin_token}
                        # we're using a test token from the ini file for now
            conn = http_connect(self.auth_host, self.auth_port, 'GET',
                                '/v1.0/token/%s' % token, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            conn.close()


            if not str(resp.status).startswith('20'):
                # Keystone rejected claim
                if self.delay_auth_decision:
                    # Downstream service will receive call still and decide
                    _decorate_request_headers("X_IDENTITY_STATUS", "Invalid", proxy_headers, env)
                else:
                    # Reject the response & send back the error (not delay_auth_decision)
                    return HTTPUnauthorized(headers=headers)(env, start_response)
            else:
                # Valid token. Get user data and put it in to the call
                # so the downstream service can use iot
                dict_response = json.loads(data)
                user = dict_response['auth']['user']['username']
                #TODO(Ziad): add additional details we may need, like tenant and group info
                _decorate_request_headers('X_AUTHORIZATION',"Proxy %s" % user, proxy_headers, env)
                _decorate_request_headers("X_IDENTITY_STATUS", "Confirmed", proxy_headers, env)


        #Token/Auth processed, headers added now decide how to pass on the call
        _decorate_request_headers('AUTHORIZATION', "Basic %s" % self.service_pass, proxy_headers, env)
        if self.app:
            # Pass to downstream WSGI component
            return self.app(env, custom_start_response)
        else:
            # We are forwarding to a remote service (no downstream WSGI app)
            req = Request(proxy_headers)
            parsed = urlparse(req.url)
            conn = http_connect(self.service_host, self.service_port, \
                 req.method, parsed.path, \
                 proxy_headers,\
                 ssl=(self.service_protocol == 'https'))
            resp = conn.getresponse()
            data = resp.read()
            #TODO: use a more sophisticated proxy
            # we are rewriting the headers now
            return Response(status=resp.status, body=data)(proxy_headers, start_response)


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
        "auth_protocol_token.ini"), global_conf={"log_name": "echo.log"})
    wsgi.server(eventlet.listen(('', 8090)), app)
