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
RACKSPACE LEGACY AUTH - STUB

This WSGI component
- transforms rackspace auth header credentials to keystone credentials
and makes an authentication call on keystone.- transforms response it
receives into custom headers defined in properties and returns
the response.
"""
import os
import sys
import optparse
import httplib
import json
import ast

from webob.exc import Request, Response
from paste.deploy import loadapp
from webob.exc import HTTPUnauthorized, HTTPInternalServerError

POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)

import keystone
import keystone.utils as utils
from keystone.common import wsgi
from keystone.common import config

PROTOCOL_NAME = "Legacy Authentication"


class AuthProtocol(object):
    """Legacy Auth Middleware that handles authenticating client calls"""

    def __init__(self, app, conf):
        """ Common initialization code """
        print "Starting the %s component" % PROTOCOL_NAME
        self.conf = conf
        self.app = app

    def __call__(self, env, start_response):
        """ Handle incoming request. Transform. And send downstream. """
        self.start_response = start_response
        self.env = env
        self.request = Request(env)
        if self.request.path.startswith('/v1.0'
                ) or self.request.path.startswith('/v1.1'):
            #Handle 1.0 and 1.1 calls via wrapper.
            params = {"passwordCredentials":
                {"username": utils.get_auth_user(self.request),
                    "password": utils.get_auth_key(self.request)}}

            new_request = Request.blank('/v2.0/tokens')
            new_request.headers['Content-type'] = 'application/json'
            new_request.accept = 'text/json'
            new_request.body = json.dumps(params)
            new_request.method = 'POST'
            response = new_request.get_response(self.app)
            #Handle failures.
            if not str(response.status).startswith('20'):
                return response(env, start_response)
            headers = self.transform_keystone_auth_to_legacy_headers(
                json.loads(response.body))
            resp = utils.send_legacy_result(204, headers)
            return resp(env, start_response)
        else:
            # Other calls pass to downstream WSGI component
            return self.app(self.env, self.start_response)

    def get_auth_user(self):
        auth_user = None
        if "X-Auth-User" in self.request.headers:
            auth_user = self.request.headers["X-Auth-User"]
        return auth_user

    def get_auth_key(self):
        auth_key = None
        if "X-Auth-Key" in self.request.headers:
            auth_key = self.request.headers["X-Auth-Key"]
        return auth_key

    def transform_keystone_auth_to_legacy_headers(self, content):
        headers = {}
        if "auth" in content:
            auth = content["auth"]
            if "token" in auth:
                headers["X-Auth-Token"] = auth["token"]["id"]
            if "serviceCatalog" in auth:
                services = auth["serviceCatalog"]
                service_mappings = ast.literal_eval(
                    self.conf["service-header-mappings"])
                for service in services:
                    service_name = service
                    service_urls = ''
                    for endpoint in services[service_name]:
                        if len(service_urls) > 0:
                            service_urls += ','
                        service_urls += endpoint["publicURL"]
                    if len(service_urls) > 0:
                        if service_mappings.get(service_name):
                            headers[service_mappings.get(
                                service_name)] = service_urls
                        else:
                            #For Services that are not mapped,
                            #use X- prefix followed by service name.
                            headers['X-' + service_name.upper()] = service_urls
        return headers


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthProtocol(app, conf)
    return auth_filter
