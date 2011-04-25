# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

import json
from webob.exc import HTTPUnauthorized, Request

from keystone.common.bufferedhttp import http_connect_raw as http_connect


class TokenAuth(object):
    """Auth Middleware that uses the dev auth server."""

    def __init__(self, app, conf):
        print "Starting the new one"
        self.app = app
        self.conf = conf
        self.auth_host = conf.get('auth_ip', '127.0.0.1')
        self.auth_port = int(conf.get('auth_port', 8080))
        self.auth_pass = conf.get('auth_pass', 'dTpw')
        self.delegated = int(conf.get('delegated', 0))

    def __call__(self, env, start_response):

        def custom_start_response(status, headers):
            if self.delegated:
                headers.append(('WWW-Authenticate', "Basic realm='API Realm'"))
            return start_response(status, headers)

        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        if token:
            # NOTE(vish): Not sure what the logic behind this other token is
            headers = {'X-Auth-Token': '999888777666'}
            conn = http_connect(self.auth_host, self.auth_port, 'GET',
                                '/v1.0/token/%s' % token, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            conn.close()
            #path = 'http://%s:%s/v1.0/token/%s' % \
            #       (self.auth_host, self.auth_port, token)
            #resp = Request.blank(path).get_response(self.app)
            #data = resp.body
            dict_response = json.loads(data)
            user = dict_response['auth']['user']['username']
            if not str(resp.status).startswith('20'):
                if self.delegated:
                    env['HTTP_X_IDENTITY_STATUS'] = "Invalid"
            else:
                env['HTTP_X_AUTHORIZATION'] = "Proxy " + user
                if self.delegated:
                    env['HTTP_X_IDENTITY_STATUS'] = "Confirmed"

        env['HTTP_AUTHORIZATION'] = "Basic dTpw"
        return self.app(env, custom_start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return TokenAuth(app, conf)
    return auth_filter
