# Copyright (c) 2010 OpenStack, LLC.
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

from webob.exc import HTTPUseProxy, HTTPUnauthorized


class PAPIAuth(object):
    """Auth Middleware that uses the dev auth server."""

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.auth_host = conf.get('auth_ip', '127.0.0.1')
        self.auth_port = int(conf.get('auth_port', 11000))
        self.auth_pass = conf.get('auth_pass', 'dTpw')
        proxy_location = 'http://' + self.auth_host + ':' + \
            str(self.auth_port) + '/'
        print 'starting PAPI Auth middleware'

    def __call__(self, env, start_response):
        # Make sure that the user has been authenticated by the Auth Service
        if 'HTTP_X_AUTH_TOKEN' not in env:
            proxy_location = 'http://' + self.auth_host + ':' + \
                str(self.auth_port) + '/'
            return HTTPUseProxy(location=proxy_location)(env, start_response)

        # Authenticate the Auth component itself.
        headers = [('www-authenticate', 'Basic realm="echo"')]
        if 'HTTP_AUTHORIZATION' not in env:
            return HTTPUnauthorized(headers=headers)(env, start_response)
        else:
            auth_type, encoded_creds = env['HTTP_AUTHORIZATION'].split(None, 1)
            if encoded_creds != self.auth_pass:
                return HTTPUnauthorized(headers=headers)(env, start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return PAPIAuth(app, conf)
    return auth_filter
