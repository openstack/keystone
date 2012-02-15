# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011,2012 Akira YOSHIYAMA <akirayoshiyama@gmail.com>
# All Rights Reserved.
#
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

# This source code is based ./auth_token.py and ./ec2_token.py.
# See them for their copyright.

"""Starting point for routing S3 requests."""

import httplib
import json

import webob

from swift.common import utils as swift_utils


PROTOCOL_NAME = "S3 Token Authentication"


class S3Token(object):
    """Auth Middleware that handles S3 authenticating client calls."""

    def __init__(self, app, conf):
        """Common initialization code."""
        self.app = app
        self.logger = swift_utils.get_logger(conf, log_route='s3_token')
        self.logger.debug('Starting the %s component' % PROTOCOL_NAME)

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_host')
        self.auth_port = int(conf.get('auth_port'))
        self.auth_protocol = conf.get('auth_protocol', 'https')

        # where to tell clients to find the auth service (default to url
        # constructed based on endpoint we have for the service to use)
        self.auth_location = conf.get('auth_uri',
                                      '%s://%s:%s' % (self.auth_protocol,
                                                      self.auth_host,
                                                      self.auth_port))

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = conf.get('admin_token')

    def __call__(self, environ, start_response):
        """Handle incoming request. authenticate and send downstream."""
        req = webob.Request(environ)
        parts = swift_utils.split_path(req.path, 1, 4, True)
        version, account, container, obj = parts

        # Read request signature and access id.
        if not 'Authorization' in req.headers:
            return self.app(environ, start_response)
        token = req.headers.get('X-Auth-Token',
                                req.headers.get('X-Storage-Token'))

        auth_header = req.headers['Authorization']
        access, signature = auth_header.split(' ')[-1].rsplit(':', 1)

        # Authenticate the request.
        creds = {'credentials': {'access': access,
                                 'token': token,
                                 'signature': signature,
                                 'host': req.host,
                                 'verb': req.method,
                                 'path': req.path,
                                 'expire': req.headers['Date'],
                                 }}

        creds_json = json.dumps(creds)
        headers = {'Content-Type': 'application/json'}
        if self.auth_protocol == 'http':
            conn = httplib.HTTPConnection(self.auth_host, self.auth_port)
        else:
            conn = httplib.HTTPSConnection(self.auth_host, self.auth_port)

        conn.request('POST', '/v2.0/s3tokens',
                     body=creds_json,
                     headers=headers)
        resp = conn.getresponse()
        if resp.status < 200 or resp.status >= 300:
            raise Exception('Keystone reply error: status=%s reason=%s' % (
                    resp.status,
                    resp.reason))

        # NOTE(vish): We could save a call to keystone by having
        #             keystone return token, tenant, user, and roles
        #             from this call.
        #
        # NOTE(chmou): We still have the same problem we would need to
        #              change token_auth to detect if we already
        #              identified and not doing a second query and just
        #              pass it through to swiftauth in this case.
        #              identity_info = json.loads(response)
        output = resp.read()
        conn.close()
        identity_info = json.loads(output)
        try:
            token_id = str(identity_info['access']['token']['id'])
            tenant = (identity_info['access']['token']['tenant']['id'],
                      identity_info['access']['token']['tenant']['name'])
        except (KeyError, IndexError):
            self.logger.debug('Error getting keystone reply: %s' %
                              (str(output)))
            raise

        req.headers['X-Auth-Token'] = token_id
        environ['PATH_INFO'] = environ['PATH_INFO'].replace(
                account, 'AUTH_%s' % tenant[0])
        return self.app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Token(app, conf)
    return auth_filter
