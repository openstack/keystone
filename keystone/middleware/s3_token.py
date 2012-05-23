# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011,2012 Akira YOSHIYAMA <akirayoshiyama@gmail.com>
# All Rights Reserved.
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

# This source code is based ./auth_token.py and ./ec2_token.py.
# See them for their copyright.

"""
S3 TOKEN MIDDLEWARE

This WSGI component:

* Get a request from the swift3 middleware with an S3 Authorization
  access key.
* Validate s3 token in Keystone.
* Transform the account name to AUTH_%(tenant_name).

"""

import httplib
import json

import webob

from swift.common import utils as swift_utils


PROTOCOL_NAME = 'S3 Token Authentication'


class ServiceError(Exception):
    pass


class S3Token(object):
    """Auth Middleware that handles S3 authenticating client calls."""

    def __init__(self, app, conf):
        """Common initialization code."""
        self.app = app
        self.logger = swift_utils.get_logger(conf, log_route='s3token')
        self.logger.debug('Starting the %s component' % PROTOCOL_NAME)
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH_')
        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_host')
        self.auth_port = int(conf.get('auth_port', 35357))
        self.auth_protocol = conf.get('auth_protocol', 'https')
        if self.auth_protocol == 'http':
            self.http_client_class = httplib.HTTPConnection
        else:
            self.http_client_class = httplib.HTTPSConnection
        # SSL
        self.cert_file = conf.get('certfile')
        self.key_file = conf.get('keyfile')

    def deny_request(self, code):
        error_table = {
            'AccessDenied':
                (401, 'Access denied'),
            'InvalidURI':
                (400, 'Could not parse the specified URI'),
            }
        resp = webob.Response(content_type='text/xml')
        resp.status = error_table[code][0]
        resp.body = error_table[code][1]
        resp.body = ('<?xml version="1.0" encoding="UTF-8"?>\r\n'
                     '<Error>\r\n  <Code>%s</Code>\r\n  '
                     '<Message>%s</Message>\r\n</Error>\r\n' %
                     (code, error_table[code][1]))
        return resp

    def _json_request(self, creds_json):
        headers = {'Content-Type': 'application/json'}

        try:
            if self.auth_protocol == 'http':
                conn = self.http_client_class(self.auth_host, self.auth_port)
            else:
                conn = self.http_client_class(self.auth_host, self.auth_port,
                    self.key_file, self.cert_file)
            conn.request('POST', '/v2.0/s3tokens',
                         body=creds_json,
                         headers=headers)
            response = conn.getresponse()
            output = response.read()
        except Exception, e:
            self.logger.info('HTTP connection exception: %s' % e)
            resp = self.deny_request('InvalidURI')
            raise ServiceError(resp)
        finally:
            conn.close()

        if response.status < 200 or response.status >= 300:
            self.logger.debug('Keystone reply error: status=%s reason=%s' %
                              (response.status, response.reason))
            resp = self.deny_request('AccessDenied')
            raise ServiceError(resp)

        return (response, output)

    def __call__(self, environ, start_response):
        """Handle incoming request. authenticate and send downstream."""
        req = webob.Request(environ)
        self.logger.debug('Calling S3Token middleware.')

        try:
            parts = swift_utils.split_path(req.path, 1, 4, True)
            version, account, container, obj = parts
        except ValueError:
            msg = 'Not a path query, skipping.'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        # Read request signature and access id.
        if not 'Authorization' in req.headers:
            msg = 'No Authorization header. skipping.'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        token = req.headers.get('X-Auth-Token',
                                req.headers.get('X-Storage-Token'))
        if not token:
            msg = 'You did not specify a auth or a storage token. skipping.'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        auth_header = req.headers['Authorization']
        try:
            access, signature = auth_header.split(' ')[-1].rsplit(':', 1)
        except(ValueError):
            msg = 'You have an invalid Authorization header: %s'
            self.logger.debug(msg % (auth_header))
            return self.deny_request('InvalidURI')(environ, start_response)

        # NOTE(chmou): This is to handle the special case with nova
        # when we have the option s3_affix_tenant. We will force it to
        # connect to another account than the one
        # authenticated. Before people start getting worried about
        # security, I should point that we are connecting with
        # username/token specified by the user but instead of
        # connecting to its own account we will force it to go to an
        # another account. In a normal scenario if that user don't
        # have the reseller right it will just fail but since the
        # reseller account can connect to every account it is allowed
        # by the swift_auth middleware.
        force_tenant = None
        if ':' in access:
            access, force_tenant = access.split(':')

        # Authenticate request.
        creds = {'credentials': {'access': access,
                                 'token': token,
                                 'signature': signature}}
        creds_json = json.dumps(creds)
        self.logger.debug('Connecting to Keystone sending this JSON: %s' %
                          creds_json)
        # NOTE(vish): We could save a call to keystone by having
        #             keystone return token, tenant, user, and roles
        #             from this call.
        #
        # NOTE(chmou): We still have the same problem we would need to
        #              change token_auth to detect if we already
        #              identified and not doing a second query and just
        #              pass it thru to swiftauth in this case.
        try:
            resp, output = self._json_request(creds_json)
        except ServiceError as e:
            resp = e.args[0]
            msg = 'Received error, exiting middleware with error: %s'
            self.logger.debug(msg % (resp.status))
            return resp(environ, start_response)

        self.logger.debug('Keystone Reply: Status: %d, Output: %s' % (
                resp.status, output))

        try:
            identity_info = json.loads(output)
            token_id = str(identity_info['access']['token']['id'])
            tenant = identity_info['access']['token']['tenant']
        except (ValueError, KeyError):
            error = 'Error on keystone reply: %d %s'
            self.logger.debug(error % (resp.status, str(output)))
            return self.deny_request('InvalidURI')(environ, start_response)

        req.headers['X-Auth-Token'] = token_id
        tenant_to_connect = force_tenant or tenant['id']
        self.logger.debug('Connecting with tenant: %s' % (tenant_to_connect))
        new_tenant_name = '%s%s' % (self.reseller_prefix, tenant_to_connect)
        environ['PATH_INFO'] = environ['PATH_INFO'].replace(account,
                                                            new_tenant_name)
        return self.app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Token(app, conf)
    return auth_filter
