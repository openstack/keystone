# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

"""
Starting point for routing S3 requests.

"""

import httplib
import json
from webob.dec import wsgify
from urlparse import urlparse

PROTOCOL_NAME = "S3 Token Authentication"


class S3Token(object):
    """Auth Middleware that handles S3 authenticating client calls"""

    def _init_protocol_common(self, app, conf):
        """ Common initialization code"""
        print "Starting the %s component" % PROTOCOL_NAME

        self.conf = conf
        self.app = app
        #if app is set, then we are in a WSGI pipeline and requests get passed
        # on to app. If it is not set, this component should forward requests

    def _init_protocol(self, conf):
        """ Protocol specific initialization """

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_host')
        self.auth_port = int(conf.get('auth_port'))
        self.auth_protocol = conf.get('auth_protocol', 'https')

        # where to tell clients to find the auth service (default to url
        # constructed based on endpoint we have for the service to use)
        self.auth_location = conf.get('auth_uri',
                                        "%s://%s:%s" % (self.auth_protocol,
                                        self.auth_host,
                                        self.auth_port))

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = conf.get('admin_token')

    def __init__(self, app, conf):
        """ Common initialization code """

        #TODO(ziad): maybe we refactor this into a superclass
        self._init_protocol_common(app, conf)  # Applies to all protocols
        self._init_protocol(conf)  # Specific to this protocol
        self.app = None
        self.auth_port = None
        self.auth_protocol = None
        self.auth_location = None
        self.auth_host = None
        self.admin_token = None
        self.conf = None

    #@webob.dec.wsgify(RequestClass=webob.exc.Request)
    # pylint: disable=R0914
    @wsgify
    def __call__(self, req):
        """ Handle incoming request. Authenticate. And send downstream. """

        # Read request signature and access id.
        if not 'Authorization' in req.headers:
            return self.app
        try:
            account, signature = \
                req.headers['Authorization'].split(' ')[-1].rsplit(':', 1)
            #del(req.headers['Authorization'])
        except StandardError:
            return self.app

        #try:
        #    account, tenant = access.split(':')
        #except Exception:
        #    account = access

        # Authenticate the request.
        creds = {'OS-KSS3:s3Credentials': {'access': account,
                                    'signature': signature,
                                    'verb': req.method,
                                    'path': req.path,
                                    'expire': req.headers['Date'],
                                   }}

        if req.headers.get('Content-Type'):
            creds['s3Credentials']['content_type'] = \
                    req.headers['Content-Type']
        if req.headers.get('Content-MD5'):
            creds['s3Credentials']['content_md5'] = req.headers['Content-MD5']
        xheaders = {}
        for key, value in req.headers.iteritems():
            if key.startswith('X-Amz'):
                xheaders[key.lower()] = value
        if xheaders:
            creds['s3Credentials']['xheaders'] = xheaders

        creds_json = json.dumps(creds)
        headers = {'Content-Type': 'application/json'}
        if self.auth_protocol == 'http':
            conn = httplib.HTTPConnection(self.auth_host, self.auth_port)
        else:
            conn = httplib.HTTPSConnection(self.auth_host, self.auth_port)

        conn.request('POST', '/v2.0/tokens', body=creds_json, headers=headers)
        response = conn.getresponse().read()
        conn.close()

        # NOTE(vish): We could save a call to keystone by
        #             having keystone return token, tenant,
        #             user, and roles from this call.
        result = json.loads(response)
        endpoint_path = ''
        try:
            token_id = str(result['access']['token']['id'])
            for endpoint in result['access']['serviceCatalog']:
                if endpoint['type'] == 'Swift Service':
                    ep = urlparse(endpoint['endpoints'][0]['internalURL'])
                    endpoint_path = str(ep.path)  # pylint: disable=E1101
                    break
        except KeyError:
            return self.app

        # Authenticated!
        req.headers['X-Auth-Token'] = token_id
        req.headers['X-Endpoint-Path'] = endpoint_path
        return self.app


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Token(app, conf)
    return auth_filter
