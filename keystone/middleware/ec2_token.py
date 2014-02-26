# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
Starting point for routing EC2 requests.

"""

from oslo.config import cfg
import requests
import webob.dec
import webob.exc

from keystone.common import config
from keystone.common import wsgi
from keystone.openstack.common import jsonutils

keystone_ec2_opts = [
    cfg.StrOpt('keystone_ec2_url',
               default='http://localhost:5000/v2.0/ec2tokens',
               help='URL to get token from ec2 request.'),
    cfg.StrOpt('keystone_ec2_keyfile', help='Required if EC2 server requires '
               'client certificate.'),
    cfg.StrOpt('keystone_ec2_certfile', help='Client certificate key '
               'filename. Required if EC2 server requires client '
               'certificate.'),
    cfg.StrOpt('keystone_ec2_cafile', help='A PEM encoded certificate '
               'authority to use when verifying HTTPS connections. Defaults '
               'to the system CAs.'),
    cfg.BoolOpt('keystone_ec2_insecure', default=False, help='Disable SSL '
                'certificate verification.'),
]

CONF = config.CONF
CONF.register_opts(keystone_ec2_opts)


class EC2Token(wsgi.Middleware):
    """Authenticate an EC2 request with keystone and convert to token."""

    @webob.dec.wsgify()
    def __call__(self, req):
        # Read request signature and access id.
        try:
            signature = req.params['Signature']
            access = req.params['AWSAccessKeyId']
        except KeyError:
            raise webob.exc.HTTPBadRequest()

        # Make a copy of args for authentication and signature verification.
        auth_params = dict(req.params)
        # Not part of authentication args
        auth_params.pop('Signature')

        # Authenticate the request.
        creds = {
            'ec2Credentials': {
                'access': access,
                'signature': signature,
                'host': req.host,
                'verb': req.method,
                'path': req.path,
                'params': auth_params,
            }
        }
        creds_json = jsonutils.dumps(creds)
        headers = {'Content-Type': 'application/json'}

        verify = True
        if CONF.keystone_ec2_insecure:
            verify = False
        elif CONF.keystone_ec2_cafile:
            verify = CONF.keystone_ec2_cafile

        cert = None
        if CONF.keystone_ec2_certfile and CONF.keystone_ec2_keyfile:
            cert = (CONF.keystone_ec2_certfile, CONF.keystone_ec2_keyfile)
        elif CONF.keystone_ec2_certfile:
            cert = CONF.keystone_ec2_certfile

        response = requests.post(CONF.keystone_ec2_url, data=creds_json,
                                 headers=headers, verify=verify, cert=cert)

        # NOTE(vish): We could save a call to keystone by
        #             having keystone return token, tenant,
        #             user, and roles from this call.

        result = response.json()
        try:
            token_id = result['access']['token']['id']
        except (AttributeError, KeyError):
            raise webob.exc.HTTPBadRequest()

        # Authenticated!
        req.headers['X-Auth-Token'] = token_id
        return self.application
