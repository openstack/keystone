# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""Main entry point into the S3 Credentials service.

TODO-DOCS
"""

import base64
import hmac

from hashlib import sha1

from keystone import config
from keystone.common import wsgi
from keystone.contrib import ec2

CONF = config.CONF


class S3Extension(wsgi.ExtensionRouter):
    def add_routes(self, mapper):
        controller = S3Controller()
        # validation
        mapper.connect('/s3tokens',
                       controller=controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))


class S3Controller(ec2.Ec2Controller):
    def check_signature(self, creds_ref, credentials):
        msg = base64.urlsafe_b64decode(str(credentials['token']))
        key = str(creds_ref['secret'])
        signed = base64.encodestring(hmac.new(key, msg, sha1).digest()).strip()

        if credentials['signature'] != signed:
            raise Exception('Not Authorized')
