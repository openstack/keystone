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


def check_signature(creds_ref, credentials):
    signature = credentials['signature']
    msg = base64.urlsafe_b64decode(str(credentials['token']))
    key = str(creds_ref['secret'])
    signed = base64.encodestring(hmac.new(key, msg, sha1).digest()).strip()

    if signature == signed:
        pass
    else:
        raise Exception("Not Authorized")


class S3Extension(wsgi.ExtensionRouter):
    def add_routes(self, mapper):
        controller = ec2.Ec2Controller()
        controller.check_signature = check_signature
        # validation
        mapper.connect('/s3tokens',
                       controller=controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))

        # No need CRUD stuff since we are sharing keystone.contrib.ec2
        # infos.
