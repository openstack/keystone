# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""Main entry point into the S3 Credentials service.

TODO-DOCS
"""

import uuid
import base64
import hmac

from hashlib import sha1
from keystone import catalog
from keystone import config
from keystone import identity
from keystone import policy
from keystone import token
from keystone import service
from keystone.common import wsgi
from keystone.contrib.ec2 import Manager as EC2Manager

CONF = config.CONF


class S3Extension(wsgi.ExtensionRouter):
    def add_routes(self, mapper):
        s3_controller = S3Controller()
        # validation
        mapper.connect('/s3tokens',
                       controller=s3_controller,
                       action='authenticate_s3',
                       conditions=dict(method=['POST']))

        # No need CRUD stuff since we are sharing keystone.contrib.ec2
        # infos.


class S3Controller(wsgi.Application):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        self.ec2_api = EC2Manager()
        super(S3Controller, self).__init__()

    def authenticate_s3(self, context, credentials=None):
        """Validate a signed S3 request and provide a token.

        TODO-DOCS::

        :param context: standard context
        :param credentials: dict of s3 signature
        :returns: token: openstack token equivalent to access key along
                         with the corresponding service catalog and roles
        """

        creds_ref = self.ec2_api.get_credential(context,
                                                credentials['access'])

        msg = base64.urlsafe_b64decode(str(credentials['token']))
        key = str(creds_ref['secret'])
        s = base64.encodestring(hmac.new(key, msg, sha1).digest()).strip()
        signature = credentials['signature']
        if signature == s:
            pass
        else:
            raise Exception("Not Authorized")

        token_id = uuid.uuid4().hex
        tenant_ref = self.identity_api.get_tenant(context,
                                                  creds_ref['tenant_id'])
        user_ref = self.identity_api.get_user(context,
                                              creds_ref['user_id'])
        metadata_ref = self.identity_api.get_metadata(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'])
        catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'],
                    metadata=metadata_ref)

        token_ref = self.token_api.create_token(
                context, token_id, dict(expires='',
                                        id=token_id,
                                        user=user_ref,
                                        tenant=tenant_ref,
                                        metadata=metadata_ref))

        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))

        token_controller = service.TokenController()
        return token_controller._format_authenticate(
                token_ref, roles_ref, catalog_ref)
