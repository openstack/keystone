# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
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

"""
Glance Keystone Integration Middleware

This WSGI component allows keystone to act as an identity service for
glance.  Glance now supports the concept of images owned by a tenant,
and this middleware takes the authentication information provided by
auth_token and builds a glance-compatible context object.

Use by applying after auth_token in the glance-api.ini and
glance-registry.ini configurations, replacing the existing context
middleware.

Example: examples/paste/glance-api.conf,
    examples/paste/glance-registry.conf
"""

from glance.common import context


class KeystoneContextMiddleware(context.ContextMiddleware):
    """Glance keystone integration middleware."""

    def process_request(self, req):
        """
        Extract keystone-provided authentication information from the
        request and construct an appropriate context from it.
        """
        # Only accept the authentication information if the identity
        # has been confirmed--presumably by upstream
        if req.headers.get('X_IDENTITY_STATUS', 'Invalid') != 'Confirmed':
            # Use the default empty context
            req.context = self.make_context(read_only=True)
            return

        # OK, let's extract the information we need
        auth_tok = req.headers.get('X_AUTH_TOKEN',
                                   req.headers.get('X_STORAGE_TOKEN'))
        user = req.headers.get('X_USER')
        tenant = req.headers.get('X_TENANT')
        roles = [r.strip() for r in req.headers.get('X_ROLE', '').split(',')]
        is_admin = 'Admin' in roles

        # Construct the context
        req.context = self.make_context(auth_tok=auth_tok,
                                        user=user,
                                        tenant=tenant,
                                        roles=roles,
                                        is_admin=is_admin)


def filter_factory(global_conf, **local_conf):
    """
    Factory method for paste.deploy
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def filter(app):
        return KeystoneContextMiddleware(app, conf)

    return filter
