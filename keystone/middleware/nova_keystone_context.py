# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011-2012 OpenStack LLC
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

"""
Nova Auth Middleware.

"""

import webob.dec
import webob.exc

from nova import context
from nova import flags
from nova import wsgi


FLAGS = flags.FLAGS
flags.DECLARE('use_forwarded_for', 'nova.api.auth')


class NovaKeystoneContext(wsgi.Middleware):
    """Make a request context from keystone headers"""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        try:
            user_id = req.headers['X_USER']
        except KeyError:
            return webob.exc.HTTPUnauthorized()
        # get the roles
        roles = [r.strip() for r in req.headers.get('X_ROLE', '').split(',')]

        if 'X_TENANT_ID' in req.headers:
            # This is the new header since Keystone went to ID/Name
            project_id = req.headers['X_TENANT_ID']
        else:
            # This is for legacy compatibility
            project_id = req.headers['X_TENANT']

        # Get the auth token
        auth_token = req.headers.get('X_AUTH_TOKEN',
                                     req.headers.get('X_STORAGE_TOKEN'))

        # Build a context, including the auth_token...
        remote_address = getattr(req, 'remote_address', '127.0.0.1')
        remote_address = req.remote_addr
        if FLAGS.use_forwarded_for:
            remote_address = req.headers.get('X-Forwarded-For', remote_address)
        ctx = context.RequestContext(user_id,
                                     project_id,
                                     roles=roles,
                                     auth_token=auth_token,
                                     strategy='keystone',
                                     remote_address=remote_address)

        req.environ['nova.context'] = ctx
        return self.application
