# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2012 OpenStack LLC
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
NOVA LAZY PROVISIONING AUTH MIDDLEWARE

This WSGI component allows keystone act as an identity service for nova by
lazy provisioning nova projects/users as authenticated by auth_token.

Use by applying after auth_token in the nova paste config.
Example: docs/nova-api-paste.ini
"""

from nova import auth
from nova import context
from nova import flags
from nova import utils
from nova import wsgi
from nova import exception
import webob.dec
import webob.exc


FLAGS = flags.FLAGS


class KeystoneAuthShim(wsgi.Middleware):
    """Lazy provisioning nova project/users from keystone tenant/user"""

    def __init__(self, application, db_driver=None):
        if not db_driver:
            db_driver = FLAGS.db_driver
        self.db = utils.import_object(db_driver)
        self.auth = auth.manager.AuthManager()
        super(KeystoneAuthShim, self).__init__(application)

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        # find or create user
        try:
            user_id = req.headers['X_USER']
        except:
            return webob.exc.HTTPUnauthorized()
        try:
            user_ref = self.auth.get_user(user_id)
        except:
            user_ref = self.auth.create_user(user_id)

        # get the roles
        roles = [r.strip() for r in req.headers.get('X_ROLE', '').split(',')]

        # set user admin-ness to keystone admin-ness
        # FIXME: keystone-admin-role value from keystone.conf is not
        # used neither here nor in glance_auth_token!
        roles = [r.strip() for r in req.headers.get('X_ROLE', '').split(',')]
        is_admin = 'admin' in roles
        if user_ref.is_admin() != is_admin:
            self.auth.modify_user(user_ref, admin=is_admin)

        # create a project for tenant
        if 'X_TENANT_ID' in req.headers:
            # This is the new header since Keystone went to ID/Name
            project_id = req.headers['X_TENANT_ID']
        else:
            # This is for legacy compatibility
            project_id = req.headers['X_TENANT']

        if project_id:
            try:
                project_ref = self.auth.get_project(project_id)
            except:
                project_ref = self.auth.create_project(project_id, user_id)
            # ensure user is a member of project
            if not self.auth.is_project_member(user_id, project_id):
                self.auth.add_to_project(user_id, project_id)
        else:
            project_ref = None

        # Get the auth token
        auth_token = req.headers.get('X_AUTH_TOKEN',
                                     req.headers.get('X_STORAGE_TOKEN'))

        # Build a context, including the auth_token...
        ctx = context.RequestContext(user_id, project_id,
                                     is_admin=('admin' in roles),
                                     auth_token=auth_token)

        req.environ['nova.context'] = ctx
        return self.application
