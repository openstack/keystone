# Copyright 2012 Red Hat, Inc
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

from oslo_log import log

from keystone.common import dependency
from keystone.common import extension
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone import identity
from keystone.models import token_model
from keystone.token import controllers as token_controllers


LOG = log.getLogger(__name__)


extension.register_public_extension(
    'OS-KSCRUD', {
        'name': 'OpenStack Keystone User CRUD',
        'namespace': 'https://docs.openstack.org/identity/api/ext/'
                     'OS-KSCRUD/v1.0',
        'alias': 'OS-KSCRUD',
        'updated': '2013-07-07T12:00:0-00:00',
        'description': 'OpenStack extensions to Keystone v2.0 API '
                       'enabling User Operations.',
        'links': [
            {
                'rel': 'describedby',
                'type': 'text/html',
                'href': 'https://developer.openstack.org/'
                        'api-ref-identity-v2-ext.html',
            }
        ]})


@dependency.requires('catalog_api', 'identity_api', 'resource_api',
                     'token_provider_api')
class UserController(identity.controllers.User):
    def set_user_password(self, request, user_id, user):
        token_id = request.context_dict.get('token_id')
        original_password = user.get('original_password')

        token_data = self.token_provider_api.validate_token(token_id)
        token_ref = token_model.KeystoneToken(token_id=token_id,
                                              token_data=token_data)

        if token_ref.user_id != user_id:
            raise exception.Forbidden('Token belongs to another user')
        if original_password is None:
            raise exception.ValidationError(target='user',
                                            attribute='original password')

        try:
            user_ref = self.identity_api.authenticate(
                request,
                user_id=token_ref.user_id,
                password=original_password)
            if not user_ref.get('enabled', True):
                # NOTE(dolph): why can't you set a disabled user's password?
                raise exception.Unauthorized('User is disabled')
        except AssertionError:
            raise exception.Unauthorized(
                _('v2.0 password change call failed '
                  'due to rejected authentication'))

        update_dict = {'password': user['password'], 'id': user_id}

        old_admin = request.context.is_admin
        request.context.is_admin = True

        super(UserController, self).set_user_password(request,
                                                      user_id,
                                                      update_dict)

        request.context.is_admin = old_admin

        # Issue a new token based upon the original token data. This will
        # always be a V2.0 token.

        # NOTE(lbragstad): Since we just updated the password and presisted a
        # revocation event for the user changing the password, it is necessary
        # to wait one second before authenticating. This ensures we are in the
        # threshold of a new second before getting a new token.
        import time
        time.sleep(1)

        new_token_id, new_token_data = self.token_provider_api.issue_token(
            token_ref.user_id, token_ref.methods,
            project_id=token_ref.project_id,
            parent_audit_id=token_ref.audit_chain_id)
        v2_helper = token_controllers.V2TokenDataHelper()
        v2_token_data = v2_helper.v3_to_v2_token(new_token_data, new_token_id)
        LOG.debug('TOKEN_REF %s', new_token_data)
        return v2_token_data


class Router(wsgi.ComposableRouter):
    """Provides a subset of CRUD operations for internal data types."""

    def add_routes(self, mapper):
        user_controller = UserController()

        mapper.connect('/OS-KSCRUD/users/{user_id}',
                       controller=user_controller,
                       action='set_user_password',
                       conditions=dict(method=['PATCH']))
