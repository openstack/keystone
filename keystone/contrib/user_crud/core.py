# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import copy
import uuid

from keystone.common import extension
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone.openstack.common import log as logging


LOG = logging.getLogger(__name__)


extension.register_public_extension(
    'OS-KSCRUD', {
        'name': 'OpenStack Keystone User CRUD',
        'namespace': 'http://docs.openstack.org/identity/api/ext/'
                     'OS-KSCRUD/v1.0',
        'alias': 'OS-KSCRUD',
        'updated': '2013-07-07T12:00:0-00:00',
        'description': 'OpenStack extensions to Keystone v2.0 API '
                       'enabling User Operations.',
        'links': [
            {
                'rel': 'describedby',
                # TODO(ayoung): needs a description
                'type': 'text/html',
                'href': 'https://github.com/openstack/identity-api',
            }
        ]})


class UserController(identity.controllers.User):
    def set_user_password(self, context, user_id, user):
        token_id = context.get('token_id')
        original_password = user.get('original_password')

        token_ref = self.token_api.get_token(token_id)
        user_id_from_token = token_ref['user']['id']

        if user_id_from_token != user_id:
            raise exception.Forbidden('Token belongs to another user')
        if original_password is None:
            raise exception.ValidationError(target='user',
                                            attribute='original password')

        try:
            user_ref = self.identity_api.authenticate(
                user_id=user_id_from_token,
                password=original_password)
            if not user_ref.get('enabled', True):
                # NOTE(dolph): why can't you set a disabled user's password?
                raise exception.Unauthorized('User is disabled')
        except AssertionError:
            raise exception.Unauthorized()

        update_dict = {'password': user['password'], 'id': user_id}

        admin_context = copy.copy(context)
        admin_context['is_admin'] = True
        super(UserController, self).set_user_password(admin_context,
                                                      user_id,
                                                      update_dict)

        token_id = uuid.uuid4().hex
        new_token_ref = copy.copy(token_ref)
        new_token_ref['id'] = token_id
        self.token_api.create_token(token_id, new_token_ref)
        LOG.debug('TOKEN_REF %s', new_token_ref)
        return {'access': {'token': new_token_ref}}


class CrudExtension(wsgi.ExtensionRouter):
    """Provides a subset of CRUD operations for internal data types."""

    def add_routes(self, mapper):
        user_controller = UserController()

        mapper.connect('/OS-KSCRUD/users/{user_id}',
                       controller=user_controller,
                       action='set_user_password',
                       conditions=dict(method=['PATCH']))
