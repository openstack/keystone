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

from oslo_log import log

from keystone.common import dependency
from keystone.common import extension
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone.models import token_model


LOG = log.getLogger(__name__)


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


@dependency.requires('catalog_api', 'identity_api', 'resource_api',
                     'token_provider_api')
class UserController(identity.controllers.User):
    def set_user_password(self, context, user_id, user):
        token_id = context.get('token_id')
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
                context,
                user_id=token_ref.user_id,
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

        # Issue a new token based upon the original token data. This will
        # always be a V2.0 token.

        # TODO(morganfainberg): Add a mechanism to issue a new token directly
        # from a token model so that this code can go away. This is likely
        # not the norm as most cases do not need to yank apart a token to
        # issue a new one.
        new_token_ref = {}
        metadata_ref = {}
        roles_ref = None

        new_token_ref['user'] = user_ref
        if token_ref.bind:
            new_token_ref['bind'] = token_ref.bind
        if token_ref.project_id:
            new_token_ref['tenant'] = self.resource_api.get_project(
                token_ref.project_id)
        if token_ref.role_names:
            roles_ref = [dict(name=value)
                         for value in token_ref.role_names]
        if token_ref.role_ids:
            metadata_ref['roles'] = token_ref.role_ids
        if token_ref.trust_id:
            metadata_ref['trust'] = {
                'id': token_ref.trust_id,
                'trustee_user_id': token_ref.trustee_user_id}
        new_token_ref['metadata'] = metadata_ref
        new_token_ref['id'] = uuid.uuid4().hex

        catalog_ref = self.catalog_api.get_catalog(user_id,
                                                   token_ref.project_id)

        new_token_id, new_token_data = self.token_provider_api.issue_v2_token(
            token_ref=new_token_ref, roles_ref=roles_ref,
            catalog_ref=catalog_ref)
        LOG.debug('TOKEN_REF %s', new_token_data)
        return new_token_data


class CrudExtension(wsgi.ExtensionRouter):
    """Provides a subset of CRUD operations for internal data types."""

    def add_routes(self, mapper):
        user_controller = UserController()

        mapper.connect('/OS-KSCRUD/users/{user_id}',
                       controller=user_controller,
                       action='set_user_password',
                       conditions=dict(method=['PATCH']))
