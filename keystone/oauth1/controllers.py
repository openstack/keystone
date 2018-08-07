# Copyright 2013 OpenStack Foundation
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

"""Extensions supporting OAuth1."""

from oslo_log import log
from oslo_serialization import jsonutils

from keystone.common import controller
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone import notifications


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class AccessTokenCrudV3(controller.V3Controller):
    collection_name = 'access_tokens'
    member_name = 'access_token'

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        # NOTE(lwolf): overriding method to add proper path to self link
        ref.setdefault('links', {})
        path = '/users/%(user_id)s/OS-OAUTH1/access_tokens' % {
            'user_id': cls._get_user_id(ref)
        }
        ref['links']['self'] = cls.base_url(context, path) + '/' + ref['id']

    @controller.protected()
    def get_access_token(self, request, user_id, access_token_id):
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise exception.NotFound()
        access_token = self._format_token_entity(request.context_dict,
                                                 access_token)
        return AccessTokenCrudV3.wrap_member(request.context_dict,
                                             access_token)

    @controller.protected()
    def list_access_tokens(self, request, user_id):
        if request.context.is_delegated_auth:
            raise exception.Forbidden(
                _('Cannot list request tokens'
                  ' with a token issued via delegation.'))
        refs = PROVIDERS.oauth_api.list_access_tokens(user_id)
        formatted_refs = ([self._format_token_entity(request.context_dict, x)
                           for x in refs])
        return AccessTokenCrudV3.wrap_collection(request.context_dict,
                                                 formatted_refs)

    @controller.protected()
    def delete_access_token(self, request, user_id, access_token_id):
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        reason = (
            'Invalidating the token cache because an access token for '
            'consumer %(consumer_id)s has been deleted. Authorization for '
            'users with OAuth tokens will be recalculated and enforced '
            'accordingly the next time they authenticate or validate a '
            'token.' % {'consumer_id': access_token['consumer_id']}
        )
        notifications.invalidate_token_cache_notification(reason)
        return PROVIDERS.oauth_api.delete_access_token(
            user_id, access_token_id, initiator=request.audit_initiator
        )

    @staticmethod
    def _get_user_id(entity):
        return entity.get('authorizing_user_id', '')

    def _format_token_entity(self, context, entity):

        formatted_entity = entity.copy()
        access_token_id = formatted_entity['id']
        user_id = self._get_user_id(formatted_entity)
        if 'role_ids' in entity:
            formatted_entity.pop('role_ids')
        if 'access_secret' in entity:
            formatted_entity.pop('access_secret')

        url = ('/users/%(user_id)s/OS-OAUTH1/access_tokens/%(access_token_id)s'
               '/roles' % {'user_id': user_id,
                           'access_token_id': access_token_id})

        formatted_entity.setdefault('links', {})
        formatted_entity['links']['roles'] = (self.base_url(context, url))

        return formatted_entity


class AccessTokenRolesV3(controller.V3Controller):
    collection_name = 'roles'
    member_name = 'role'

    @controller.protected()
    def list_access_token_roles(self, request, user_id, access_token_id):
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise exception.NotFound()
        authed_role_ids = access_token['role_ids']
        authed_role_ids = jsonutils.loads(authed_role_ids)
        refs = ([self._format_role_entity(x) for x in authed_role_ids])
        return AccessTokenRolesV3.wrap_collection(request.context_dict, refs)

    @controller.protected()
    def get_access_token_role(self, request, user_id,
                              access_token_id, role_id):
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise exception.Unauthorized(_('User IDs do not match'))
        authed_role_ids = access_token['role_ids']
        authed_role_ids = jsonutils.loads(authed_role_ids)
        for authed_role_id in authed_role_ids:
            if authed_role_id == role_id:
                role = self._format_role_entity(role_id)
                return AccessTokenRolesV3.wrap_member(request.context_dict,
                                                      role)
        raise exception.RoleNotFound(role_id=role_id)

    def _format_role_entity(self, role_id):
        role = PROVIDERS.role_api.get_role(role_id)
        formatted_entity = role.copy()
        if 'description' in role:
            formatted_entity.pop('description')
        if 'enabled' in role:
            formatted_entity.pop('enabled')
        return formatted_entity
