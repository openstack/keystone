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

from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import timeutils

from keystone.common import controller
from keystone.common import dependency
from keystone.common import utils
from keystone.common import wsgi
from keystone.contrib.oauth1 import core as oauth1
from keystone.contrib.oauth1 import validator
from keystone import exception
from keystone.i18n import _
from keystone import notifications


CONF = cfg.CONF


@notifications.internal(notifications.INVALIDATE_USER_OAUTH_CONSUMER_TOKENS,
                        resource_id_arg_index=0)
def _emit_user_oauth_consumer_token_invalidate(payload):
    # This is a special case notification that expect the payload to be a dict
    # containing the user_id and the consumer_id. This is so that the token
    # provider can invalidate any tokens in the token persistence if
    # token persistence is enabled
    pass


@dependency.requires('oauth_api', 'token_provider_api')
class ConsumerCrudV3(controller.V3Controller):
    collection_name = 'consumers'
    member_name = 'consumer'

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""

        # NOTE(stevemar): Overriding path to /OS-OAUTH1/consumers so that
        # V3Controller.base_url handles setting the self link correctly.
        path = '/OS-OAUTH1/' + cls.collection_name
        return controller.V3Controller.base_url(context, path=path)

    @controller.protected()
    def create_consumer(self, context, consumer):
        ref = self._assign_unique_id(self._normalize_dict(consumer))
        initiator = notifications._get_request_audit_info(context)
        consumer_ref = self.oauth_api.create_consumer(ref, initiator)
        return ConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected()
    def update_consumer(self, context, consumer_id, consumer):
        self._require_matching_id(consumer_id, consumer)
        ref = self._normalize_dict(consumer)
        self._validate_consumer_ref(ref)
        initiator = notifications._get_request_audit_info(context)
        ref = self.oauth_api.update_consumer(consumer_id, ref, initiator)
        return ConsumerCrudV3.wrap_member(context, ref)

    @controller.protected()
    def list_consumers(self, context):
        ref = self.oauth_api.list_consumers()
        return ConsumerCrudV3.wrap_collection(context, ref)

    @controller.protected()
    def get_consumer(self, context, consumer_id):
        ref = self.oauth_api.get_consumer(consumer_id)
        return ConsumerCrudV3.wrap_member(context, ref)

    @controller.protected()
    def delete_consumer(self, context, consumer_id):
        user_token_ref = utils.get_token_ref(context)
        payload = {'user_id': user_token_ref.user_id,
                   'consumer_id': consumer_id}
        _emit_user_oauth_consumer_token_invalidate(payload)
        initiator = notifications._get_request_audit_info(context)
        self.oauth_api.delete_consumer(consumer_id, initiator)

    def _validate_consumer_ref(self, consumer):
        if 'secret' in consumer:
            msg = _('Cannot change consumer secret')
            raise exception.ValidationError(message=msg)


@dependency.requires('oauth_api')
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
    def get_access_token(self, context, user_id, access_token_id):
        access_token = self.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise exception.NotFound()
        access_token = self._format_token_entity(context, access_token)
        return AccessTokenCrudV3.wrap_member(context, access_token)

    @controller.protected()
    def list_access_tokens(self, context, user_id):
        auth_context = context.get('environment',
                                   {}).get('KEYSTONE_AUTH_CONTEXT', {})
        if auth_context.get('is_delegated_auth'):
            raise exception.Forbidden(
                _('Cannot list request tokens'
                  ' with a token issued via delegation.'))
        refs = self.oauth_api.list_access_tokens(user_id)
        formatted_refs = ([self._format_token_entity(context, x)
                           for x in refs])
        return AccessTokenCrudV3.wrap_collection(context, formatted_refs)

    @controller.protected()
    def delete_access_token(self, context, user_id, access_token_id):
        access_token = self.oauth_api.get_access_token(access_token_id)
        consumer_id = access_token['consumer_id']
        payload = {'user_id': user_id, 'consumer_id': consumer_id}
        _emit_user_oauth_consumer_token_invalidate(payload)
        initiator = notifications._get_request_audit_info(context)
        return self.oauth_api.delete_access_token(
            user_id, access_token_id, initiator)

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


@dependency.requires('oauth_api', 'role_api')
class AccessTokenRolesV3(controller.V3Controller):
    collection_name = 'roles'
    member_name = 'role'

    @controller.protected()
    def list_access_token_roles(self, context, user_id, access_token_id):
        access_token = self.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise exception.NotFound()
        authed_role_ids = access_token['role_ids']
        authed_role_ids = jsonutils.loads(authed_role_ids)
        refs = ([self._format_role_entity(x) for x in authed_role_ids])
        return AccessTokenRolesV3.wrap_collection(context, refs)

    @controller.protected()
    def get_access_token_role(self, context, user_id,
                              access_token_id, role_id):
        access_token = self.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise exception.Unauthorized(_('User IDs do not match'))
        authed_role_ids = access_token['role_ids']
        authed_role_ids = jsonutils.loads(authed_role_ids)
        for authed_role_id in authed_role_ids:
            if authed_role_id == role_id:
                role = self._format_role_entity(role_id)
                return AccessTokenRolesV3.wrap_member(context, role)
        raise exception.RoleNotFound(_('Could not find role'))

    def _format_role_entity(self, role_id):
        role = self.role_api.get_role(role_id)
        formatted_entity = role.copy()
        if 'description' in role:
            formatted_entity.pop('description')
        if 'enabled' in role:
            formatted_entity.pop('enabled')
        return formatted_entity


@dependency.requires('assignment_api', 'oauth_api',
                     'resource_api', 'token_provider_api')
class OAuthControllerV3(controller.V3Controller):
    collection_name = 'not_used'
    member_name = 'not_used'

    def create_request_token(self, context):
        headers = context['headers']
        oauth_headers = oauth1.get_oauth_headers(headers)
        consumer_id = oauth_headers.get('oauth_consumer_key')
        requested_project_id = headers.get('Requested-Project-Id')

        if not consumer_id:
            raise exception.ValidationError(
                attribute='oauth_consumer_key', target='request')
        if not requested_project_id:
            raise exception.ValidationError(
                attribute='requested_project_id', target='request')

        # NOTE(stevemar): Ensure consumer and requested project exist
        self.resource_api.get_project(requested_project_id)
        self.oauth_api.get_consumer(consumer_id)

        url = self.base_url(context, context['path'])

        req_headers = {'Requested-Project-Id': requested_project_id}
        req_headers.update(headers)
        request_verifier = oauth1.RequestTokenEndpoint(
            request_validator=validator.OAuthValidator(),
            token_generator=oauth1.token_generator)
        h, b, s = request_verifier.create_request_token_response(
            url,
            http_method='POST',
            body=context['query_string'],
            headers=req_headers)

        if (not b) or int(s) > 399:
            msg = _('Invalid signature')
            raise exception.Unauthorized(message=msg)

        request_token_duration = CONF.oauth1.request_token_duration
        initiator = notifications._get_request_audit_info(context)
        token_ref = self.oauth_api.create_request_token(consumer_id,
                                                        requested_project_id,
                                                        request_token_duration,
                                                        initiator)

        result = ('oauth_token=%(key)s&oauth_token_secret=%(secret)s'
                  % {'key': token_ref['id'],
                     'secret': token_ref['request_secret']})

        if CONF.oauth1.request_token_duration:
            expiry_bit = '&oauth_expires_at=%s' % token_ref['expires_at']
            result += expiry_bit

        headers = [('Content-Type', 'application/x-www-urlformencoded')]
        response = wsgi.render_response(result,
                                        status=(201, 'Created'),
                                        headers=headers)

        return response

    def create_access_token(self, context):
        headers = context['headers']
        oauth_headers = oauth1.get_oauth_headers(headers)
        consumer_id = oauth_headers.get('oauth_consumer_key')
        request_token_id = oauth_headers.get('oauth_token')
        oauth_verifier = oauth_headers.get('oauth_verifier')

        if not consumer_id:
            raise exception.ValidationError(
                attribute='oauth_consumer_key', target='request')
        if not request_token_id:
            raise exception.ValidationError(
                attribute='oauth_token', target='request')
        if not oauth_verifier:
            raise exception.ValidationError(
                attribute='oauth_verifier', target='request')

        req_token = self.oauth_api.get_request_token(
            request_token_id)

        expires_at = req_token['expires_at']
        if expires_at:
            now = timeutils.utcnow()
            expires = timeutils.normalize_time(
                timeutils.parse_isotime(expires_at))
            if now > expires:
                raise exception.Unauthorized(_('Request token is expired'))

        url = self.base_url(context, context['path'])

        access_verifier = oauth1.AccessTokenEndpoint(
            request_validator=validator.OAuthValidator(),
            token_generator=oauth1.token_generator)
        h, b, s = access_verifier.create_access_token_response(
            url,
            http_method='POST',
            body=context['query_string'],
            headers=headers)
        params = oauth1.extract_non_oauth_params(b)
        if len(params) != 0:
            msg = _('There should not be any non-oauth parameters')
            raise exception.Unauthorized(message=msg)

        if req_token['consumer_id'] != consumer_id:
            msg = _('provided consumer key does not match stored consumer key')
            raise exception.Unauthorized(message=msg)

        if req_token['verifier'] != oauth_verifier:
            msg = _('provided verifier does not match stored verifier')
            raise exception.Unauthorized(message=msg)

        if req_token['id'] != request_token_id:
            msg = _('provided request key does not match stored request key')
            raise exception.Unauthorized(message=msg)

        if not req_token.get('authorizing_user_id'):
            msg = _('Request Token does not have an authorizing user id')
            raise exception.Unauthorized(message=msg)

        access_token_duration = CONF.oauth1.access_token_duration
        initiator = notifications._get_request_audit_info(context)
        token_ref = self.oauth_api.create_access_token(request_token_id,
                                                       access_token_duration,
                                                       initiator)

        result = ('oauth_token=%(key)s&oauth_token_secret=%(secret)s'
                  % {'key': token_ref['id'],
                     'secret': token_ref['access_secret']})

        if CONF.oauth1.access_token_duration:
            expiry_bit = '&oauth_expires_at=%s' % (token_ref['expires_at'])
            result += expiry_bit

        headers = [('Content-Type', 'application/x-www-urlformencoded')]
        response = wsgi.render_response(result,
                                        status=(201, 'Created'),
                                        headers=headers)

        return response

    @controller.protected()
    def authorize_request_token(self, context, request_token_id, roles):
        """An authenticated user is going to authorize a request token.

        As a security precaution, the requested roles must match those in
        the request token. Because this is in a CLI-only world at the moment,
        there is not another easy way to make sure the user knows which roles
        are being requested before authorizing.
        """
        auth_context = context.get('environment',
                                   {}).get('KEYSTONE_AUTH_CONTEXT', {})
        if auth_context.get('is_delegated_auth'):
            raise exception.Forbidden(
                _('Cannot authorize a request token'
                  ' with a token issued via delegation.'))

        req_token = self.oauth_api.get_request_token(request_token_id)

        expires_at = req_token['expires_at']
        if expires_at:
            now = timeutils.utcnow()
            expires = timeutils.normalize_time(
                timeutils.parse_isotime(expires_at))
            if now > expires:
                raise exception.Unauthorized(_('Request token is expired'))

        # put the roles in a set for easy comparison
        authed_roles = set()
        for role in roles:
            authed_roles.add(role['id'])

        # verify the authorizing user has the roles
        user_token = utils.get_token_ref(context)
        user_id = user_token.user_id
        project_id = req_token['requested_project_id']
        user_roles = self.assignment_api.get_roles_for_user_and_project(
            user_id, project_id)
        cred_set = set(user_roles)

        if not cred_set.issuperset(authed_roles):
            msg = _('authorizing user does not have role required')
            raise exception.Unauthorized(message=msg)

        # create list of just the id's for the backend
        role_list = list(authed_roles)

        # verify the user has the project too
        req_project_id = req_token['requested_project_id']
        user_projects = self.assignment_api.list_projects_for_user(user_id)
        for user_project in user_projects:
            if user_project['id'] == req_project_id:
                break
        else:
            msg = _("User is not a member of the requested project")
            raise exception.Unauthorized(message=msg)

        # finally authorize the token
        authed_token = self.oauth_api.authorize_request_token(
            request_token_id, user_id, role_list)

        to_return = {'token': {'oauth_verifier': authed_token['verifier']}}
        return to_return
