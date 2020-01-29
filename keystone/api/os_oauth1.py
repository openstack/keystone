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

# This file handles all flask-restful resources for /v3/OS-OAUTH1/

import flask
import flask_restful
import http.client
from oslo_log import log
from oslo_utils import timeutils
from urllib import parse as urlparse
from werkzeug import exceptions

from keystone.api._shared import json_home_relations
from keystone.common import authorization
from keystone.common import context
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone import notifications
from keystone.oauth1 import core as oauth1
from keystone.oauth1 import schema
from keystone.oauth1 import validator
from keystone.server import flask as ks_flask


LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs
ENFORCER = rbac_enforcer.RBACEnforcer
CONF = keystone.conf.CONF


_build_resource_relation = json_home_relations.os_oauth1_resource_rel_func
_build_parameter_relation = json_home_relations.os_oauth1_parameter_rel_func

_ACCESS_TOKEN_ID_PARAMETER_RELATION = _build_parameter_relation(
    parameter_name='access_token_id')


def _normalize_role_list(authorize_roles):
    roles = set()
    for role in authorize_roles:
        if role.get('id'):
            roles.add(role['id'])
        else:
            roles.add(PROVIDERS.role_api.get_unique_role_by_name(
                role['name'])['id'])
    return roles


def _update_url_scheme():
    """Update request url scheme with base url scheme."""
    url = ks_flask.base_url()
    url_scheme = list(urlparse.urlparse(url))[0]
    req_url_list = list(urlparse.urlparse(flask.request.url))
    req_url_list[0] = url_scheme
    req_url = urlparse.urlunparse(req_url_list)
    return req_url


class _OAuth1ResourceBase(flask_restful.Resource):
    def get(self):
        # GET is not allowed, however flask restful doesn't handle "GET" not
        # being allowed cleanly. Here we explicitly mark is as not allowed. All
        # other methods not defined would raise a method NotAllowed error and
        # this would not be needed.
        raise exceptions.MethodNotAllowed(valid_methods=['POST'])


class ConsumerResource(ks_flask.ResourceBase):
    collection_key = 'consumers'
    member_key = 'consumer'
    api_prefix = '/OS-OAUTH1'
    json_home_resource_rel_func = _build_resource_relation
    json_home_parameter_rel_func = _build_parameter_relation

    def _list_consumers(self):
        ENFORCER.enforce_call(action='identity:list_consumers')
        return self.wrap_collection(PROVIDERS.oauth_api.list_consumers())

    def _get_consumer(self, consumer_id):
        ENFORCER.enforce_call(action='identity:get_consumer')
        return self.wrap_member(PROVIDERS.oauth_api.get_consumer(consumer_id))

    def get(self, consumer_id=None):
        if consumer_id is None:
            return self._list_consumers()
        return self._get_consumer(consumer_id)

    def post(self):
        ENFORCER.enforce_call(action='identity:create_consumer')
        consumer = (flask.request.get_json(force=True, silent=True) or {}).get(
            'consumer', {})
        consumer = self._normalize_dict(consumer)
        validation.lazy_validate(schema.consumer_create, consumer)
        consumer = self._assign_unique_id(consumer)
        ref = PROVIDERS.oauth_api.create_consumer(
            consumer, initiator=self.audit_initiator)
        return self.wrap_member(ref), http.client.CREATED

    def delete(self, consumer_id):
        ENFORCER.enforce_call(action='identity:delete_consumer')
        reason = (
            'Invalidating token cache because consumer %(consumer_id)s has '
            'been deleted. Authorization for users with OAuth tokens will be '
            'recalculated and enforced accordingly the next time they '
            'authenticate or validate a token.' %
            {'consumer_id': consumer_id}
        )
        notifications.invalidate_token_cache_notification(reason)
        PROVIDERS.oauth_api.delete_consumer(
            consumer_id, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT

    def patch(self, consumer_id):
        ENFORCER.enforce_call(action='identity:update_consumer')
        consumer = (flask.request.get_json(force=True, silent=True) or {}).get(
            'consumer', {})
        validation.lazy_validate(schema.consumer_update, consumer)
        consumer = self._normalize_dict(consumer)
        self._require_matching_id(consumer)
        ref = PROVIDERS.oauth_api.update_consumer(
            consumer_id, consumer, initiator=self.audit_initiator)
        return self.wrap_member(ref)


class RequestTokenResource(_OAuth1ResourceBase):
    @ks_flask.unenforced_api
    def post(self):
        oauth_headers = oauth1.get_oauth_headers(flask.request.headers)
        consumer_id = oauth_headers.get('oauth_consumer_key')
        requested_project_id = flask.request.headers.get(
            'Requested-Project-Id')

        if not consumer_id:
            raise exception.ValidationError(
                attribute='oauth_consumer_key', target='request')
        if not requested_project_id:
            raise exception.ValidationError(
                attribute='Requested-Project-Id', target='request')

        # NOTE(stevemar): Ensure consumer and requested project exist
        PROVIDERS.resource_api.get_project(requested_project_id)
        PROVIDERS.oauth_api.get_consumer(consumer_id)

        url = _update_url_scheme()
        req_headers = {'Requested-Project-Id': requested_project_id}
        req_headers.update(flask.request.headers)
        request_verifier = oauth1.RequestTokenEndpoint(
            request_validator=validator.OAuthValidator(),
            token_generator=oauth1.token_generator)
        h, b, s = request_verifier.create_request_token_response(
            url, http_method='POST', body=flask.request.args,
            headers=req_headers)
        if not b:
            msg = _('Invalid signature')
            raise exception.Unauthorized(message=msg)
        # show the details of the failure.
        oauth1.validate_oauth_params(b)
        request_token_duration = CONF.oauth1.request_token_duration
        token_ref = PROVIDERS.oauth_api.create_request_token(
            consumer_id,
            requested_project_id,
            request_token_duration,
            initiator=notifications.build_audit_initiator())

        result = ('oauth_token=%(key)s&oauth_token_secret=%(secret)s'
                  % {'key': token_ref['id'],
                     'secret': token_ref['request_secret']})

        if CONF.oauth1.request_token_duration > 0:
            expiry_bit = '&oauth_expires_at=%s' % token_ref['expires_at']
            result += expiry_bit

        resp = flask.make_response(result, http.client.CREATED)
        resp.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return resp


class AccessTokenResource(_OAuth1ResourceBase):
    @ks_flask.unenforced_api
    def post(self):
        oauth_headers = oauth1.get_oauth_headers(flask.request.headers)
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

        req_token = PROVIDERS.oauth_api.get_request_token(
            request_token_id)

        expires_at = req_token['expires_at']
        if expires_at:
            now = timeutils.utcnow()
            expires = timeutils.normalize_time(
                timeutils.parse_isotime(expires_at))
            if now > expires:
                raise exception.Unauthorized(_('Request token is expired'))

        url = _update_url_scheme()
        access_verifier = oauth1.AccessTokenEndpoint(
            request_validator=validator.OAuthValidator(),
            token_generator=oauth1.token_generator)
        try:
            h, b, s = access_verifier.create_access_token_response(
                url,
                http_method='POST',
                body=flask.request.args,
                headers=dict(flask.request.headers))
        except NotImplementedError:
            # Client key or request token validation failed, since keystone
            # does not yet support dummy client or dummy request token,
            # so we will raise unauthorized exception instead.
            try:
                PROVIDERS.oauth_api.get_consumer(consumer_id)
            except exception.NotFound:
                msg = _('Provided consumer does not exist.')
                LOG.warning('Provided consumer does not exist.')
                raise exception.Unauthorized(message=msg)
            if req_token['consumer_id'] != consumer_id:
                msg = ('Provided consumer key does not match stored consumer '
                       'key.')
                tr_msg = _('Provided consumer key does not match stored '
                           'consumer key.')
                LOG.warning(msg)
                raise exception.Unauthorized(message=tr_msg)
        # The response body is empty since either one of the following reasons
        if not b:
            if req_token['verifier'] != oauth_verifier:
                msg = 'Provided verifier does not match stored verifier'
                tr_msg = _('Provided verifier does not match stored verifier')
            else:
                msg = 'Invalid signature'
                tr_msg = _('Invalid signature')
            LOG.warning(msg)
            raise exception.Unauthorized(message=tr_msg)
        # show the details of the failure
        oauth1.validate_oauth_params(b)
        if not req_token.get('authorizing_user_id'):
            msg = _('Request Token does not have an authorizing user id.')
            LOG.warning('Request Token does not have an authorizing user id.')
            raise exception.Unauthorized(message=msg)

        access_token_duration = CONF.oauth1.access_token_duration
        token_ref = PROVIDERS.oauth_api.create_access_token(
            request_token_id,
            access_token_duration,
            initiator=notifications.build_audit_initiator())

        result = ('oauth_token=%(key)s&oauth_token_secret=%(secret)s'
                  % {'key': token_ref['id'],
                     'secret': token_ref['access_secret']})

        if CONF.oauth1.access_token_duration > 0:
            expiry_bit = '&oauth_expires_at=%s' % (token_ref['expires_at'])
            result += expiry_bit

        resp = flask.make_response(result, http.client.CREATED)
        resp.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return resp


class AuthorizeResource(_OAuth1ResourceBase):
    def put(self, request_token_id):
        ENFORCER.enforce_call(action='identity:authorize_request_token')
        roles = (flask.request.get_json(force=True, silent=True) or {}).get(
            'roles', [])
        validation.lazy_validate(schema.request_token_authorize, roles)
        ctx = flask.request.environ[context.REQUEST_CONTEXT_ENV]
        if ctx.is_delegated_auth:
            raise exception.Forbidden(
                _('Cannot authorize a request token with a token issued via '
                  'delegation.'))

        req_token = PROVIDERS.oauth_api.get_request_token(request_token_id)

        expires_at = req_token['expires_at']
        if expires_at:
            now = timeutils.utcnow()
            expires = timeutils.normalize_time(
                timeutils.parse_isotime(expires_at))
            if now > expires:
                raise exception.Unauthorized(_('Request token is expired'))

        authed_roles = _normalize_role_list(roles)

        # verify the authorizing user has the roles
        try:
            auth_context = flask.request.environ[
                authorization.AUTH_CONTEXT_ENV]
            user_token_ref = auth_context['token']
        except KeyError:
            LOG.warning("Couldn't find the auth context.")
            raise exception.Unauthorized()

        user_id = user_token_ref.user_id
        project_id = req_token['requested_project_id']
        user_roles = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            user_id, project_id)
        cred_set = set(user_roles)

        if not cred_set.issuperset(authed_roles):
            msg = _('authorizing user does not have role required')
            raise exception.Unauthorized(message=msg)

        # create least of just the id's for the backend
        role_ids = list(authed_roles)

        # finally authorize the token
        authed_token = PROVIDERS.oauth_api.authorize_request_token(
            request_token_id, user_id, role_ids)

        to_return = {'token': {'oauth_verifier': authed_token['verifier']}}
        return to_return


class OSAuth1API(ks_flask.APIBase):
    _name = 'OS-OAUTH1'
    _import_name = __name__
    _api_url_prefix = '/OS-OAUTH1'
    resources = [ConsumerResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=RequestTokenResource,
            url='/request_token',
            resource_kwargs={},
            rel='request_tokens',
            resource_relation_func=_build_resource_relation
        ),
        ks_flask.construct_resource_map(
            resource=AccessTokenResource,
            url='/access_token',
            rel='access_tokens',
            resource_kwargs={},
            resource_relation_func=_build_resource_relation
        ),
        ks_flask.construct_resource_map(
            resource=AuthorizeResource,
            url='/authorize/<string:request_token_id>',
            resource_kwargs={},
            rel='authorize_request_token',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'request_token_id': _build_parameter_relation(
                    parameter_name='request_token_id')
            })]


APIs = (OSAuth1API,)
