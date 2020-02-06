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

import flask
from oslo_log import log

from keystone.auth.plugins import base
from keystone.auth.plugins import mapped
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _


LOG = log.getLogger(__name__)

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class Token(base.AuthMethodHandler):

    def _get_token_ref(self, auth_payload):
        token_id = auth_payload['id']
        return PROVIDERS.token_provider_api.validate_token(token_id)

    def authenticate(self, auth_payload):
        if 'id' not in auth_payload:
            raise exception.ValidationError(attribute='id',
                                            target='token')
        token = self._get_token_ref(auth_payload)
        if token.is_federated and PROVIDERS.federation_api:
            response_data = mapped.handle_scoped_token(
                token, PROVIDERS.federation_api,
                PROVIDERS.identity_api
            )
        else:
            response_data = token_authenticate(token)

        # NOTE(notmorgan): The Token auth method is *very* special and sets the
        # previous values to the method_names. This is because it can be used
        # for re-scoping and we want to maintain the values. Most
        # AuthMethodHandlers do no such thing and this is not required.
        response_data.setdefault('method_names', []).extend(token.methods)

        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)


def token_authenticate(token):
    response_data = {}
    try:

        # Do not allow tokens used for delegation to
        # create another token, or perform any changes of
        # state in Keystone. To do so is to invite elevation of
        # privilege attacks

        json_body = flask.request.get_json(silent=True, force=True) or {}
        project_scoped = 'project' in json_body['auth'].get(
            'scope', {}
        )
        domain_scoped = 'domain' in json_body['auth'].get(
            'scope', {}
        )

        if token.oauth_scoped:
            raise exception.ForbiddenAction(
                action=_(
                    'Using OAuth-scoped token to create another token. '
                    'Create a new OAuth-scoped token instead'))
        elif token.trust_scoped:
            raise exception.ForbiddenAction(
                action=_(
                    'Using trust-scoped token to create another token. '
                    'Create a new trust-scoped token instead'))
        elif token.system_scoped and (project_scoped or domain_scoped):
            raise exception.ForbiddenAction(
                action=_(
                    'Using a system-scoped token to create a project-scoped '
                    'or domain-scoped token is not allowed.'
                )
            )

        if not CONF.token.allow_rescope_scoped_token:
            # Do not allow conversion from scoped tokens.
            if token.project_scoped or token.domain_scoped:
                raise exception.ForbiddenAction(
                    action=_('rescope a scoped token'))

        # New tokens maintain the audit_id of the original token in the
        # chain (if possible) as the second element in the audit data
        # structure. Look for the last element in the audit data structure
        # which will be either the audit_id of the token (in the case of
        # a token that has not been rescoped) or the audit_chain id (in
        # the case of a token that has been rescoped).
        try:
            token_audit_id = token.parent_audit_id or token.audit_id
        except IndexError:
            # NOTE(morganfainberg): In the case this is a token that was
            # issued prior to audit id existing, the chain is not tracked.
            token_audit_id = None

        # To prevent users from never having to re-authenticate, the original
        # token expiration time is maintained in the new token. Not doing this
        # would make it possible for a user to continuously bump token
        # expiration through token rescoping without proving their identity.
        response_data.setdefault('expires_at', token.expires_at)
        response_data['audit_id'] = token_audit_id
        response_data.setdefault('user_id', token.user_id)

        return response_data

    except AssertionError as e:
        LOG.error(e)
        raise exception.Unauthorized(e)
