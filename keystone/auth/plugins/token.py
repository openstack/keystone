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

from oslo_config import cfg
from oslo_log import log
import six

from keystone import auth
from keystone.auth.plugins import mapped
from keystone.common import dependency
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model


LOG = log.getLogger(__name__)

CONF = cfg.CONF


@dependency.requires('federation_api', 'identity_api', 'token_provider_api')
class Token(auth.AuthMethodHandler):

    def _get_token_ref(self, auth_payload):
        token_id = auth_payload['id']
        response = self.token_provider_api.validate_token(token_id)
        return token_model.KeystoneToken(token_id=token_id,
                                         token_data=response)

    def authenticate(self, context, auth_payload, user_context):
        if 'id' not in auth_payload:
            raise exception.ValidationError(attribute='id',
                                            target='token')
        token_ref = self._get_token_ref(auth_payload)
        if token_ref.is_federated_user and self.federation_api:
            mapped.handle_scoped_token(
                context, auth_payload, user_context, token_ref,
                self.federation_api, self.identity_api,
                self.token_provider_api)
        else:
            token_authenticate(context, auth_payload, user_context, token_ref)


def token_authenticate(context, auth_payload, user_context, token_ref):
    try:

        # Do not allow tokens used for delegation to
        # create another token, or perform any changes of
        # state in Keystone. To do so is to invite elevation of
        # privilege attacks

        if token_ref.oauth_scoped or token_ref.trust_scoped:
            raise exception.Forbidden()

        if not CONF.token.allow_rescope_scoped_token:
            # Do not allow conversion from scoped tokens.
            if token_ref.project_scoped or token_ref.domain_scoped:
                raise exception.Forbidden(action=_("rescope a scoped token"))

        wsgi.validate_token_bind(context, token_ref)

        # New tokens maintain the audit_id of the original token in the
        # chain (if possible) as the second element in the audit data
        # structure. Look for the last element in the audit data structure
        # which will be either the audit_id of the token (in the case of
        # a token that has not been rescoped) or the audit_chain id (in
        # the case of a token that has been rescoped).
        try:
            token_audit_id = token_ref.get('audit_ids', [])[-1]
        except IndexError:
            # NOTE(morganfainberg): In the case this is a token that was
            # issued prior to audit id existing, the chain is not tracked.
            token_audit_id = None

        user_context.setdefault('expires_at', token_ref.expires)
        user_context['audit_id'] = token_audit_id
        user_context.setdefault('user_id', token_ref.user_id)
        # TODO(morganfainberg: determine if token 'extras' can be removed
        # from the user_context
        user_context['extras'].update(token_ref.get('extras', {}))
        user_context['method_names'].extend(token_ref.methods)

    except AssertionError as e:
        LOG.error(six.text_type(e))
        raise exception.Unauthorized(e)
