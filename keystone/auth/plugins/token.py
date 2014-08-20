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

from keystone import auth
from keystone.common import dependency
from keystone.common import wsgi
from keystone import exception
from keystone.models import token_model
from keystone.openstack.common import log


LOG = log.getLogger(__name__)


@dependency.requires('token_provider_api')
class Token(auth.AuthMethodHandler):

    method = 'token'

    def authenticate(self, context, auth_payload, user_context):
        try:
            if 'id' not in auth_payload:
                raise exception.ValidationError(attribute='id',
                                                target=self.method)
            token_id = auth_payload['id']
            response = self.token_provider_api.validate_token(token_id)
            token_ref = token_model.KeystoneToken(token_id=token_id,
                                                  token_data=response)

            # Do not allow tokens used for delegation to
            # create another token, or perform any changes of
            # state in Keystone. To do so is to invite elevation of
            # privilege attacks
            if token_ref.oauth_scoped or token_ref.trust_scoped:
                raise exception.Forbidden()

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
            LOG.error(e)
            raise exception.Unauthorized(e)
