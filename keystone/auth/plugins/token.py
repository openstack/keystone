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
from keystone.openstack.common import log
from keystone.openstack.common import timeutils


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
            # For V3 tokens, the essential data is under the 'token' value.
            # For V2, the comparable data was nested under 'access'.
            token_ref = response.get('token', response.get('access'))

            #Do not allow tokens used for delegation to
            #create another token, or perform any changes of
            #state in Keystone. TO do so is to invite elevation of
            #privilege attacks
            if 'OS-TRUST:trust' in token_ref:
                raise exception.Forbidden()
            if 'trust' in token_ref:
                raise exception.Forbidden()
            if 'trust_id' in token_ref.get('metadata', {}):
                raise exception.Forbidden()
            if 'OS-OAUTH1' in token_ref:
                raise exception.Forbidden()

            wsgi.validate_token_bind(context, token_ref)

            #new tokens are not allowed to extend the expiration
            #time of an old token, otherwise, they could be extened
            #forever.   The expiration value was stored at different
            #locations in v2 and v3 tokens.
            expires_at = token_ref.get('expires_at')
            if not expires_at:
                expires_at = token_ref.get('expires')
            if not expires_at:
                expires_at = timeutils.normalize_time(
                    timeutils.parse_isotime(token_ref['token']['expires']))

            user_context.setdefault('expires_at', expires_at)
            user_context.setdefault('user_id', token_ref['user']['id'])
            user_context['extras'].update(token_ref.get('extras', {}))
            user_context['method_names'].extend(token_ref.get('methods', []))

        except AssertionError as e:
            LOG.error(e)
            raise exception.Unauthorized(e)
