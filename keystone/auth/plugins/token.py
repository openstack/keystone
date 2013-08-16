# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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
from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common import log as logging
from keystone.openstack.common import timeutils
from keystone.token import provider


METHOD_NAME = 'token'

LOG = logging.getLogger(__name__)


class Token(auth.AuthMethodHandler):
    def __init__(self):
        self.provider = provider.Manager()

    def authenticate(self, context, auth_payload, user_context):
        try:
            if 'id' not in auth_payload:
                raise exception.ValidationError(attribute='id',
                                                target=METHOD_NAME)
            token_id = auth_payload['id']
            response = self.provider.validate_token(token_id)
            #for V3 tokens, the esential data is under  the 'token' value.
            #For V2, the comparable data was nested under 'access'
            token_ref = response.get('token', response.get('access'))

            #Do not allow tokens used for delegation to
            #create another token, or perform any changes of
            #state in Keystone. TO do so is to invite elevation of
            #priviledge attacks
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
