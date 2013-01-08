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


from keystone.common import dependency
from keystone.common import logging
from keystone import auth
from keystone import exception
from keystone import token


METHOD_NAME = 'token'

LOG = logging.getLogger(__name__)


class Token(auth.AuthMethodHandler):
    def __init__(self):
        self.token_api = token.Manager()

    def authenticate(self, context, auth_payload, user_context):
        try:
            if 'id' not in auth_payload:
                raise exception.ValidationError(attribute='id',
                                                target=METHOD_NAME)
            token_id = auth_payload['id']
            token_ref = self.token_api.get_token(context, token_id)
            user_context.setdefault('user_id',
                                    token_ref['token_data']['user']['id'])
            user_context.setdefault('expires',
                                    token_ref['expires'])
            user_context['extras'].update(token_ref['token_data']['extras'])
            user_context['method_names'] += token_ref['token_data']['methods']
        except AssertionError as e:
            LOG.error(e)
            raise exception.Unauthorized(e)
