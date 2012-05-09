# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
import datetime

from keystone.common import kvs
from keystone import exception
from keystone import token


class Token(kvs.Base, token.Driver):
    # Public interface
    def get_token(self, token_id):
        token = self.db.get('token-%s' % token_id)
        if (token and (token['expires'] is None
                       or token['expires'] > datetime.datetime.utcnow())):
            return token
        else:
            raise exception.TokenNotFound(token_id=token_id)

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        if 'expires' not in data:
            data_copy['expires'] = self._get_default_expire_time()
        self.db.set('token-%s' % token_id, data_copy)
        return copy.deepcopy(data_copy)

    def delete_token(self, token_id):
        try:
            return self.db.delete('token-%s' % token_id)
        except KeyError:
            raise exception.TokenNotFound(token_id=token_id)

    def list_tokens(self, user_id):
        tokens = []
        now = datetime.datetime.utcnow()
        for token, user_ref in self.db.items():
            if not token.startswith('token-'):
                continue
            if 'user' not in user_ref:
                continue
            if user_ref['user'].get('id') != user_id:
                continue
            if user_ref.get('expires') and user_ref.get('expires') < now:
                continue
            tokens.append(token.split('-', 1)[1])
        return tokens
