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

from keystone.common import kvs
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import token


class Token(kvs.Base, token.Driver):

    # Public interface
    def get_token(self, token_id):
        token_id = self.token_to_key(token_id)
        try:
            token = self.db.get('token-%s' % token_id)
        except exception.NotFound:
            raise exception.TokenNotFound(token_id=token_id)
        if token['expires'] is None or token['expires'] > timeutils.utcnow():
            return copy.deepcopy(token)
        else:
            raise exception.TokenNotFound(token_id=token_id)

    def create_token(self, token_id, data):
        token_id = self.token_to_key(token_id)
        data_copy = copy.deepcopy(data)
        if 'expires' not in data:
            data_copy['expires'] = self._get_default_expire_time()
        self.db.set('token-%s' % token_id, data_copy)
        return copy.deepcopy(data_copy)

    def delete_token(self, token_id):
        token_id = self.token_to_key(token_id)
        try:
            token_ref = self.get_token(token_id)
            self.db.delete('token-%s' % token_id)
            self.db.set('revoked-token-%s' % token_id, token_ref)
        except exception.NotFound:
            raise exception.TokenNotFound(token_id=token_id)

    def list_tokens(self, user_id, tenant_id=None):
        tokens = []
        now = timeutils.utcnow()
        for token, ref in self.db.items():
            if not token.startswith('token-'):
                continue
            user = ref.get('user')
            if not user:
                continue
            if user.get('id') != user_id:
                continue
            if ref.get('expires') and ref.get('expires') < now:
                continue
            if tenant_id is not None:
                tenant = ref.get('tenant')
                if not tenant:
                    continue
                if tenant.get('id') != tenant_id:
                    continue
            tokens.append(token.split('-', 1)[1])
        return tokens

    def list_revoked_tokens(self):
        tokens = []
        for token, token_ref in self.db.items():
            if not token.startswith('revoked-token-'):
                continue
            record = {}
            record['id'] = token_ref['id']
            record['expires'] = token_ref['expires']
            tokens.append(record)
        return tokens
