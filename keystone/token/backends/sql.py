# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

from keystone.common import sql
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import token


class TokenModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'token'
    attributes = ['id', 'expires', 'user_id', 'trust_id']
    id = sql.Column(sql.String(64), primary_key=True)
    expires = sql.Column(sql.DateTime(), default=None)
    extra = sql.Column(sql.JsonBlob())
    valid = sql.Column(sql.Boolean(), default=True, nullable=False)
    user_id = sql.Column(sql.String(64))
    trust_id = sql.Column(sql.String(64))
    __table_args__ = (
        sql.Index('ix_token_expires', 'expires'),
        sql.Index('ix_token_valid', 'valid')
    )


class Token(sql.Base, token.Driver):
    # Public interface
    def get_token(self, token_id):
        if token_id is None:
            raise exception.TokenNotFound(token_id=token_id)
        session = self.get_session()
        token_ref = session.query(TokenModel).get(token_id)
        if not token_ref or not token_ref.valid:
            raise exception.TokenNotFound(token_id=token_id)
        return token_ref.to_dict()

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        if not data_copy.get('expires'):
            data_copy['expires'] = token.default_expire_time()
        if not data_copy.get('user_id'):
            data_copy['user_id'] = data_copy['user']['id']

        token_ref = TokenModel.from_dict(data_copy)
        token_ref.valid = True
        session = self.get_session()
        with session.begin():
            session.add(token_ref)
            session.flush()
        return token_ref.to_dict()

    def delete_token(self, token_id):
        session = self.get_session()
        with session.begin():
            token_ref = session.query(TokenModel).get(token_id)
            if not token_ref or not token_ref.valid:
                raise exception.TokenNotFound(token_id=token_id)
            token_ref.valid = False
            session.flush()

    def delete_tokens(self, user_id, tenant_id=None, trust_id=None,
                      consumer_id=None):
        """Deletes all tokens in one session

        The user_id will be ignored if the trust_id is specified. user_id
        will always be specified.
        If using a trust, the token's user_id is set to the trustee's user ID
        or the trustor's user ID, so will use trust_id to query the tokens.

        """
        session = self.get_session()
        with session.begin():
            now = timeutils.utcnow()
            query = session.query(TokenModel)
            query = query.filter_by(valid=True)
            query = query.filter(TokenModel.expires > now)
            if trust_id:
                query = query.filter(TokenModel.trust_id == trust_id)
            else:
                query = query.filter(TokenModel.user_id == user_id)

            for token_ref in query.all():
                if tenant_id:
                    token_ref_dict = token_ref.to_dict()
                    if not self._tenant_matches(tenant_id, token_ref_dict):
                        continue
                if consumer_id:
                    token_ref_dict = token_ref.to_dict()
                    if not self._consumer_matches(consumer_id, token_ref_dict):
                        continue

                token_ref.valid = False

            session.flush()

    def _tenant_matches(self, tenant_id, token_ref_dict):
        return ((tenant_id is None) or
                (token_ref_dict.get('tenant') and
                 token_ref_dict['tenant'].get('id') == tenant_id))

    def _consumer_matches(self, consumer_id, ref):
        if consumer_id is None:
            return True
        else:
            try:
                oauth = ref['token_data']['token'].get('OS-OAUTH1', {})
                return oauth and oauth['consumer_id'] == consumer_id
            except KeyError:
                return False

    def _list_tokens_for_trust(self, trust_id):
        session = self.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires > now)
        query = query.filter(TokenModel.trust_id == trust_id)

        token_references = query.filter_by(valid=True)
        for token_ref in token_references:
            token_ref_dict = token_ref.to_dict()
            tokens.append(token_ref_dict['id'])
        return tokens

    def _list_tokens_for_user(self, user_id, tenant_id=None):
        session = self.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires > now)
        query = query.filter(TokenModel.user_id == user_id)

        token_references = query.filter_by(valid=True)
        for token_ref in token_references:
            token_ref_dict = token_ref.to_dict()
            if self._tenant_matches(tenant_id, token_ref_dict):
                tokens.append(token_ref['id'])
        return tokens

    def _list_tokens_for_consumer(self, user_id, consumer_id):
        tokens = []
        session = self.get_session()
        with session.begin():
            now = timeutils.utcnow()
            query = session.query(TokenModel)
            query = query.filter(TokenModel.expires > now)
            query = query.filter(TokenModel.user_id == user_id)
            token_references = query.filter_by(valid=True)

            for token_ref in token_references:
                token_ref_dict = token_ref.to_dict()
                if self._consumer_matches(consumer_id, token_ref_dict):
                    tokens.append(token_ref_dict['id'])
            session.flush()
        return tokens

    def list_tokens(self, user_id, tenant_id=None, trust_id=None,
                    consumer_id=None):
        if trust_id:
            return self._list_tokens_for_trust(trust_id)
        if consumer_id:
            return self._list_tokens_for_consumer(user_id, consumer_id)
        else:
            return self._list_tokens_for_user(user_id, tenant_id)

    def list_revoked_tokens(self):
        session = self.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires > now)
        token_references = query.filter_by(valid=False)
        for token_ref in token_references:
            record = {
                'id': token_ref['id'],
                'expires': token_ref['expires'],
            }
            tokens.append(record)
        return tokens

    def flush_expired_tokens(self):
        session = self.get_session()

        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires < timeutils.utcnow())
        query.delete(synchronize_session=False)

        session.flush()
