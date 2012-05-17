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

from keystone.common import sql
from keystone import exception
from keystone import token


class TokenModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'token'
    id = sql.Column(sql.String(64), primary_key=True)
    expires = sql.Column(sql.DateTime(), default=None)
    extra = sql.Column(sql.JsonBlob())

    @classmethod
    def from_dict(cls, token_dict):
        # shove any non-indexed properties into extra
        extra = copy.deepcopy(token_dict)
        data = {}
        for k in ('id', 'expires'):
            data[k] = extra.pop(k, None)
        data['extra'] = extra
        return cls(**data)

    def to_dict(self):
        out = copy.deepcopy(self.extra)
        out['id'] = self.id
        out['expires'] = self.expires
        return out


class Token(sql.Base, token.Driver):
    # Public interface
    def get_token(self, token_id):
        session = self.get_session()
        token_ref = session.query(TokenModel).filter_by(id=token_id).first()
        now = datetime.datetime.utcnow()
        if token_ref and (not token_ref.expires or now < token_ref.expires):
            return token_ref.to_dict()
        else:
            raise exception.TokenNotFound(token_id=token_id)

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        if 'expires' not in data_copy:
            data_copy['expires'] = self._get_default_expire_time()

        token_ref = TokenModel.from_dict(data_copy)
        token_ref.id = token_id

        session = self.get_session()
        with session.begin():
            session.add(token_ref)
            session.flush()
        return token_ref.to_dict()

    def delete_token(self, token_id):
        session = self.get_session()
        token_ref = session.query(TokenModel)\
                           .filter_by(id=token_id)\
                           .first()
        if not token_ref:
            raise exception.TokenNotFound(token_id=token_id)

        with session.begin():
            session.delete(token_ref)
            session.flush()

    def list_tokens(self, user_id):
        session = self.get_session()
        tokens = []
        now = datetime.datetime.utcnow()
        for token_ref in session.query(TokenModel)\
                                .filter(TokenModel.expires > now):
            token_ref_dict = token_ref.to_dict()
            if 'user' not in token_ref_dict:
                continue
            if token_ref_dict['user'].get('id') != user_id:
                continue
            tokens.append(token_ref['id'])
        return tokens
