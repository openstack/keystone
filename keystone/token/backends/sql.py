# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
        now = datetime.datetime.now()
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
