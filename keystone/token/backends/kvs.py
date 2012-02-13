# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone.common import kvs
from keystone import exception
from keystone import token


class Token(kvs.Base, token.Driver):
    # Public interface
    def get_token(self, token_id):
        try:
            return self.db['token-%s' % token_id]
        except KeyError:
            raise exception.TokenNotFound(token_id=token_id)

    def create_token(self, token_id, data):
        self.db.set('token-%s' % token_id, data)
        return data

    def delete_token(self, token_id):
        try:
            return self.db.delete('token-%s' % token_id)
        except KeyError:
            raise exception.TokenNotFound(token_id=token_id)
