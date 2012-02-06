# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone import token
from keystone.common import kvs


class Token(kvs.Base, token.Driver):
    # Public interface
    def get_token(self, token_id):
        return self.db.get('token-%s' % token_id)

    def create_token(self, token_id, data):
        self.db.set('token-%s' % token_id, data)
        return data

    def delete_token(self, token_id):
        return self.db.delete('token-%s' % token_id)
