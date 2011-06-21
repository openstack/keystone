# vim: tabstop=4 shiftwidth=4 softtabstop=4

# the token interfaces

import uuid

from keystonelight import identity

STORE = {}

class Manager(object):
    def create_token(self, context, data):
        token = uuid.uuid4().hex
        STORE[token] = data
        return token

    def validate_token(self, context, token_id):
        """Return info for a token if it is valid."""
        return STORE.get(token_id)

    def revoke_token(self, context, token_id):
        STORE.pop(token_id)
