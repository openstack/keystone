# vim: tabstop=4 shiftwidth=4 softtabstop=4

# the token interfaces

from keystonelight import identity

class TokenManager(object):
    def create_token(self, context, data):
        pass

    def validate_token(self, context, token_id):
        """Return info for a token if it is valid."""
        pass

    def revoke_token(self, context, token_id):
        pass
