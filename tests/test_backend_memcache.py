# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone import exception
from keystone import test
from keystone.token.backends import memcache as token_memcache

import test_backend


class MemcacheClient(object):
    """Replicates a tiny subset of memcached client interface."""

    def __init__(self, *args, **kwargs):
        """Ignores the passed in args."""
        self.cache = {}

    def get(self, key):
        """Retrieves the value for a key or None."""
        try:
            return self.cache[key]
        except KeyError:
            raise exception.TokenNotFound(token_id=key)

    def set(self, key, value):
        """Sets the value for a key."""
        self.cache[key] = value
        return True

    def delete(self, key):
        try:
            del self.cache[key]
        except KeyError:
            #NOTE(bcwaldon): python-memcached always returns the same value
            pass


class MemcacheToken(test.TestCase, test_backend.TokenTests):
    def setUp(self):
        super(MemcacheToken, self).setUp()
        fake_client = MemcacheClient()
        self.token_api = token_memcache.Token(client=fake_client)
