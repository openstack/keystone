# vim: tabstop=4 shiftwidth=4 softtabstop=4

from __future__ import absolute_import
import copy

import memcache

from keystone import config
from keystone import exception
from keystone import token
from keystone.common import utils


CONF = config.CONF
config.register_str('servers', group='memcache', default='localhost:11211')


class Token(token.Driver):
    def __init__(self, client=None):
        self._memcache_client = client

    @property
    def client(self):
        return self._memcache_client or self._get_memcache_client()

    def _get_memcache_client(self):
        memcache_servers = CONF.memcache.servers.split(',')
        self._memcache_client = memcache.Client(memcache_servers, debug=0)
        return self._memcache_client

    def _prefix_token_id(self, token_id):
        return 'token-%s' % token_id.encode('utf-8')

    def get_token(self, token_id):
        ptk = self._prefix_token_id(token_id)
        token = self.client.get(ptk)
        if token is None:
            raise exception.TokenNotFound(token_id=token_id)

        return token

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        ptk = self._prefix_token_id(token_id)
        if 'expires' not in data_copy:
            data_copy['expires'] = self._get_default_expire_time()
        kwargs = {}
        if data_copy['expires'] is not None:
            expires_ts = utils.unixtime(data_copy['expires'])
            kwargs['time'] = expires_ts
        self.client.set(ptk, data_copy, **kwargs)
        return copy.deepcopy(data_copy)

    def delete_token(self, token_id):
        # Test for existence
        self.get_token(token_id)
        ptk = self._prefix_token_id(token_id)
        return self.client.delete(ptk)
