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

import datetime
import time
import uuid

import memcache

from keystone import exception
from keystone import test
from keystone.token.backends import memcache as token_memcache

import test_backend


class MemcacheClient(object):
    """Replicates a tiny subset of memcached client interface."""

    def __init__(self, *args, **kwargs):
        """Ignores the passed in args."""
        self.cache = {}

    def check_key(self, key):
        if not isinstance(key, str):
            raise memcache.Client.MemcachedStringEncodingError()

    def get(self, key):
        """Retrieves the value for a key or None."""
        self.check_key(key)
        obj = self.cache.get(key)
        now = time.mktime(datetime.datetime.utcnow().utctimetuple())
        if obj and (obj[1] == 0 or obj[1] > now):
            return obj[0]
        else:
            raise exception.TokenNotFound(token_id=key)

    def set(self, key, value, time=0):
        """Sets the value for a key."""
        self.check_key(key)
        self.cache[key] = (value, time)
        return True

    def delete(self, key):
        self.check_key(key)
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

    def test_get_unicode(self):
        token_id = unicode(uuid.uuid4().hex)
        data = {'id': token_id, 'a': 'b'}
        self.token_api.create_token(token_id, data)
        self.token_api.get_token(token_id)
