# Copyright 2013 Metacloud, Inc.
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

"""
Keystone In-Memory Dogpile.cache backend implementation.
"""

import copy

from dogpile.cache import api


NO_VALUE = api.NO_VALUE


class MemoryBackend(api.CacheBackend):
    """A backend that uses a plain dictionary.

    There is no size management, and values which are placed into the
    dictionary will remain until explicitly removed. Note that Dogpile's
    expiration of items is based on timestamps and does not remove them from
    the cache.

    E.g.::

        from dogpile.cache import make_region

        region = make_region().configure(
            'keystone.common.kvs.Memory'
        )
    """
    def __init__(self, arguments):
        self._db = {}

    def _isolate_value(self, value):
        if value is not NO_VALUE:
            return copy.deepcopy(value)
        return value

    def get(self, key):
        return self._isolate_value(self._db.get(key, NO_VALUE))

    def get_multi(self, keys):
        return [self.get(key) for key in keys]

    def set(self, key, value):
        self._db[key] = self._isolate_value(value)

    def set_multi(self, mapping):
        for key, value in mapping.items():
            self.set(key, value)

    def delete(self, key):
        self._db.pop(key, None)

    def delete_multi(self, keys):
        for key in keys:
            self.delete(key)
