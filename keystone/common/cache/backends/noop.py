# Copyright 2013 Metacloud
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

from dogpile.cache import api


NO_VALUE = api.NO_VALUE


class NoopCacheBackend(api.CacheBackend):
    """A no op backend as a default caching backend.

    The no op backend is provided as the default caching backend for keystone
    to ensure that ``dogpile.cache.memory`` is not used in any real-world
    circumstances unintentionally.  ``dogpile.cache.memory`` does not have a
    mechanism to cleanup it's internal dict and therefore could cause run-away
    memory utilization.
    """
    def __init__(self, *args):
        return

    def get(self, key):
        return NO_VALUE

    def get_multi(self, keys):
        return [NO_VALUE for x in keys]

    def set(self, key, value):
        return

    def set_multi(self, mapping):
        return

    def delete(self, key):
        return

    def delete_multi(self, keys):
        return
