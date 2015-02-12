# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import fixtures

from keystone.common import cache


class Cache(fixtures.Fixture):
    """A fixture for setting up and tearing down the cache between test cases.
    """

    def setUp(self):
        super(Cache, self).setUp()

        # NOTE(dstanek):  We must remove the existing cache backend in the
        # setUp instead of the tearDown because it defaults to a no-op cache
        # and we want the configure call below to create the correct backend.

        # NOTE(morganfainberg):  The only way to reconfigure the CacheRegion
        # object on each setUp() call is to remove the .backend property.
        if cache.REGION.is_configured:
            del cache.REGION.backend

        # ensure the cache region instance is setup
        cache.configure_cache_region(cache.REGION)
