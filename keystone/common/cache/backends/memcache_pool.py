# Copyright 2014 Mirantis Inc
# All Rights Reserved.
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

"""This module is deprecated."""

from oslo_cache.backends import memcache_pool
from oslo_log import versionutils


@versionutils.deprecated(
    versionutils.deprecated.LIBERTY,
    what='keystone.cache.memcache_pool backend',
    in_favor_of='oslo_cache.memcache_pool backend',
    remove_in=+1)
class PooledMemcachedBackend(memcache_pool.PooledMemcachedBackend):
    pass
