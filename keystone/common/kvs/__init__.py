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

from dogpile.cache import region

from keystone.common.kvs.core import *  # noqa
from keystone.common.kvs.legacy import Base, DictKvs, INMEMDB  # noqa


# NOTE(morganfainberg): Provided backends are registered here in the __init__
# for the kvs system.  Any out-of-tree backends should be registered via the
# ``backends`` option in the ``[kvs]`` section of the Keystone configuration
# file.
region.register_backend(
    'openstack.kvs.Memory',
    'keystone.common.kvs.backends.inmemdb',
    'MemoryBackend')

region.register_backend(
    'openstack.kvs.Memcached',
    'keystone.common.kvs.backends.memcached',
    'MemcachedBackend')
