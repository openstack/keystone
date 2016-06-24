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

from oslo_log import versionutils

import keystone.conf
from keystone.token.persistence.backends import memcache


CONF = keystone.conf.CONF


class Token(memcache.Token):
    memcached_backend = 'pooled_memcached'

    @versionutils.deprecated(
        what='Memcache Pool Token Persistence Driver',
        as_of=versionutils.deprecated.MITAKA,
        in_favor_of='fernet token driver (no-persistence)',
        remove_in=0)
    def __init__(self, *args, **kwargs):
        for arg in ('dead_retry', 'socket_timeout', 'pool_maxsize',
                    'pool_unused_timeout', 'pool_connection_get_timeout'):
            kwargs[arg] = getattr(CONF.memcache, arg)
        super(Token, self).__init__(*args, **kwargs)
