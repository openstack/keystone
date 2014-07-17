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

from keystone.openstack.common import versionutils
from keystone.token.persistence.backends import memcache


class Token(memcache.Token):
    @versionutils.deprecated(
        versionutils.deprecated.JUNO,
        in_favor_of='keystone.token.persistence.backends.memcache.Token',
        remove_in=+1,
        what='keystone.token.backends.memcache.Token')
    def __init__(self):
        super(Token, self).__init__()
