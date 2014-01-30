# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.contrib.kds.common import exception
from keystone.contrib.kds.db import connection


def get_backend():
    return KvsDbImpl()


class KvsDbImpl(connection.Connection):
    """A simple in-memory Key Value backend.

    KVS backends are designed for use in testing and for simple debugging.
    This backend should not be deployed in any production systems.
    """

    def __init__(self):
        super(KvsDbImpl, self).__init__()
        self.clear()

    def clear(self):
        self._data = dict()

    def set_key(self, name, key, signature, group, expiration=None):
        host = self._data.setdefault(name, {'latest_generation': 0,
                                            'keys': dict(), 'group': group})

        if host['group'] != group:
            raise exception.GroupStatusChanged(name=name)

        host['latest_generation'] += 1
        host['keys'][host['latest_generation']] = {'key': key,
                                                   'signature': signature,
                                                   'expiration': expiration}

        return host['latest_generation']

    def get_key(self, name, generation=None, group=None):
        response = {'name': name}
        try:
            host = self._data[name]
            if generation is None:
                generation = host['latest_generation']
            key_data = host['keys'][generation]
        except KeyError:
            return None

        response['generation'] = generation
        response['group'] = host['group']

        if group is not None and host['group'] != group:
            return None

        response.update(key_data)
        return response
