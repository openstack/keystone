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

from oslo_config import cfg
from oslo_log import versionutils
from oslo_utils import timeutils

from keystone.common import kvs
from keystone.contrib import revoke
from keystone import exception


CONF = cfg.CONF

_EVENT_KEY = 'os-revoke-events'
_KVS_BACKEND = 'openstack.kvs.Memory'


class Revoke(revoke.RevokeDriverV8):

    @versionutils.deprecated(
        versionutils.deprecated.JUNO,
        in_favor_of='keystone.contrib.revoke.backends.sql',
        remove_in=+1,
        what='keystone.contrib.revoke.backends.kvs')
    def __init__(self, **kwargs):
        super(Revoke, self).__init__()
        self._store = kvs.get_key_value_store('os-revoke-driver')
        self._store.configure(backing_store=_KVS_BACKEND, **kwargs)

    def _list_events(self):
        try:
            return self._store.get(_EVENT_KEY)
        except exception.NotFound:
            return []

    def list_events(self, last_fetch=None):
        results = []

        with self._store.get_lock(_EVENT_KEY):
            events = self._list_events()

        for event in events:
            revoked_at = event.revoked_at
            if last_fetch is None or revoked_at > last_fetch:
                results.append(event)
        return results

    def revoke(self, event):
        pruned = []
        expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
        oldest = timeutils.utcnow() - expire_delta

        with self._store.get_lock(_EVENT_KEY) as lock:
            events = self._list_events()
            if event:
                events.append(event)

            for event in events:
                revoked_at = event.revoked_at
                if revoked_at > oldest:
                    pruned.append(event)
            self._store.set(_EVENT_KEY, pruned, lock)
