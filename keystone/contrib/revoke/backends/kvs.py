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
from oslo_utils import timeutils

from keystone.common import kvs
from keystone.contrib import revoke
from keystone import exception
from keystone.openstack.common import versionutils


CONF = cfg.CONF

_EVENT_KEY = 'os-revoke-events'
_KVS_BACKEND = 'openstack.kvs.Memory'


class Revoke(revoke.Driver):

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

    def _prune_expired_events_and_get(self, last_fetch=None, new_event=None):
        pruned = []
        results = []
        expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
        oldest = timeutils.utcnow() - expire_delta
        # TODO(ayoung): Store the time of the oldest event so that the
        # prune process can be skipped if none of the events have timed out.
        with self._store.get_lock(_EVENT_KEY) as lock:
            events = self._list_events()
            if new_event is not None:
                events.append(new_event)

            for event in events:
                revoked_at = event.revoked_at
                if revoked_at > oldest:
                    pruned.append(event)
                    if last_fetch is None or revoked_at > last_fetch:
                        results.append(event)
            self._store.set(_EVENT_KEY, pruned, lock)
        return results

    def list_events(self, last_fetch=None):
        return self._prune_expired_events_and_get(last_fetch=last_fetch)

    def revoke(self, event):
        self._prune_expired_events_and_get(new_event=event)
