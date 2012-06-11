# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from keystone.contrib import stats
from keystone.common import kvs


class Stats(kvs.Base, stats.Driver):
    def get_stats(self, api):
        return self.db.get('stats-%s' % api, {})

    def set_stats(self, api, stats_ref):
        self.db.set('stats-%s' % api, stats_ref)

    def increment_stat(self, api, category, value):
        """Increment a statistic counter, or create it if it doesn't exist."""
        stats = self.get_stats(api)
        stats.setdefault(category, dict())
        counter = stats[category].setdefault(value, 0)
        stats[category][value] = counter + 1
        self.set_stats(api, stats)
