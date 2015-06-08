# Copyright 2012 OpenStack Foundation
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

from oslo_log import versionutils

from keystone import exception


class DictKvs(dict):
    def get(self, key, default=None):
        try:
            if isinstance(self[key], dict):
                return self[key].copy()
            else:
                return self[key][:]
        except KeyError:
            if default is not None:
                return default
            raise exception.NotFound(target=key)

    def set(self, key, value):
        if isinstance(value, dict):
            self[key] = value.copy()
        else:
            self[key] = value[:]

    def delete(self, key):
        """Deletes an item, returning True on success, False otherwise."""
        try:
            del self[key]
        except KeyError:
            raise exception.NotFound(target=key)


INMEMDB = DictKvs()


class Base(object):
    @versionutils.deprecated(versionutils.deprecated.ICEHOUSE,
                             in_favor_of='keystone.common.kvs.KeyValueStore',
                             remove_in=+2,
                             what='keystone.common.kvs.Base')
    def __init__(self, db=None):
        if db is None:
            db = INMEMDB
        elif isinstance(db, DictKvs):
            db = db
        elif isinstance(db, dict):
            db = DictKvs(db)
        self.db = db
