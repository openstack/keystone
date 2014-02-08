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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class Connection(object):

    @abc.abstractmethod
    def set_key(self, name, key, signature, group, expiration=None):
        """Set a key for a name in the database.

        If a key is set for an existing key name then a new key entry with a
        new generation value is created.

        :param string name: The unique name of the key to set.
        :param string key: The key data to save.
        :param string signature: The signature of the key data to save.
        :param bool group: Whether this is a group key or not.
        :param DateTime expiration: When the key should expire
                                    (None is never expire).

        :raises IntegrityError: If a key exists then new keys assigned to the
                                name must have the same 'group' setting. If the
                                value of group is changed an IntegrityError is
                                raised.

        :returns int: The generation number of this key.
        """

    @abc.abstractmethod
    def get_key(self, name, generation=None, group=None):
        """Get key related to kds_id.

        :param string name: The unique name of the key to fetch.
        :param int generation: A specific generation of the key to retrieve. If
                               not specified the most recent generation is
                               retrieved.
        :param bool group: If provided only retrieve this key if its group
                           value is the same.

        :returns dict: A dictionary of the key information or None if not
                       found. Keys will contain:
                       - name: Unique name of the key.
                       - group: If this key is a group key or not.
                       - key: The key data.
                       - signature: The signature of the key data.
                       - generation: The generation of this key.
                       - expiration: When the key expires (or None).
                                     Expired keys can be returned.
        """
