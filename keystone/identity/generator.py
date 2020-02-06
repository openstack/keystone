# Copyright 2014 IBM Corp.
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

"""ID Generator provider interface."""

import abc

from keystone.common import manager
import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


class Manager(manager.Manager):
    """Default pivot point for the identifier generator backend."""

    driver_namespace = 'keystone.identity.id_generator'
    _provides_api = 'id_generator_api'

    def __init__(self):
        super(Manager, self).__init__(CONF.identity_mapping.generator)


class IDGenerator(object, metaclass=abc.ABCMeta):
    """Interface description for an ID Generator provider."""

    @abc.abstractmethod
    def generate_public_ID(self, mapping):
        """Return a Public ID for the given mapping dict.

        :param dict mapping: The items to be hashed.

        The ID must be reproducible and no more than 64 chars in length.
        The ID generated should be independent of the order of the items
        in the mapping dict.

        """
        raise exception.NotImplemented()  # pragma: no cover
