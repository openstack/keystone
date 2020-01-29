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

import abc

from keystone.common import provider_api
from keystone import exception


class MappingDriverBase(provider_api.ProviderAPIMixin, object,
                        metaclass=abc.ABCMeta):
    """Interface description for an ID Mapping driver."""

    @abc.abstractmethod
    def get_public_id(self, local_entity):
        """Return the public ID for the given local entity.

        :param dict local_entity: Containing the entity domain, local ID and
                                  type ('user' or 'group').
        :returns: public ID, or None if no mapping is found.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_domain_mapping_list(self, domain_id, entity_type=None):
        """Return mappings for the domain.

        :param domain_id: Domain ID to get mappings for.
        :param entity_type: Optional entity_type to get mappings for.
        :type entity_type: String, one of mappings defined in
            keystone.identity.mapping_backends.mapping.EntityType
        :returns: list of mappings.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_id_mapping(self, public_id):
        """Return the local mapping.

        :param public_id: The public ID for the mapping required.
        :returns dict: Containing the entity domain, local ID and type. If no
                       mapping is found, it returns None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_id_mapping(self, local_entity, public_id=None):
        """Create and store a mapping to a public_id.

        :param dict local_entity: Containing the entity domain, local ID and
                                  type ('user' or 'group').
        :param public_id: If specified, this will be the public ID.  If this
                          is not specified, a public ID will be generated.
        :returns: public ID

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_id_mapping(self, public_id):
        """Delete an entry for the given public_id.

        :param public_id: The public ID for the mapping to be deleted.

        The method is silent if no mapping is found.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def purge_mappings(self, purge_filter):
        """Purge selected identity mappings.

        :param dict purge_filter: Containing the attributes of the filter that
                                  defines which entries to purge. An empty
                                  filter means purge all mappings.

        """
        raise exception.NotImplemented()  # pragma: no cover
