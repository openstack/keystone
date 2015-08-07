# Copyright 2013 OpenStack Foundation
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

import uuid

from oslo_config import cfg
from six.moves import range


CONF = cfg.CONF


class FilterTests(object):

    # Provide support for checking if a batch of list items all
    # exist within a contiguous range in a total list
    def _match_with_list(self, this_batch, total_list,
                         batch_size=None,
                         list_start=None, list_end=None):
        if batch_size is None:
            batch_size = len(this_batch)
        if list_start is None:
            list_start = 0
        if list_end is None:
            list_end = len(total_list)
        for batch_item in range(0, batch_size):
            found = False
            for list_item in range(list_start, list_end):
                if this_batch[batch_item]['id'] == total_list[list_item]['id']:
                    found = True
            self.assertTrue(found)

    def _create_entity(self, entity_type):
        """Find the create_<entity_type> method.

        Searches through the [identity_api, resource_api, assignment_api]
        managers for a method called create_<entity_type> and returns the first
        one.

        """

        f = getattr(self.identity_api, 'create_%s' % entity_type, None)
        if f is None:
            f = getattr(self.resource_api, 'create_%s' % entity_type, None)
        if f is None:
            f = getattr(self.assignment_api, 'create_%s' % entity_type)
        return f

    def _delete_entity(self, entity_type):
        """Find the delete_<entity_type> method.

        Searches through the [identity_api, resource_api, assignment_api]
        managers for a method called delete_<entity_type> and returns the first
        one.

        """

        f = getattr(self.identity_api, 'delete_%s' % entity_type, None)
        if f is None:
            f = getattr(self.resource_api, 'delete_%s' % entity_type, None)
        if f is None:
            f = getattr(self.assignment_api, 'delete_%s' % entity_type)
        return f

    def _list_entities(self, entity_type):
        """Find the list_<entity_type> method.

        Searches through the [identity_api, resource_api, assignment_api]
        managers for a method called list_<entity_type> and returns the first
        one.

        """

        f = getattr(self.identity_api, 'list_%ss' % entity_type, None)
        if f is None:
            f = getattr(self.resource_api, 'list_%ss' % entity_type, None)
        if f is None:
            f = getattr(self.assignment_api, 'list_%ss' % entity_type)
        return f

    def _create_one_entity(self, entity_type, domain_id, name):
        new_entity = {'name': name,
                      'domain_id': domain_id}
        if entity_type in ['user', 'group']:
            # The manager layer creates the ID for users and groups
            new_entity = self._create_entity(entity_type)(new_entity)
        else:
            new_entity['id'] = '0000' + uuid.uuid4().hex
            self._create_entity(entity_type)(new_entity['id'], new_entity)
        return new_entity

    def _create_test_data(self, entity_type, number, domain_id=None,
                          name_dict=None):
        """Create entity test data

        :param entity_type: type of entity to create, e.g. 'user', group' etc.
        :param number: number of entities to create,
        :param domain_id: if not defined, all users will be created in the
                          default domain.
        :param name_dict: optional dict containing entity number and name pairs

        """
        entity_list = []
        if domain_id is None:
            domain_id = CONF.identity.default_domain_id
        name_dict = name_dict or {}
        for x in range(number):
            # If this index has a name defined in the name_dict, then use it
            name = name_dict.get(x, uuid.uuid4().hex)
            new_entity = self._create_one_entity(entity_type, domain_id, name)
            entity_list.append(new_entity)
        return entity_list

    def _delete_test_data(self, entity_type, entity_list):
        for entity in entity_list:
            self._delete_entity(entity_type)(entity['id'])
