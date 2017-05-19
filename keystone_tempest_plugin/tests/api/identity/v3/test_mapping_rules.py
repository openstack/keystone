# Copyright 2016 Red Hat, Inc.
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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from keystone_tempest_plugin.tests.api.identity.v3 import fixtures
from keystone_tempest_plugin.tests import base


class MappingRulesTest(base.BaseIdentityTest):

    _MAPPING_REF = fixtures.mapping_ref()

    def _assert_mapping_rules_attributes(self, mapping, mapping_id,
                                         mapping_ref=None):
        self.assertIn('id', mapping)
        self.assertEqual(mapping_id, mapping['id'])

        self.assertIn('rules', mapping)

        if mapping_ref:
            self.assertItemsEqual(mapping_ref['rules'], mapping['rules'])

    def _create_mapping_rule(self, mapping_id, mapping_ref):
        mapping = self.mappings_client.create_mapping_rule(
            mapping_id, mapping_ref)['mapping']
        self.addCleanup(self.mappings_client.delete_mapping_rule, mapping_id)
        return mapping

    @decorators.idempotent_id('4ca48c01-b6da-4759-acb6-007e15ad712a')
    def test_mapping_rules_create(self):
        mapping_id = data_utils.rand_uuid_hex()
        mapping = self._create_mapping_rule(mapping_id, self._MAPPING_REF)
        self._assert_mapping_rules_attributes(
            mapping, mapping_id, self._MAPPING_REF)

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('341dac45-ce1f-4f15-afdc-1f9a7d7d7c40')
    def test_mapping_rules_create_without_mandatory_attributes_fails(self):
        mapping_id = data_utils.rand_uuid_hex()
        self.assertRaises(
            lib_exc.BadRequest,
            self.mappings_client.create_mapping_rule,
            mapping_id,
            {})

    @decorators.idempotent_id('8db213e3-1db0-48c6-863c-7a3ed23577ec')
    def test_mapping_rules_get(self):
        mapping_id = data_utils.rand_uuid_hex()
        mapping_create = self._create_mapping_rule(
            mapping_id, self._MAPPING_REF)

        mapping_get = self.mappings_client.show_mapping_rule(mapping_id)[
            'mapping']
        self._assert_mapping_rules_attributes(
            mapping_get, mapping_id, mapping_create)

    @decorators.idempotent_id('bb80b242-2a6a-4d29-b45f-4035be574a6e')
    def test_mapping_rules_list(self):
        mapping_ids = []
        for _ in range(3):
            mapping_id = data_utils.rand_uuid_hex()
            self._create_mapping_rule(mapping_id, self._MAPPING_REF)
            mapping_ids.append(mapping_id)

        mappings_list = self.mappings_client.list_mapping_rules()['mappings']
        fetched_ids = [mapping['id'] for mapping in mappings_list]

        for mapping_id in mapping_ids:
            self.assertIn(mapping_id, fetched_ids)

    @decorators.idempotent_id('1fc5d104-faf5-4809-8c89-29b5c1666a96')
    def test_mapping_rule_update(self):
        mapping_id = data_utils.rand_uuid_hex()
        mapping_ref = fixtures.mapping_ref()
        mapping = self._create_mapping_rule(mapping_id, mapping_ref)

        new_local = [{'group': {'id': data_utils.rand_uuid_hex()}}]
        mapping_ref['rules'][0]['local'] = new_local

        mapping = self.mappings_client.update_mapping_rule(
            mapping_id, mapping_ref)['mapping']
        self._assert_mapping_rules_attributes(
            mapping, mapping_id, mapping_ref)

        mapping_get = self.mappings_client.show_mapping_rule(mapping_id)[
            'mapping']
        self._assert_mapping_rules_attributes(
            mapping_get, mapping_id, mapping)
