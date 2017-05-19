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

DEFAULT_RELAY_STATE_PREFIX = 'ss:mem:'


class ServiceProvidersTest(base.BaseIdentityTest):

    def _assert_service_provider_attributes(self, sp, sp_id, sp_ref=None):
        self.assertIn('id', sp)
        self.assertEqual(sp_id, sp['id'])

        self.assertIn('auth_url', sp)
        self.assertIn('sp_url', sp)

        # Check the optional attributes have been set
        self.assertIn('description', sp)
        self.assertIn('enabled', sp)
        self.assertIn('relay_state_prefix', sp)

        if sp_ref:
            self.assertEqual(sp_ref['auth_url'], sp['auth_url'])
            self.assertEqual(sp_ref['sp_url'], sp['sp_url'])
            self.assertEqual(sp_ref['description'], sp['description'])

            if 'enabled' in sp_ref:
                self.assertEqual(sp_ref['enabled'], sp['enabled'])

            if 'relay_state_prefix' in sp_ref:
                self.assertEqual(
                    sp_ref['relay_state_prefix'], sp['relay_state_prefix'])

    def _add_cleanup(self, sp_id):
        self.addCleanup(
            self.sps_client.delete_service_provider, sp_id)

    def _create_sp(self, sp_id, sp_ref):
        sp = self.sps_client.create_service_provider(
            sp_id, **sp_ref)['service_provider']
        self.addCleanup(self.sps_client.delete_service_provider, sp_id)
        return sp

    @decorators.idempotent_id('6fae0971-5acb-4559-ba25-96f1fd7e5385')
    def test_service_provider_create(self):
        sp_id = data_utils.rand_uuid_hex()
        sp_ref = fixtures.sp_ref()
        sp = self._create_sp(sp_id, sp_ref)

        # The service provider is disabled by default
        sp_ref['enabled'] = False

        # The relay_state_prefix should have been set to the default value
        sp_ref['relay_state_prefix'] = DEFAULT_RELAY_STATE_PREFIX

        self._assert_service_provider_attributes(sp, sp_id, sp_ref)

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('d9d7454c-50b7-4966-aedb-b9d520a41409')
    def test_service_provider_create_without_mandatory_attributes(self):
        sp_id = data_utils.rand_uuid_hex()
        self.assertRaises(
            lib_exc.BadRequest,
            self.sps_client.create_service_provider,
            sp_id)

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('f77ed1c0-c428-44a7-9364-e8e4362c360a')
    def test_service_provider_create_with_bad_attributes(self):
        sp_id = data_utils.rand_uuid_hex()
        sp_ref = fixtures.sp_ref()

        # The auth_url must follow a URL regex
        sp_ref['auth_url'] = data_utils.rand_uuid_hex()
        self.assertRaises(
            lib_exc.BadRequest,
            self.sps_client.create_service_provider,
            sp_id,
            **sp_ref)

        sp_ref = fixtures.sp_ref()

        # The sp_url must follow a URL regex
        sp_ref['sp_url'] = data_utils.rand_uuid_hex()
        self.assertRaises(
            lib_exc.BadRequest,
            self.sps_client.create_service_provider,
            sp_id,
            **sp_ref)

    @decorators.idempotent_id('8550b419-f212-4e34-a8fa-7ff64f8a7fd3')
    def test_service_provider_create_with_enabled_true(self):
        sp_id = data_utils.rand_uuid_hex()
        sp_ref = fixtures.sp_ref(enabled=True)
        sp = self._create_sp(sp_id, sp_ref)

        self._assert_service_provider_attributes(sp, sp_id, sp_ref)

    @decorators.idempotent_id('0e319a14-1548-474e-a406-273c6b1c1f2d')
    def test_service_provider_create_with_relay_state_prefix(self):
        sp_id = data_utils.rand_uuid_hex()
        sp_ref = fixtures.sp_ref(
            enabled=True, relay_state_prefix=data_utils.rand_uuid_hex())
        sp = self._create_sp(sp_id, sp_ref)

        self._assert_service_provider_attributes(sp, sp_id, sp_ref)

    @decorators.idempotent_id('7df78c7a-9265-4b4f-9630-193b7f07d9eb')
    def test_service_provider_get(self):
        sp_id = data_utils.rand_uuid_hex()
        sp_create = self._create_sp(sp_id, fixtures.sp_ref())

        sp_get = self.sps_client.show_service_provider(sp_id)[
            'service_provider']

        self._assert_service_provider_attributes(sp_get, sp_id, sp_create)

    @decorators.idempotent_id('9237cea0-fbeb-4d64-8347-46c567e1d78f')
    def test_service_provider_list(self):
        sp_ids = []
        for _ in range(3):
            sp_id = data_utils.rand_uuid_hex()
            self._create_sp(sp_id, fixtures.sp_ref())
            sp_ids.append(sp_id)

        sp_list = self.sps_client.list_service_providers()['service_providers']
        fetched_ids = [fetched_sp['id'] for fetched_sp in sp_list]

        for sp_id in sp_ids:
            self.assertIn(sp_id, fetched_ids)

    @decorators.idempotent_id('bb68653f-fbba-4f20-ac1b-7b318a557366')
    def test_service_provider_update(self):
        sp_id = data_utils.rand_uuid_hex()
        sp = self._create_sp(sp_id, fixtures.sp_ref(enabled=True))

        # The service provider should be enabled
        self.assertTrue(sp['enabled'])

        sp = self.sps_client.update_service_provider(
            sp_id, enabled=False)['service_provider']

        # The service provider should be now disabled
        self.assertFalse(sp['enabled'])

        sp_get = self.sps_client.show_service_provider(sp_id)[
            'service_provider']
        self.assertFalse(sp_get['enabled'])

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('91ce1183-1a15-4598-ae5f-85cfa98a1c77')
    def test_service_provider_update_with_bad_attributes_fails(self):
        sp_id = data_utils.rand_uuid_hex()
        self._create_sp(sp_id, fixtures.sp_ref())

        # The auth_url must follow a URL regex
        self.assertRaises(
            lib_exc.BadRequest,
            self.sps_client.update_service_provider,
            sp_id,
            auth_url=data_utils.rand_uuid_hex())

        # The sp_url must follow a URL regex
        self.assertRaises(
            lib_exc.BadRequest,
            self.sps_client.update_service_provider,
            sp_id,
            auth_url=data_utils.rand_uuid_hex())

    @decorators.idempotent_id('7553579b-9a9e-45dd-9ada-70d906b516c0')
    def test_service_providers_in_token(self):
        # Create some enabled service providers
        enabled_sps = []
        for _ in range(2):
            sp_id = data_utils.rand_uuid_hex()
            self._create_sp(sp_id, fixtures.sp_ref(enabled=True))
            enabled_sps.append(sp_id)

        # Create some disabled service providers
        for _ in range(2):
            sp_id = data_utils.rand_uuid_hex()
            self._create_sp(sp_id, fixtures.sp_ref(enabled=False))

        sps_in_token_ids = [
            sp['id'] for sp in
            self.sps_client.get_service_providers_in_token()]

        # Should be equal to the enabled_sps list
        self.assertItemsEqual(enabled_sps, sps_in_token_ids)
