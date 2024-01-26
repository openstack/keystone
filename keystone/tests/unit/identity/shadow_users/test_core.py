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

import copy
import uuid

from keystone.common import driver_hints
from keystone.common import provider_api

PROVIDERS = provider_api.ProviderAPIs


class ShadowUsersCoreTests(object):
    def test_shadow_federated_user(self):
        federated_user1 = copy.deepcopy(self.federated_user)
        ShadowUsersCoreTests.normalize_federated_user_properties_for_test(
            federated_user1, email=self.email
        )

        user = PROVIDERS.identity_api.shadow_federated_user(
            self.federated_user['idp_id'], self.federated_user['protocol_id'],
            federated_user1)

        self.assertIsNotNone(user['id'])
        self.assertEqual(7, len(user.keys()))
        self.assertIsNotNone(user['name'])
        self.assertIsNone(user['password_expires_at'])
        self.assertIsNotNone(user['domain_id'])

        # NOTE(breton): below, attribute `enabled` is explicitly tested to be
        # equal True. assertTrue should not be used, because it converts
        # the passed value to bool().
        self.assertEqual(True, user['enabled'])
        self.assertIsNotNone(user['email'])

    def test_shadow_existing_federated_user(self):
        federated_user1 = copy.deepcopy(self.federated_user)
        ShadowUsersCoreTests.normalize_federated_user_properties_for_test(
            federated_user1, email=self.email
        )

        # introduce the user to keystone for the first time
        shadow_user1 = PROVIDERS.identity_api.shadow_federated_user(
            self.federated_user['idp_id'], self.federated_user['protocol_id'],
            federated_user1)

        self.assertEqual(federated_user1['display_name'], shadow_user1['name'])

        # shadow the user again, with another name to invalidate the cache
        # internally, this operation causes request to the driver. It should
        # not fail.
        federated_user2 = copy.deepcopy(self.federated_user)
        federated_user2['display_name'] = uuid.uuid4().hex
        ShadowUsersCoreTests.normalize_federated_user_properties_for_test(
            federated_user2, email=self.email
        )

        shadow_user2 = PROVIDERS.identity_api.shadow_federated_user(
            self.federated_user['idp_id'], self.federated_user['protocol_id'],
            federated_user2)
        self.assertEqual(federated_user2['display_name'], shadow_user2['name'])
        self.assertNotEqual(shadow_user1['name'], shadow_user2['name'])

        # The shadowed users still share the same unique ID.
        self.assertEqual(shadow_user1['id'], shadow_user2['id'])

    def test_shadow_federated_user_not_creating_a_local_user(self):
        federated_user1 = copy.deepcopy(self.federated_user)
        ShadowUsersCoreTests.normalize_federated_user_properties_for_test(
            federated_user1, email="some_id@mail.provider"
        )

        PROVIDERS.identity_api.shadow_federated_user(
            federated_user1['idp_id'], federated_user1['protocol_id'],
            federated_user1)

        hints = driver_hints.Hints()
        hints.add_filter('name', federated_user1['display_name'])
        users = PROVIDERS.identity_api.list_users(hints=hints)

        self.assertEqual(1, len(users))

        federated_user2 = copy.deepcopy(federated_user1)
        # Avoid caching
        federated_user2['name'] = uuid.uuid4().hex
        federated_user2['id'] = uuid.uuid4().hex
        federated_user2['email'] = "some_id_2@mail.provider"

        PROVIDERS.identity_api.shadow_federated_user(
            federated_user2['idp_id'], federated_user2['protocol_id'],
            federated_user2)

        hints.add_filter('name', federated_user2['display_name'])
        users = PROVIDERS.identity_api.list_users(hints=hints)

        # The number os users must remain 1
        self.assertEqual(1, len(users))

    @staticmethod
    def normalize_federated_user_properties_for_test(federated_user,
                                                     email=None):
        federated_user['email'] = email
        federated_user['id'] = federated_user['unique_id']
        federated_user['name'] = federated_user['display_name']
        if not federated_user.get('domain'):
            federated_user['domain'] = {'id': uuid.uuid4().hex}
