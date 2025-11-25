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

from unittest import mock
import uuid

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database

PROVIDERS = provider_api.ProviderAPIs


class FederatedGroupCacheTest(unit.TestCase):
    """Test federated group membership cache invalidation."""

    def setUp(self):
        # Mock LDAP to avoid environment-specific errors
        ldap_patcher = mock.patch('ldap.initialize')
        self.addCleanup(ldap_patcher.stop)
        ldap_patcher.start()

        # Mock LDAP options that are checked during setup
        with mock.patch('ldap.get_option', return_value=None):
            with mock.patch('ldap.set_option'):
                super().setUp()
        self.useFixture(database.Database())
        self.load_backends()

        # Create domain
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN
        )

        # Create IDP, mapping, and protocol
        self.idp = {
            'id': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex,
        }
        self.mapping = {'id': uuid.uuid4().hex}
        self.protocol = {
            'id': uuid.uuid4().hex,
            'idp_id': self.idp['id'],
            'mapping_id': self.mapping['id'],
        }

        PROVIDERS.federation_api.create_idp(self.idp['id'], self.idp)
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        PROVIDERS.federation_api.create_protocol(
            self.idp['id'], self.protocol['id'], self.protocol
        )

        self.domain_id = PROVIDERS.federation_api.get_idp(self.idp['id'])[
            'domain_id'
        ]

        # Create a federated user
        self.federated_user = {
            'idp_id': self.idp['id'],
            'protocol_id': self.protocol['id'],
            'unique_id': uuid.uuid4().hex,
            'display_name': uuid.uuid4().hex,
        }
        self.user = PROVIDERS.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user
        )

        # Create groups
        self.group1 = unit.new_group_ref(domain_id=self.domain_id)
        self.group1 = PROVIDERS.identity_api.create_group(self.group1)

        self.group2 = unit.new_group_ref(domain_id=self.domain_id)
        self.group2 = PROVIDERS.identity_api.create_group(self.group2)

    def test_group_membership_returns_true_for_new_membership(self):
        """Test that adding a new group membership returns True."""
        result = PROVIDERS.shadow_users_api.add_user_to_group_expires(
            self.user['id'], self.group1['id']
        )
        self.assertTrue(result)

    def test_group_membership_returns_false_for_renewal(self):
        """Test that renewing an existing group membership returns False."""
        PROVIDERS.shadow_users_api.add_user_to_group_expires(
            self.user['id'], self.group1['id']
        )
        result = PROVIDERS.shadow_users_api.add_user_to_group_expires(
            self.user['id'], self.group1['id']
        )
        self.assertFalse(result)

    def test_new_group_membership_triggers_token_revocation(self):
        """Test that new group membership triggers token revocation."""
        with mock.patch.object(
            PROVIDERS.assignment_api, 'invalidate_user_cache_on_group_change'
        ) as mock_revoke:
            user_dict = {
                'id': self.federated_user['unique_id'],
                'name': self.federated_user['display_name'],
                'domain': {'id': self.domain_id},
            }

            PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'],
                self.protocol['id'],
                user_dict,
                group_ids=[self.group1['id']],
            )

            mock_revoke.assert_called_once_with(self.user['id'])

    def test_membership_renewal_does_not_trigger_revocation(self):
        """Test that pure membership renewal doesn't trigger token revocation."""
        with mock.patch.object(
            PROVIDERS.shadow_users_api,
            'add_user_to_group_expires',
            return_value=False,
        ):
            with mock.patch.object(
                PROVIDERS.shadow_users_api,
                'cleanup_stale_group_memberships',
                return_value=False,
            ):
                with mock.patch.object(
                    PROVIDERS.assignment_api,
                    'invalidate_user_cache_on_group_change',
                ) as mock_revoke:
                    user_dict = {
                        'id': self.federated_user['unique_id'],
                        'name': self.federated_user['display_name'],
                        'domain': {'id': self.domain_id},
                    }

                    PROVIDERS.identity_api.shadow_federated_user(
                        self.idp['id'],
                        self.protocol['id'],
                        user_dict,
                        group_ids=[self.group1['id']],
                    )

                    mock_revoke.assert_not_called()

    def test_adding_additional_group_triggers_revocation(self):
        """Test that adding an additional group triggers token revocation."""
        PROVIDERS.shadow_users_api.add_user_to_group_expires(
            self.user['id'], self.group1['id']
        )

        with mock.patch.object(
            PROVIDERS.assignment_api, 'invalidate_user_cache_on_group_change'
        ) as mock_revoke:
            user_dict = {
                'id': self.federated_user['unique_id'],
                'name': self.federated_user['display_name'],
                'domain': {'id': self.domain_id},
            }

            PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'],
                self.protocol['id'],
                user_dict,
                group_ids=[self.group1['id'], self.group2['id']],
            )

            mock_revoke.assert_called_once_with(self.user['id'])

    def test_empty_group_list_does_not_trigger_revocation(self):
        """Test that shadowing with no groups doesn't trigger revocation."""
        with mock.patch.object(
            PROVIDERS.assignment_api, 'invalidate_user_cache_on_group_change'
        ) as mock_revoke:
            user_dict = {
                'id': self.federated_user['unique_id'],
                'name': self.federated_user['display_name'],
                'domain': {'id': self.domain_id},
            }

            PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'], self.protocol['id'], user_dict, group_ids=[]
            )

            mock_revoke.assert_not_called()

    @mock.patch('keystone.notifications.invalidate_token_cache_notification')
    def test_token_revocation_persists_event_and_invalidates_cache(
        self, mock_cache_notification
    ):
        """Test that token revocation creates revoke event and invalidates cache."""
        with mock.patch.object(PROVIDERS.revoke_api, 'revoke') as mock_revoke:
            PROVIDERS.assignment_api.invalidate_user_cache_on_group_change(
                self.user['id']
            )

            # Verify revoke was called with a RevokeEvent
            mock_revoke.assert_called_once()
            revoke_event = mock_revoke.call_args[0][0]

            # Check that the revoke event has the correct user_id
            self.assertEqual(revoke_event.user_id, self.user['id'])

            # Check that issued_before is set (indicating -1 second logic)
            self.assertIsNotNone(revoke_event.issued_before)

            # Verify cache invalidation notification was called
            mock_cache_notification.assert_called_once()
            call_args = mock_cache_notification.call_args[0][0]
            self.assertIn(self.user['id'], call_args)
            self.assertIn('group membership changed', call_args)
