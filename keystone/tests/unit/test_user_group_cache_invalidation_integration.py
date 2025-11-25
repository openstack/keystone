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

"""Integration tests for federated group membership cache invalidation."""

from unittest import mock
import uuid

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database

PROVIDERS = provider_api.ProviderAPIs


class FederatedGroupCacheIntegrationTest(unit.TestCase):
    """Integration test for federated group membership cache invalidation."""

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
            'description': 'Test Identity Provider',
        }
        self.mapping = {'id': uuid.uuid4().hex, 'rules': []}
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

        # Create groups
        self.group1 = unit.new_group_ref(
            domain_id=self.domain_id, name='group1'
        )
        self.group1 = PROVIDERS.identity_api.create_group(self.group1)

        self.group2 = unit.new_group_ref(
            domain_id=self.domain_id, name='group2'
        )
        self.group2 = PROVIDERS.identity_api.create_group(self.group2)

        self.group3 = unit.new_group_ref(
            domain_id=self.domain_id, name='group3'
        )
        self.group3 = PROVIDERS.identity_api.create_group(self.group3)

    def test_complete_user_shadowing_workflow(self):
        """Test complete workflow of user shadowing with cache invalidation."""
        federated_user = {
            'idp_id': self.idp['id'],
            'protocol_id': self.protocol['id'],
            'unique_id': uuid.uuid4().hex,
            'display_name': 'Test User',
        }

        user_dict = {
            'id': federated_user['unique_id'],
            'name': federated_user['display_name'],
            'domain': {'id': self.domain_id},
        }

        with mock.patch.object(
            PROVIDERS.assignment_api, 'invalidate_user_cache_on_group_change'
        ) as mock_revoke:
            user = PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'],
                self.protocol['id'],
                user_dict,
                group_ids=[self.group1['id']],
            )

            self.assertEqual(0, mock_revoke.call_count)
            mock_revoke.reset_mock()

            user = PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'],
                self.protocol['id'],
                user_dict,
                group_ids=[self.group1['id'], self.group2['id']],
            )

            self.assertGreaterEqual(mock_revoke.call_count, 1)
            mock_revoke.reset_mock()

            user = PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'],
                self.protocol['id'],
                user_dict,
                group_ids=[self.group2['id'], self.group3['id']],
            )

            self.assertEqual(1, mock_revoke.call_count)

    def test_multiple_users_concurrent_operations(self):
        """Test cache invalidation with multiple concurrent user operations."""
        users = []
        for i in range(3):
            fed_user = {
                'idp_id': self.idp['id'],
                'protocol_id': self.protocol['id'],
                'unique_id': uuid.uuid4().hex,
                'display_name': f'User {i}',
            }
            user_dict = {
                'id': fed_user['unique_id'],
                'name': fed_user['display_name'],
                'domain': {'id': self.domain_id},
            }
            users.append((fed_user, user_dict))

        invalidation_counts = {}

        original_revoke = (
            PROVIDERS.assignment_api.invalidate_user_cache_on_group_change
        )

        def track_revocation(user_id):
            invalidation_counts[user_id] = (
                invalidation_counts.get(user_id, 0) + 1
            )
            return original_revoke(user_id)

        with mock.patch.object(
            PROVIDERS.assignment_api,
            'invalidate_user_cache_on_group_change',
            side_effect=track_revocation,
        ):
            shadowed_users = []
            for fed_user, user_dict in users:
                user = PROVIDERS.identity_api.shadow_federated_user(
                    self.idp['id'],
                    self.protocol['id'],
                    user_dict,
                    group_ids=[self.group1['id']],
                )
                shadowed_users.append(user)

            self.assertEqual(0, len(invalidation_counts))

            PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'],
                self.protocol['id'],
                users[1][1],
                group_ids=[self.group1['id'], self.group2['id']],
            )

            self.assertEqual(1, len(invalidation_counts))
            self.assertEqual(1, invalidation_counts[shadowed_users[1]['id']])

    def test_expired_membership_removal_triggers_revocation(self):
        """Test that expired membership removal triggers cache invalidation."""
        federated_user = {
            'idp_id': self.idp['id'],
            'protocol_id': self.protocol['id'],
            'unique_id': uuid.uuid4().hex,
            'display_name': 'Expiry Test User',
        }

        user_dict = {
            'id': federated_user['unique_id'],
            'name': federated_user['display_name'],
            'domain': {'id': self.domain_id},
        }

        user = PROVIDERS.identity_api.shadow_federated_user(
            self.idp['id'],
            self.protocol['id'],
            user_dict,
            group_ids=[self.group1['id']],
        )

        with mock.patch.object(
            PROVIDERS.shadow_users_api,
            'cleanup_stale_group_memberships',
            return_value=True,
        ):
            with mock.patch.object(
                PROVIDERS.assignment_api,
                'invalidate_user_cache_on_group_change',
            ) as mock_revoke:
                PROVIDERS.identity_api.shadow_federated_user(
                    self.idp['id'],
                    self.protocol['id'],
                    user_dict,
                    group_ids=[self.group1['id']],
                )

                mock_revoke.assert_called_once_with(user['id'])

    def test_role_assignments_reflect_group_changes(self):
        """Test that role assignments reflect group membership changes."""
        project1 = unit.new_project_ref(domain_id=self.domain_id)
        project1 = PROVIDERS.resource_api.create_project(
            project1['id'], project1
        )

        project2 = unit.new_project_ref(domain_id=self.domain_id)
        project2 = PROVIDERS.resource_api.create_project(
            project2['id'], project2
        )

        role_admin = unit.new_role_ref(name='admin')
        role_admin = PROVIDERS.role_api.create_role(
            role_admin['id'], role_admin
        )

        role_member = unit.new_role_ref(name='member')
        role_member = PROVIDERS.role_api.create_role(
            role_member['id'], role_member
        )

        PROVIDERS.assignment_api.create_grant(
            role_admin['id'],
            group_id=self.group1['id'],
            project_id=project1['id'],
        )

        PROVIDERS.assignment_api.create_grant(
            role_member['id'],
            group_id=self.group2['id'],
            project_id=project2['id'],
        )

        federated_user = {
            'idp_id': self.idp['id'],
            'protocol_id': self.protocol['id'],
            'unique_id': uuid.uuid4().hex,
            'display_name': 'Role Test User',
        }

        user_dict = {
            'id': federated_user['unique_id'],
            'name': federated_user['display_name'],
            'domain': {'id': self.domain_id},
        }

        user = PROVIDERS.identity_api.shadow_federated_user(
            self.idp['id'],
            self.protocol['id'],
            user_dict,
            group_ids=[self.group1['id']],
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], self.group1['id'])

        roles_proj1 = PROVIDERS.assignment_api.list_role_assignments(
            user_id=user['id'], project_id=project1['id'], effective=True
        )
        self.assertEqual(1, len(roles_proj1))
        self.assertEqual(role_admin['id'], roles_proj1[0]['role_id'])

        PROVIDERS.identity_api.remove_user_from_group(
            user['id'], self.group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(user['id'], self.group2['id'])
        PROVIDERS.assignment_api.invalidate_user_cache_on_group_change(
            user['id']
        )

        roles_proj2 = PROVIDERS.assignment_api.list_role_assignments(
            user_id=user['id'], project_id=project2['id'], effective=True
        )
        self.assertEqual(1, len(roles_proj2))
        self.assertEqual(role_member['id'], roles_proj2[0]['role_id'])

    def test_token_revocation_event_persisted(self):
        """Test that revoke event is created on group change."""
        federated_user = {
            'idp_id': self.idp['id'],
            'protocol_id': self.protocol['id'],
            'unique_id': uuid.uuid4().hex,
            'display_name': 'Revocation Test User',
        }

        user_dict = {
            'id': federated_user['unique_id'],
            'name': federated_user['display_name'],
            'domain': {'id': self.domain_id},
        }

        # Initial shadowing - no revocation expected
        user = PROVIDERS.identity_api.shadow_federated_user(
            self.idp['id'],
            self.protocol['id'],
            user_dict,
            group_ids=[self.group1['id']],
        )

        # Shadow again with additional group - revocation expected
        with mock.patch.object(PROVIDERS.revoke_api, 'revoke') as mock_revoke:
            user = PROVIDERS.identity_api.shadow_federated_user(
                self.idp['id'],
                self.protocol['id'],
                user_dict,
                group_ids=[self.group1['id'], self.group2['id']],
            )

            # Verify revoke was called with a RevokeEvent
            mock_revoke.assert_called_once()
            revoke_event = mock_revoke.call_args[0][0]

            # Check that the revoke event has the correct user_id
            self.assertEqual(revoke_event.user_id, user['id'])

            # Check that issued_before is set (indicating -1 second logic)
            self.assertIsNotNone(revoke_event.issued_before)
