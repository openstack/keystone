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

from keystone.common import provider_api
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.identity.shadow_users import test_backend
from keystone.tests.unit.identity.shadow_users import test_core
from keystone.tests.unit.ksfixtures import database

PROVIDERS = provider_api.ProviderAPIs


class ShadowUsersTests(
    unit.TestCase,
    test_backend.ShadowUsersBackendTests,
    test_core.ShadowUsersCoreTests,
):
    def setUp(self):
        super().setUp()
        self.useFixture(database.Database())
        self.load_backends()
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN
        )
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
        self.federated_user = {
            'idp_id': self.idp['id'],
            'protocol_id': self.protocol['id'],
            'unique_id': uuid.uuid4().hex,
            'display_name': uuid.uuid4().hex,
        }
        self.email = uuid.uuid4().hex
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


class TestUserWithFederatedUser(ShadowUsersTests):
    def setUp(self):
        super().setUp()
        self.useFixture(database.Database())
        self.load_backends()

    def assertFederatedDictsEqual(self, fed_dict, fed_object):
        self.assertEqual(fed_dict['idp_id'], fed_object['idp_id'])
        self.assertEqual(
            fed_dict['protocol_id'], fed_object['protocols'][0]['protocol_id']
        )
        self.assertEqual(
            fed_dict['unique_id'], fed_object['protocols'][0]['unique_id']
        )

    def test_get_user_when_user_has_federated_object(self):
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'], protocol_id=self.protocol['id']
        )
        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )

        # test that the user returns a federated object and that there is only
        # one returned
        user_ref = self.identity_api.get_user(user['id'])
        self.assertIn('federated', user_ref)
        self.assertEqual(1, len(user_ref['federated']))

        self.assertFederatedDictsEqual(fed_dict, user_ref['federated'][0])

    def test_create_user_with_invalid_idp_and_protocol_fails(self):
        baduser = unit.new_user_ref(domain_id=self.domain_id)
        baduser['federated'] = [
            {
                'idp_id': 'fakeidp',
                'protocols': [
                    {'protocol_id': 'nonexistent', 'unique_id': 'unknown'}
                ],
            }
        ]
        # Check validation works by throwing a federated object with
        # invalid idp_id, protocol_id inside the user passed to create_user.
        self.assertRaises(
            exception.ValidationError, self.identity_api.create_user, baduser
        )

        baduser['federated'][0]['idp_id'] = self.idp['id']
        self.assertRaises(
            exception.ValidationError, self.identity_api.create_user, baduser
        )

    def test_create_user_with_federated_attributes(self):
        # Create the schema of a federated attribute being passed in with a
        # user.
        user = unit.new_user_ref(domain_id=self.domain_id)
        unique_id = uuid.uuid4().hex
        user['federated'] = [
            {
                'idp_id': self.idp['id'],
                'protocols': [
                    {
                        'protocol_id': self.protocol['id'],
                        'unique_id': unique_id,
                    }
                ],
            }
        ]

        # Test that there are no current federated_users that match our users
        # federated object and create the user
        self.assertRaises(
            exception.UserNotFound,
            self.shadow_users_api.get_federated_user,
            self.idp['id'],
            self.protocol['id'],
            unique_id,
        )

        ref = self.identity_api.create_user(user)

        # Test that the user and federated object now exists
        self.assertEqual(user['name'], ref['name'])
        self.assertEqual(user['federated'], ref['federated'])
        fed_user = self.shadow_users_api.get_federated_user(
            self.idp['id'], self.protocol['id'], unique_id
        )
        self.assertIsNotNone(fed_user)

    def test_update_user_with_invalid_idp_and_protocol_fails(self):
        baduser = unit.new_user_ref(domain_id=self.domain_id)
        baduser['federated'] = [
            {
                'idp_id': 'fakeidp',
                'protocols': [
                    {'protocol_id': 'nonexistent', 'unique_id': 'unknown'}
                ],
            }
        ]
        # Check validation works by throwing a federated object with
        # invalid idp_id, protocol_id inside the user passed to create_user.
        self.assertRaises(
            exception.ValidationError, self.identity_api.create_user, baduser
        )

        baduser['federated'][0]['idp_id'] = self.idp['id']
        self.assertRaises(
            exception.ValidationError, self.identity_api.create_user, baduser
        )

    def test_update_user_with_federated_attributes(self):
        user = self.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user
        )
        user = self.identity_api.get_user(user['id'])

        # Test that update user can return a federated object with the user as
        # a response if the user has any
        user = self.identity_api.update_user(user['id'], user)
        self.assertFederatedDictsEqual(
            self.federated_user, user['federated'][0]
        )

        # Test that update user can replace a users federated objects if added
        # in the request and that its response is that new federated objects
        new_fed = [
            {
                'idp_id': self.idp['id'],
                'protocols': [
                    {
                        'protocol_id': self.protocol['id'],
                        'unique_id': uuid.uuid4().hex,
                    }
                ],
            }
        ]
        user['federated'] = new_fed
        user = self.identity_api.update_user(user['id'], user)
        self.assertTrue('federated' in user)
        self.assertEqual(len(user['federated']), 1)
        self.assertEqual(user['federated'][0], new_fed[0])


class TestFederatedUserNameInList(ShadowUsersTests):
    """Test that federated user name is consistent between get_user and list_users.

    Verifies that FederatedUser.display_name is propagated to the User.name
    hybrid property in the list_users path, which uses explicit outerjoin
    rather than relying solely on lazy='joined' eager loading.
    """

    def setUp(self):
        super().setUp()
        self.useFixture(database.Database())
        self.load_backends()

    def test_federated_user_name_in_get_and_list(self):
        display_name = 'federated_test_user'
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'],
            protocol_id=self.protocol['id'],
            display_name=display_name,
        )

        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )

        # Also create a local user so list_users query has both local and
        # federated rows (exercises the outerjoin path).
        local_user = unit.new_user_ref(domain_id=self.domain_id)
        PROVIDERS.identity_api.create_user(local_user)

        # Verify get_user returns the federated display_name
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(
            display_name,
            user_ref['name'],
            'get_user should return the federated user display_name',
        )

        # Verify list_users (no filters) returns the same display_name.
        # This exercises the explicit outerjoin(model.LocalUser) path in
        # sql.py:list_users and ensures the federated_users eager-loaded
        # relationship is populated alongside the explicit join.
        users = PROVIDERS.identity_api.list_users()
        found = [u for u in users if u['id'] == user['id']]
        self.assertEqual(
            1, len(found), 'Federated user should appear in list_users'
        )
        self.assertIsNotNone(
            found[0]['name'],
            'list_users must not return None for federated user name',
        )
        self.assertEqual(
            display_name,
            found[0]['name'],
            'list_users should match get_user for federated display_name',
        )

    def test_orphaned_users_cleaned_up_after_idp_deletion(self):
        """Verify users become orphaned and are deleted after IDP deletion.

        When an IDP is deleted, federated_user records are CASCADE deleted.
        Users that had no other name source (no local_user, no nonlocal_user,
        no other federated_users) should be cleaned up.
        """
        from keystone.common import sql
        from keystone.identity.backends import sql_model as identity_model

        display_name = 'federated_orphan_user'
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'],
            protocol_id=self.protocol['id'],
            display_name=display_name,
        )

        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )
        user_id = user['id']

        with sql.session_for_read() as session:
            # Verify the user exists before IDP deletion
            u = session.get(identity_model.User, user_id)
            self.assertIsNotNone(u)

        # Delete the IDP, which should CASCADE delete federated_user records
        # and then clean up the orphaned user
        PROVIDERS.federation_api.delete_idp(self.idp['id'])

        # Clear the cache so get_user doesn't return stale data
        self.identity_api.get_user.invalidate()

        # The orphaned user should no longer exist
        self.assertRaises(
            exception.UserNotFound, self.identity_api.get_user, user_id
        )

    def test_orphaned_users_cleaned_up_after_protocol_deletion(self):
        """Verify users become orphaned and are deleted after protocol deletion.

        When a protocol is deleted, federated_user records for that protocol
        are CASCADE deleted. Users that had no other name source should be
        cleaned up.
        """
        from keystone.common import sql
        from keystone.identity.backends import sql_model as identity_model

        display_name = 'federated_orphan_protocol_user'
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'],
            protocol_id=self.protocol['id'],
            display_name=display_name,
        )

        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )
        user_id = user['id']

        with sql.session_for_read() as session:
            # Verify the user exists before protocol deletion
            u = session.get(identity_model.User, user_id)
            self.assertIsNotNone(u)

        # Delete the protocol, which should CASCADE delete federated_user
        # records and then clean up the orphaned user
        PROVIDERS.federation_api.delete_protocol(
            self.idp['id'], self.protocol['id']
        )

        # Clear the cache so get_user doesn't return stale data
        self.identity_api.get_user.invalidate()

        # The orphaned user should no longer exist
        self.assertRaises(
            exception.UserNotFound, self.identity_api.get_user, user_id
        )

    def test_orphaned_federated_users_cleaned_up_after_idp_deletion(self):
        """Verify federated_user records are cleaned up after IDP deletion.

        Some databases (SQLite) do not enforce FK CASCADE, so federated_user
        records whose IDP is deleted should be explicitly cleaned up.
        """
        from keystone.common import sql
        from keystone.identity.backends import sql_model as identity_model

        display_name = 'federated_cleanup_test'
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'],
            protocol_id=self.protocol['id'],
            display_name=display_name,
        )

        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )
        user_id = user['id']

        # Verify federated_user exists before IDP deletion
        with sql.session_for_read() as session:
            fed_count = (
                session.query(identity_model.FederatedUser)
                .filter_by(user_id=user_id)
                .count()
            )
            self.assertEqual(1, fed_count)

        # Delete the IDP
        PROVIDERS.federation_api.delete_idp(self.idp['id'])

        # Verify federated_user record was cleaned up even though
        # SQLite doesn't enforce FK CASCADE by default
        with sql.session_for_read() as session:
            fed_count = (
                session.query(identity_model.FederatedUser)
                .filter_by(idp_id=self.idp['id'])
                .count()
            )
            self.assertEqual(
                0,
                fed_count,
                'federated_user records for deleted IDP must be cleaned up',
            )

    def test_orphaned_federated_users_cleaned_up_after_protocol_deletion(self):
        """Verify federated_user records are cleaned up after protocol deletion.

        Some databases (SQLite) do not enforce FK CASCADE, so federated_user
        records whose protocol is deleted should be explicitly cleaned up.
        """
        from keystone.common import sql
        from keystone.identity.backends import sql_model as identity_model

        display_name = 'federated_cleanup_protocol_test'
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'],
            protocol_id=self.protocol['id'],
            display_name=display_name,
        )

        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )
        user_id = user['id']

        # Verify federated_user exists before protocol deletion
        with sql.session_for_read() as session:
            fed_count = (
                session.query(identity_model.FederatedUser)
                .filter_by(user_id=user_id)
                .count()
            )
            self.assertEqual(1, fed_count)

        # Delete the protocol
        PROVIDERS.federation_api.delete_protocol(
            self.idp['id'], self.protocol['id']
        )

        # Verify federated_user record was cleaned up
        with sql.session_for_read() as session:
            fed_count = (
                session.query(identity_model.FederatedUser)
                .filter_by(protocol_id=self.protocol['id'])
                .count()
            )
            self.assertEqual(
                0,
                fed_count,
                'federated_user records for deleted protocol must be cleaned up',
            )

    def test_user_group_membership_cleaned_on_orphan_user_deletion(self):
        """Verify UserGroupMembership rows are deleted before orphaned users.

        UserGroupMembership.user_id has FK on user.id WITHOUT ondelete='CASCADE'.
        Query.delete() bypasses ORM-level cascades, so we must explicitly clean up
        dependent rows before deleting orphaned users to avoid FK constraint errors.
        """
        from keystone.common import sql
        from keystone.identity.backends import sql_model as identity_model

        # Create a federated user
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'],
            protocol_id=self.protocol['id'],
            display_name='group_membership_test',
        )
        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )
        user_id = user['id']

        # Create a group and membership
        group = unit.new_group_ref(domain_id=self.domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        group_id = group['id']

        # Add membership
        PROVIDERS.identity_api.add_user_to_group(user_id, group_id)

        # Verify membership exists
        with sql.session_for_read() as session:
            membership_count = (
                session.query(identity_model.UserGroupMembership)
                .filter_by(user_id=user_id)
                .count()
            )
            self.assertEqual(1, membership_count)

        # Clear the cache so get_user doesn't return stale data
        self.identity_api.get_user.invalidate()

        # Delete the IDP, which triggers orphan user cleanup
        PROVIDERS.federation_api.delete_idp(self.idp['id'])

        # Verify user was deleted
        self.assertRaises(
            exception.UserNotFound, self.identity_api.get_user, user_id
        )

        # Verify UserGroupMembership row was cleaned up alongside the user
        with sql.session_for_read() as session:
            membership_count = (
                session.query(identity_model.UserGroupMembership)
                .filter_by(user_id=user_id)
                .count()
            )
            self.assertEqual(
                0,
                membership_count,
                'UserGroupMembership rows must be cleaned up before '
                'orphaned user deletion',
            )

    def test_expiring_user_group_membership_cleaned_on_orphan_deletion(self):
        """Verify ExpiringUserGroupMembership rows are deleted before users.

        ExpiringUserGroupMembership.user_id has FK on user.id WITHOUT
        ondelete='CASCADE'. Query.delete() bypasses ORM-level cascades, so we
        must explicitly clean up dependent rows before deleting orphaned users.
        """
        import datetime

        from keystone.common import sql
        from keystone.identity.backends import sql_model as identity_model

        # Create a federated user
        fed_dict = unit.new_federated_user_ref(
            idp_id=self.idp['id'],
            protocol_id=self.protocol['id'],
            display_name='expiring_membership_test',
        )
        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict
        )
        user_id = user['id']

        # Create a group
        group = unit.new_group_ref(domain_id=self.domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        group_id = group['id']

        # Insert an ExpiringUserGroupMembership row directly
        with sql.session_for_write() as session:
            membership = identity_model.ExpiringUserGroupMembership(
                user_id=user_id,
                group_id=group_id,
                idp_id=self.idp['id'],
                last_verified=datetime.datetime.now(datetime.UTC),
            )
            session.add(membership)

        # Verify membership exists
        with sql.session_for_read() as session:
            membership_count = (
                session.query(identity_model.ExpiringUserGroupMembership)
                .filter_by(user_id=user_id)
                .count()
            )
            self.assertEqual(1, membership_count)

        # Clear the cache so get_user doesn't return stale data
        self.identity_api.get_user.invalidate()

        # Delete the IDP, which triggers orphan user cleanup
        PROVIDERS.federation_api.delete_idp(self.idp['id'])

        # Verify user was deleted
        self.assertRaises(
            exception.UserNotFound, self.identity_api.get_user, user_id
        )

        # Verify ExpiringUserGroupMembership row was cleaned up
        with sql.session_for_read() as session:
            membership_count = (
                session.query(identity_model.ExpiringUserGroupMembership)
                .filter_by(user_id=user_id)
                .count()
            )
            self.assertEqual(
                0,
                membership_count,
                'ExpiringUserGroupMembership rows must be cleaned up '
                'before orphaned user deletion',
            )
