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


import datetime
from unittest import mock
import uuid

from oslo_utils import timeutils
from testtools import matchers

from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.models import revoke_model
from keystone.revoke.backends import sql
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_backend_sql
from keystone.token import provider


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


def _future_time():
    expire_delta = datetime.timedelta(seconds=1000)
    future_time = timeutils.utcnow() + expire_delta
    return future_time


def _sample_blank_token():
    issued_delta = datetime.timedelta(minutes=-2)
    issued_at = timeutils.utcnow() + issued_delta
    token_data = revoke_model.blank_token_data(issued_at)
    return token_data


class RevokeTests(object):

    def _assertTokenRevoked(self, token_data):
        self.assertRaises(exception.TokenNotFound,
                          PROVIDERS.revoke_api.check_token,
                          token=token_data)

    def _assertTokenNotRevoked(self, token_data):
        self.assertIsNone(PROVIDERS.revoke_api.check_token(token_data))

    def test_list(self):
        PROVIDERS.revoke_api.revoke_by_user(user_id=1)
        self.assertEqual(1, len(PROVIDERS.revoke_api.list_events()))

        PROVIDERS.revoke_api.revoke_by_user(user_id=2)
        self.assertEqual(2, len(PROVIDERS.revoke_api.list_events()))

    def test_list_since(self):
        PROVIDERS.revoke_api.revoke_by_user(user_id=1)
        PROVIDERS.revoke_api.revoke_by_user(user_id=2)
        past = timeutils.utcnow() - datetime.timedelta(seconds=1000)
        self.assertEqual(
            2, len(PROVIDERS.revoke_api.list_events(last_fetch=past))
        )
        future = timeutils.utcnow() + datetime.timedelta(seconds=1000)
        self.assertEqual(
            0, len(PROVIDERS.revoke_api.list_events(last_fetch=future))
        )

    def test_list_revoked_user(self):
        revocation_backend = sql.Revoke()

        # This simulates creating a token for a specific user. When we revoke
        # the token we should have a single revocation event in the list. We
        # are going to assert that the token values match the only revocation
        # event in the backend.
        first_token = _sample_blank_token()
        first_token['user_id'] = uuid.uuid4().hex
        PROVIDERS.revoke_api.revoke_by_user(user_id=first_token['user_id'])
        self._assertTokenRevoked(first_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=first_token))
        )

        # This simulates creating a separate token for a separate user. We are
        # going to revoke the token just like we did for the previous token.
        # We should have two revocation events stored in the backend but only
        # one should match the values of the second token.
        second_token = _sample_blank_token()
        second_token['user_id'] = uuid.uuid4().hex
        PROVIDERS.revoke_api.revoke_by_user(user_id=second_token['user_id'])
        self._assertTokenRevoked(second_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=second_token))
        )
        # This simulates creating another separate token for a separate user,
        # but we're not going to issue a revocation event. Even though we have
        # two revocation events persisted in the backend, neither of them
        # should match the values of the third token. If they did - our
        # revocation event matching would be too heavy handed, which would
        # result in over-generalized revocation patterns.
        third_token = _sample_blank_token()
        third_token['user_id'] = uuid.uuid4().hex
        self._assertTokenNotRevoked(third_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=third_token))
        )
        # This gets a token but overrides the user_id of the token to be None.
        # Technically this should never happen because tokens must belong to
        # a user. What we're testing here is that the two revocation events
        # we've created won't match None values for the user_id.
        fourth_token = _sample_blank_token()
        fourth_token['user_id'] = None
        self._assertTokenNotRevoked(fourth_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=fourth_token))
        )

    def test_list_revoked_project(self):
        revocation_backend = sql.Revoke()
        token = _sample_blank_token()

        # Create a token for a project, revoke token, check the token we
        # created has been revoked, and check the list returned a match for
        # the token when passed in.
        first_token = _sample_blank_token()
        first_token['project_id'] = uuid.uuid4().hex
        revocation_backend.revoke(revoke_model.RevokeEvent(
            project_id=first_token['project_id']))
        self._assertTokenRevoked(first_token)
        self.assertEqual(1, len(revocation_backend.list_events(
            token=first_token)))

        # Create a second token, revoke it, check the token has been revoked,
        # and check the list to make sure that even though we now have 2
        # revoked events in the revocation list, it will only return 1 because
        # only one match for our second_token should exist
        second_token = _sample_blank_token()
        second_token['project_id'] = uuid.uuid4().hex
        revocation_backend.revoke(revoke_model.RevokeEvent(
            project_id=second_token['project_id']))
        self._assertTokenRevoked(second_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=second_token)))

        # This gets a token but overrides project_id of the token to be None.
        # We expect that since there are two events which both have populated
        # project_ids, this should not match this third_token with any other
        # event in the list so we should receive 0.
        third_token = _sample_blank_token()
        third_token['project_id'] = None
        self._assertTokenNotRevoked(token)
        self.assertEqual(0, len(revocation_backend.list_events(token=token)))

    def test_list_revoked_audit(self):
        revocation_backend = sql.Revoke()

        # Create a token with audit_id set, revoke it, check it is revoked,
        # check to make sure that list_events matches the token to the event we
        # just revoked.
        first_token = _sample_blank_token()
        first_token['audit_id'] = provider.random_urlsafe_str()
        PROVIDERS.revoke_api.revoke_by_audit_id(
            audit_id=first_token['audit_id'])
        self._assertTokenRevoked(first_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=first_token)))

        # Create a second token, revoke it, check it is revoked, check to make
        # sure that list events only finds 1 match since there are 2 and they
        # dont both have different populated audit_id fields
        second_token = _sample_blank_token()
        second_token['audit_id'] = provider.random_urlsafe_str()
        PROVIDERS.revoke_api.revoke_by_audit_id(
            audit_id=second_token['audit_id'])
        self._assertTokenRevoked(second_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=second_token)))

        # Create a third token with audit_id set to None to make sure that
        # since there are no events currently revoked with audit_id None this
        # finds no matches
        third_token = _sample_blank_token()
        third_token['audit_id'] = None
        self._assertTokenNotRevoked(third_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=third_token)))

    def test_list_revoked_since(self):
        revocation_backend = sql.Revoke()
        token = _sample_blank_token()
        PROVIDERS.revoke_api.revoke_by_user(user_id=None)
        PROVIDERS.revoke_api.revoke_by_user(user_id=None)
        self.assertEqual(2, len(revocation_backend.list_events(token=token)))
        future = timeutils.utcnow() + datetime.timedelta(seconds=1000)
        token['issued_at'] = future
        self.assertEqual(0, len(revocation_backend.list_events(token=token)))

    def test_list_revoked_multiple_filters(self):
        revocation_backend = sql.Revoke()

        # create token that sets key/value filters in list_revoked
        first_token = _sample_blank_token()
        first_token['user_id'] = uuid.uuid4().hex
        first_token['project_id'] = uuid.uuid4().hex
        first_token['audit_id'] = provider.random_urlsafe_str()
        # revoke event and then verify that there is only one revocation
        # and verify the only revoked event is the token
        PROVIDERS.revoke_api.revoke(revoke_model.RevokeEvent(
            user_id=first_token['user_id'],
            project_id=first_token['project_id'],
            audit_id=first_token['audit_id']))
        self._assertTokenRevoked(first_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=first_token)))
        # If a token has None values which the event contains it shouldn't
        # match and not be revoked
        second_token = _sample_blank_token()
        self._assertTokenNotRevoked(second_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=second_token)))
        # If an event column and corresponding dict value don't match, Then
        # it should not add the event in the list. Demonstrate for project
        third_token = _sample_blank_token()
        third_token['project_id'] = uuid.uuid4().hex
        self._assertTokenNotRevoked(third_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=third_token)))
        # A revoked event with user_id as null and token user_id non null
        # should still be return an event and be revoked if other non null
        # event fields match non null token fields
        fourth_token = _sample_blank_token()
        fourth_token['user_id'] = uuid.uuid4().hex
        fourth_token['project_id'] = uuid.uuid4().hex
        fourth_token['audit_id'] = provider.random_urlsafe_str()
        PROVIDERS.revoke_api.revoke(revoke_model.RevokeEvent(
            project_id=fourth_token['project_id'],
            audit_id=fourth_token['audit_id']))
        self._assertTokenRevoked(fourth_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=fourth_token)))

    def _user_field_test(self, field_name):
        token = _sample_blank_token()
        token[field_name] = uuid.uuid4().hex
        PROVIDERS.revoke_api.revoke_by_user(user_id=token[field_name])
        self._assertTokenRevoked(token)
        token2 = _sample_blank_token()
        token2[field_name] = uuid.uuid4().hex
        self._assertTokenNotRevoked(token2)

    def test_revoke_by_user(self):
        self._user_field_test('user_id')

    def test_revoke_by_user_matches_trustee(self):
        self._user_field_test('trustee_id')

    def test_revoke_by_user_matches_trustor(self):
        self._user_field_test('trustor_id')

    def test_by_domain_user(self):
        revocation_backend = sql.Revoke()
        # If revoke a domain, then a token for a user in the domain is revoked
        user_id = uuid.uuid4().hex
        domain_id = uuid.uuid4().hex

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['identity_domain_id'] = domain_id

        self._assertTokenNotRevoked(token_data)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=token_data)))

        PROVIDERS.revoke_api.revoke(
            revoke_model.RevokeEvent(domain_id=domain_id)
        )

        self._assertTokenRevoked(token_data)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=token_data)))

    def test_by_domain_project(self):
        revocation_backend = sql.Revoke()

        token_data = _sample_blank_token()
        token_data['user_id'] = uuid.uuid4().hex
        token_data['identity_domain_id'] = uuid.uuid4().hex
        token_data['project_id'] = uuid.uuid4().hex
        token_data['assignment_domain_id'] = uuid.uuid4().hex

        self._assertTokenNotRevoked(token_data)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=token_data)))

        # If revoke a domain, then a token scoped to a project in the domain
        # is revoked.
        PROVIDERS.revoke_api.revoke(revoke_model.RevokeEvent(
            domain_id=token_data['assignment_domain_id']))

        self._assertTokenRevoked(token_data)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=token_data)))

    def test_by_domain_domain(self):
        revocation_backend = sql.Revoke()

        token_data = _sample_blank_token()
        token_data['user_id'] = uuid.uuid4().hex
        token_data['identity_domain_id'] = uuid.uuid4().hex
        token_data['assignment_domain_id'] = uuid.uuid4().hex

        self._assertTokenNotRevoked(token_data)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=token_data)))

        # If revoke a domain, then a token scoped to the domain is revoked.
        PROVIDERS.revoke_api.revoke(revoke_model.RevokeEvent(
            domain_id=token_data['assignment_domain_id']))

        self._assertTokenRevoked(token_data)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=token_data)))

    def test_revoke_by_audit_id(self):
        token = _sample_blank_token()
        # Audit ID and Audit Chain ID are populated with the same value
        # if the token is an original token
        token['audit_id'] = uuid.uuid4().hex
        token['audit_chain_id'] = token['audit_id']
        PROVIDERS.revoke_api.revoke_by_audit_id(audit_id=token['audit_id'])
        self._assertTokenRevoked(token)

        token2 = _sample_blank_token()
        token2['audit_id'] = uuid.uuid4().hex
        token2['audit_chain_id'] = token2['audit_id']
        self._assertTokenNotRevoked(token2)

    def test_revoke_by_audit_chain_id(self):
        revocation_backend = sql.Revoke()

        # Create our first token with audit_id
        audit_id = provider.random_urlsafe_str()
        token = _sample_blank_token()
        # Audit ID and Audit Chain ID are populated with the same value
        # if the token is an original token
        token['audit_id'] = audit_id
        token['audit_chain_id'] = audit_id
        # Check that the token is not revoked
        self._assertTokenNotRevoked(token)
        self.assertEqual(0, len(revocation_backend.list_events(token=token)))

        # Revoked token by audit chain id using the audit_id
        PROVIDERS.revoke_api.revoke_by_audit_chain_id(audit_id)
        # Check that the token is now revoked
        self._assertTokenRevoked(token)
        self.assertEqual(1, len(revocation_backend.list_events(token=token)))

    @mock.patch.object(timeutils, 'utcnow')
    def test_expired_events_are_removed(self, mock_utcnow):
        def _sample_token_values():
            token = _sample_blank_token()
            token['expires_at'] = utils.isotime(_future_time(),
                                                subsecond=True)
            return token

        now = datetime.datetime.utcnow()
        now_plus_2h = now + datetime.timedelta(hours=2)
        mock_utcnow.return_value = now

        # Build a token and validate it. This will seed the cache for the
        # future 'synchronize' call.
        token_values = _sample_token_values()

        audit_chain_id = uuid.uuid4().hex
        PROVIDERS.revoke_api.revoke_by_audit_chain_id(audit_chain_id)
        token_values['audit_chain_id'] = audit_chain_id
        self.assertRaises(exception.TokenNotFound,
                          PROVIDERS.revoke_api.check_token,
                          token_values)

        # Move our clock forward by 2h, build a new token and validate it.
        # 'synchronize' should now be exercised and remove old expired events
        mock_utcnow.return_value = now_plus_2h
        PROVIDERS.revoke_api.revoke_by_audit_chain_id(audit_chain_id)
        # two hours later, it should still be not found
        self.assertRaises(exception.TokenNotFound,
                          PROVIDERS.revoke_api.check_token,
                          token_values)

    def test_delete_group_without_role_does_not_revoke_users(self):
        revocation_backend = sql.Revoke()
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        # Create two groups. Group1 will be used to test deleting a group,
        # without role assignments and users in the group, doesn't create
        # revoked events. Group2 will show that deleting a group with role
        # assignment and users in the group does create revoked events
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        user2 = unit.new_user_ref(domain_id=domain['id'])
        user2 = PROVIDERS.identity_api.create_user(user2)

        # Add two users to the group, verify they are added, delete group, and
        # check that the revocaiton events have not been created
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user1['id'], group_id=group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user2['id'], group_id=group1['id']
        )
        self.assertEqual(
            2, len(PROVIDERS.identity_api.list_users_in_group(group1['id'])))
        PROVIDERS.identity_api.delete_group(group1['id'])
        self.assertEqual(0, len(revocation_backend.list_events()))

        # Assign a role to the group, add two users to the group, verify that
        # the role has been assigned to the group, verify the users have been
        # added to the group, delete the group, check that the revocation
        # events have been created
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], domain_id=domain['id'], role_id=role['id']
        )
        grants = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id']
        )
        self.assertThat(grants, matchers.HasLength(1))
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user1['id'], group_id=group2['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user2['id'], group_id=group2['id']
        )
        self.assertEqual(
            2, len(PROVIDERS.identity_api.list_users_in_group(group2['id'])))
        PROVIDERS.identity_api.delete_group(group2['id'])
        self.assertEqual(2, len(revocation_backend.list_events()))


class FernetSqlRevokeTests(test_backend_sql.SqlTests, RevokeTests):
    def config_overrides(self):
        super(FernetSqlRevokeTests, self).config_overrides()
        self.config_fixture.config(
            group='token',
            provider='fernet',
            revoke_by_id=False)
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )
