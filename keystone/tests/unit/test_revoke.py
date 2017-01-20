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
import uuid

import mock
from oslo_utils import timeutils
from six.moves import range
from testtools import matchers

from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.models import revoke_model
from keystone.revoke.backends import sql
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_backend_sql
from keystone.token.providers import common


CONF = keystone.conf.CONF


def _future_time():
    expire_delta = datetime.timedelta(seconds=1000)
    future_time = timeutils.utcnow() + expire_delta
    return future_time


def _past_time():
    expire_delta = datetime.timedelta(days=-1000)
    past_time = timeutils.utcnow() + expire_delta
    return past_time


def _sample_blank_token():
    issued_delta = datetime.timedelta(minutes=-2)
    issued_at = timeutils.utcnow() + issued_delta
    token_data = revoke_model.blank_token_data(issued_at)
    return token_data


def _sample_data():
    user_ids = []
    project_ids = []
    role_ids = []
    for i in range(0, 3):
        user_ids.append(uuid.uuid4().hex)
        project_ids.append(uuid.uuid4().hex)
        role_ids.append(uuid.uuid4().hex)

    # For testing purposes, create 3 project tokens with a different user_id,
    # role_id, and project_id which will be used to verify that revoking by
    # grant on certain user_id, project_id, and role_id pairs leaves these
    # project_tokens unrevoked if only one of the revoked columns are matched
    # but not all of them as the expected behavior dictates

    project_tokens = []
    i = len(project_tokens)
    project_tokens.append(_sample_blank_token())
    project_tokens[i]['user_id'] = user_ids[1]
    project_tokens[i]['project_id'] = project_ids[0]
    project_tokens[i]['roles'] = [role_ids[0]]

    i = len(project_tokens)
    project_tokens.append(_sample_blank_token())
    project_tokens[i]['user_id'] = user_ids[0]
    project_tokens[i]['project_id'] = project_ids[1]
    project_tokens[i]['roles'] = [role_ids[0]]

    i = len(project_tokens)
    project_tokens.append(_sample_blank_token())
    project_tokens[i]['user_id'] = user_ids[0]
    project_tokens[i]['project_id'] = project_ids[0]
    project_tokens[i]['roles'] = [role_ids[1]]

    return user_ids, project_ids, role_ids, project_tokens


def _matches(event, token_values):
    """See if the token matches the revocation event.

    Used as a secondary check on the logic to Check
    By Tree Below:  This is abrute force approach to checking.
    Compare each attribute from the event with the corresponding
    value from the token.  If the event does not have a value for
    the attribute, a match is still possible.  If the event has a
    value for the attribute, and it does not match the token, no match
    is possible, so skip the remaining checks.

    :param event: one revocation event to match
    :param token_values: dictionary with set of values taken from the
    token
    :returns: True if the token matches the revocation event, indicating the
    token has been revoked
    """
    # The token has three attributes that can match the user_id
    if event.user_id is not None:
        for attribute_name in ['user_id', 'trustor_id', 'trustee_id']:
            if event.user_id == token_values[attribute_name]:
                break
        else:
            return False

    # The token has two attributes that can match the domain_id
    if event.domain_id is not None:
        for attribute_name in ['identity_domain_id', 'assignment_domain_id']:
            if event.domain_id == token_values[attribute_name]:
                break
        else:
            return False

    if event.domain_scope_id is not None:
        if event.domain_scope_id != token_values['assignment_domain_id']:
            return False

    # If any one check does not match, the while token does
    # not match the event. The numerous return False indicate
    # that the token is still valid and short-circuits the
    # rest of the logic.
    attribute_names = ['project_id',
                       'expires_at', 'trust_id', 'consumer_id',
                       'access_token_id', 'audit_id', 'audit_chain_id']
    for attribute_name in attribute_names:
        if getattr(event, attribute_name) is not None:
            if (getattr(event, attribute_name) !=
                    token_values[attribute_name]):
                        return False

    if event.role_id is not None:
        roles = token_values['roles']
        for role in roles:
            if event.role_id == role:
                break
        else:
            return False
    if token_values['issued_at'] > event.issued_before:
        return False
    return True


class RevokeTests(object):

    def _assertTokenRevoked(self, events, token_data):
        backend = sql.Revoke()
        if events:
            self.assertTrue(revoke_model.is_revoked(events, token_data),
                            'Token should be revoked')
        return self.assertTrue(
            revoke_model.is_revoked(backend.list_events(token=token_data),
                                    token_data), 'Token should be revoked')

    def _assertTokenNotRevoked(self, events, token_data):
        backend = sql.Revoke()
        if events:
            self.assertTrue(revoke_model.is_revoked(events, token_data),
                            'Token should be revoked')
        return self.assertFalse(
            revoke_model.is_revoked(backend.list_events(token=token_data),
                                    token_data), 'Token should not be revoked')

    def test_list(self):
        self.revoke_api.revoke_by_user(user_id=1)
        self.assertEqual(1, len(self.revoke_api.list_events()))

        self.revoke_api.revoke_by_user(user_id=2)
        self.assertEqual(2, len(self.revoke_api.list_events()))

    def test_list_since(self):
        self.revoke_api.revoke_by_user(user_id=1)
        self.revoke_api.revoke_by_user(user_id=2)
        past = timeutils.utcnow() - datetime.timedelta(seconds=1000)
        self.assertEqual(2, len(self.revoke_api.list_events(last_fetch=past)))
        future = timeutils.utcnow() + datetime.timedelta(seconds=1000)
        self.assertEqual(0,
                         len(self.revoke_api.list_events(last_fetch=future)))

    def test_list_revoked_user(self):
        revocation_backend = sql.Revoke()
        events = []

        # This simulates creating a token for a specific user. When we revoke
        # the token we should have a single revocation event in the list. We
        # are going to assert that the token values match the only revocation
        # event in the backend.
        first_token = _sample_blank_token()
        first_token['user_id'] = uuid.uuid4().hex
        add_event(
            events, revoke_model.RevokeEvent(user_id=first_token['user_id'])
        )
        self.revoke_api.revoke_by_user(user_id=first_token['user_id'])
        self._assertTokenRevoked(events, first_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=first_token))
        )

        # This simulates creating a separate token for a separate user. We are
        # going to revoke the token just like we did for the previous token.
        # We should have two revocation events stored in the backend but only
        # one should match the values of the second token.
        second_token = _sample_blank_token()
        second_token['user_id'] = uuid.uuid4().hex
        add_event(
            events, revoke_model.RevokeEvent(user_id=second_token['user_id'])
        )
        self.revoke_api.revoke_by_user(user_id=second_token['user_id'])
        self._assertTokenRevoked(events, second_token)
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
        self._assertTokenNotRevoked(events, third_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=third_token))
        )
        # This gets a token but overrides the user_id of the token to be None.
        # Technically this should never happen because tokens must belong to
        # a user. What we're testing here is that the two revocation events
        # we've created won't match None values for the user_id.
        fourth_token = _sample_blank_token()
        fourth_token['user_id'] = None
        self._assertTokenNotRevoked(events, fourth_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=fourth_token))
        )

    def test_list_revoked_project(self):
        revocation_backend = sql.Revoke()
        events = []
        token = _sample_blank_token()

        # Create a token for a project, revoke token, check the token we
        # created has been revoked, and check the list returned a match for
        # the token when passed in.
        first_token = _sample_blank_token()
        first_token['project_id'] = uuid.uuid4().hex
        add_event(events, revoke_model.RevokeEvent(
            project_id=first_token['project_id']))
        revocation_backend.revoke(revoke_model.RevokeEvent(
            project_id=first_token['project_id']))
        self._assertTokenRevoked(events, first_token)
        self.assertEqual(1, len(revocation_backend.list_events(
            token=first_token)))

        # Create a second token, revoke it, check the token has been revoked,
        # and check the list to make sure that even though we now have 2
        # revoked events in the revocation list, it will only return 1 because
        # only one match for our second_token should exist
        second_token = _sample_blank_token()
        second_token['project_id'] = uuid.uuid4().hex
        add_event(events, revoke_model.RevokeEvent(
            project_id=second_token['project_id']))
        revocation_backend.revoke(revoke_model.RevokeEvent(
            project_id=second_token['project_id']))
        self._assertTokenRevoked(events, second_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=second_token)))

        # This gets a token but overrides project_id of the token to be None.
        # We expect that since there are two events which both have populated
        # project_ids, this should not match this third_token with any other
        # event in the list so we should receive 0.
        third_token = _sample_blank_token()
        third_token['project_id'] = None
        self._assertTokenNotRevoked(events, token)
        self.assertEqual(0, len(revocation_backend.list_events(token=token)))

    def test_list_revoked_audit(self):
        revocation_backend = sql.Revoke()
        events = []

        # Create a token with audit_id set, revoke it, check it is revoked,
        # check to make sure that list_events matches the token to the event we
        # just revoked.
        first_token = _sample_blank_token()
        first_token['audit_id'] = common.random_urlsafe_str()
        add_event(events, revoke_model.RevokeEvent(
            audit_id=first_token['audit_id']))
        self.revoke_api.revoke_by_audit_id(
            audit_id=first_token['audit_id'])
        self._assertTokenRevoked(events, first_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=first_token)))

        # Create a second token, revoke it, check it is revoked, check to make
        # sure that list events only finds 1 match since there are 2 and they
        # dont both have different populated audit_id fields
        second_token = _sample_blank_token()
        second_token['audit_id'] = common.random_urlsafe_str()
        add_event(events, revoke_model.RevokeEvent(
            audit_id=second_token['audit_id']))
        self.revoke_api.revoke_by_audit_id(
            audit_id=second_token['audit_id'])
        self._assertTokenRevoked(events, second_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=second_token)))

        # Create a third token with audit_id set to None to make sure that
        # since there are no events currently revoked with audit_id None this
        # finds no matches
        third_token = _sample_blank_token()
        third_token['audit_id'] = None
        self._assertTokenNotRevoked(events, third_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=third_token)))

    def test_list_revoked_since(self):
        revocation_backend = sql.Revoke()
        token = _sample_blank_token()
        self.revoke_api.revoke_by_user(user_id=None)
        self.revoke_api.revoke_by_user(user_id=None)
        self.assertEqual(2, len(revocation_backend.list_events(token=token)))
        future = timeutils.utcnow() + datetime.timedelta(seconds=1000)
        token['issued_at'] = future
        self.assertEqual(0, len(revocation_backend.list_events(token=token)))

    def test_list_revoked_multiple_filters(self):
        revocation_backend = sql.Revoke()
        events = []

        # create token that sets key/value filters in list_revoked
        first_token = _sample_blank_token()
        first_token['user_id'] = uuid.uuid4().hex
        first_token['project_id'] = uuid.uuid4().hex
        first_token['audit_id'] = common.random_urlsafe_str()
        # revoke event and then verify that that there is only one revocation
        # and verify the only revoked event is the token
        add_event(events, revoke_model.RevokeEvent(
            user_id=first_token['user_id'],
            project_id=first_token['project_id'],
            audit_id=first_token['audit_id']))
        self.revoke_api.revoke(revoke_model.RevokeEvent(
            user_id=first_token['user_id'],
            project_id=first_token['project_id'],
            audit_id=first_token['audit_id']))
        self._assertTokenRevoked(events, first_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=first_token)))
        # If a token has None values which the event contains it shouldn't
        # match and not be revoked
        second_token = _sample_blank_token()
        self._assertTokenNotRevoked(events, second_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=second_token)))
        # If an event column and corresponding dict value don't match, Then
        # it should not add the event in the list. Demonstrate for project
        third_token = _sample_blank_token()
        third_token['project_id'] = uuid.uuid4().hex
        self._assertTokenNotRevoked(events, third_token)
        self.assertEqual(
            0, len(revocation_backend.list_events(token=third_token)))
        # A revoked event with user_id as null and token user_id non null
        # should still be return an event and be revoked if other non null
        # event fields match non null token fields
        fourth_token = _sample_blank_token()
        fourth_token['user_id'] = uuid.uuid4().hex
        fourth_token['project_id'] = uuid.uuid4().hex
        fourth_token['audit_id'] = common.random_urlsafe_str()
        add_event(events, revoke_model.RevokeEvent(
            project_id=fourth_token['project_id'],
            audit_id=fourth_token['audit_id']))
        self.revoke_api.revoke(revoke_model.RevokeEvent(
            project_id=fourth_token['project_id'],
            audit_id=fourth_token['audit_id']))
        self._assertTokenRevoked(events, fourth_token)
        self.assertEqual(
            1, len(revocation_backend.list_events(token=fourth_token)))

    def _user_field_test(self, field_name):
        token = _sample_blank_token()
        token[field_name] = uuid.uuid4().hex
        self.revoke_api.revoke_by_user(user_id=token[field_name])
        self._assertTokenRevoked(None, token)
        token2 = _sample_blank_token()
        token2[field_name] = uuid.uuid4().hex
        self._assertTokenNotRevoked(None, token2)

    def test_revoke_by_user(self):
        self._user_field_test('user_id')

    def test_revoke_by_user_matches_trustee(self):
        self._user_field_test('trustee_id')

    def test_revoke_by_user_matches_trustor(self):
        self._user_field_test('trustor_id')

    def test_revoke_by_audit_id(self):
        token = _sample_blank_token()
        # Audit ID and Audit Chain ID are populated with the same value
        # if the token is an original token
        token['audit_id'] = uuid.uuid4().hex
        token['audit_chain_id'] = token['audit_id']
        self.revoke_api.revoke_by_audit_id(audit_id=token['audit_id'])
        self._assertTokenRevoked(None, token)

        token2 = _sample_blank_token()
        token2['audit_id'] = uuid.uuid4().hex
        token2['audit_chain_id'] = token2['audit_id']
        self._assertTokenNotRevoked(None, token2)

    def test_by_project_grant(self):
        user_ids, project_ids, role_ids, project_tokens = _sample_data()
        token1 = _sample_blank_token()
        token1['roles'] = role_ids[0]
        token1['user_id'] = user_ids[0]
        token1['project_id'] = project_ids[0]

        token2 = _sample_blank_token()
        token2['roles'] = role_ids[1]
        token2['user_id'] = user_ids[1]
        token2['project_id'] = project_ids[1]

        token3 = _sample_blank_token()
        token3['roles'] = [role_ids[0],
                           role_ids[1],
                           role_ids[2]]
        token3['user_id'] = user_ids[2]
        token3['project_id'] = project_ids[2]

        # Check that all tokens are revoked at the start
        self._assertTokenNotRevoked(None, token1)
        self._assertTokenNotRevoked(None, token2)
        self._assertTokenNotRevoked(None, token3)
        for token in project_tokens:
            self._assertTokenNotRevoked(None, token)

        self.revoke_api.revoke_by_grant(role_id=role_ids[0],
                                        user_id=user_ids[0],
                                        project_id=project_ids[0])

        # Only the first token should be revoked
        self._assertTokenRevoked(None, token1)
        self._assertTokenNotRevoked(None, token2)
        self._assertTokenNotRevoked(None, token3)
        for token in project_tokens:
            self._assertTokenNotRevoked(None, token)

        self.revoke_api.revoke_by_grant(role_id=role_ids[1],
                                        user_id=user_ids[1],
                                        project_id=project_ids[1])

        # Tokens 1 and 2 should be revoked now
        self._assertTokenRevoked(None, token1)
        self._assertTokenRevoked(None, token2)
        self._assertTokenNotRevoked(None, token3)
        for token in project_tokens:
            self._assertTokenNotRevoked(None, token)

        # test that multiple roles with a single user and project get revoked
        # and invalidate token3
        self.revoke_api.revoke_by_grant(role_id=role_ids[0],
                                        user_id=user_ids[2],
                                        project_id=project_ids[2])

        self.revoke_api.revoke_by_grant(role_id=role_ids[1],
                                        user_id=user_ids[2],
                                        project_id=project_ids[2])

        self.revoke_api.revoke_by_grant(role_id=role_ids[2],
                                        user_id=user_ids[2],
                                        project_id=project_ids[2])

        # Tokens 1, 2, and 3 should now be revoked leaving project_tokens
        # unrevoked.
        self._assertTokenRevoked(None, token1)
        self._assertTokenRevoked(None, token2)
        self._assertTokenRevoked(None, token3)
        for token in project_tokens:
            self._assertTokenNotRevoked(None, token)

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
        self.revoke_api.revoke_by_audit_chain_id(audit_chain_id)
        token_values['audit_chain_id'] = audit_chain_id
        self.assertRaises(exception.TokenNotFound,
                          self.revoke_api.check_token,
                          token_values)

        # Move our clock forward by 2h, build a new token and validate it.
        # 'synchronize' should now be exercised and remove old expired events
        mock_utcnow.return_value = now_plus_2h
        self.revoke_api.revoke_by_audit_chain_id(audit_chain_id)
        # two hours later, it should still be not found
        self.assertRaises(exception.TokenNotFound,
                          self.revoke_api.check_token,
                          token_values)

    def test_delete_group_without_role_does_not_revoke_users(self):
        revocation_backend = sql.Revoke()
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        # Create two groups. Group1 will be used to test deleting a group,
        # without role assignments and users in the group, doesn't create
        # revoked events. Group2 will show that deleting a group with role
        # assignment and users in the group does create revoked events
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = self.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain['id'])
        group2 = self.identity_api.create_group(group2)
        role = unit.new_role_ref()
        self.role_api.create_role(role['id'], role)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = self.identity_api.create_user(user1)
        user2 = unit.new_user_ref(domain_id=domain['id'])
        user2 = self.identity_api.create_user(user2)

        # Add two users to the group, verify they are added, delete group, and
        # check that the revocaiton events have not been created
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group1['id'])
        self.identity_api.add_user_to_group(user_id=user2['id'],
                                            group_id=group1['id'])
        self.assertEqual(
            2, len(self.identity_api.list_users_in_group(group1['id'])))
        self.identity_api.delete_group(group1['id'])
        self.assertEqual(0, len(revocation_backend.list_events()))

        # Assign a role to the group, add two users to the group, verify that
        # the role has been assigned to the group, verify the users have been
        # added to the group, delete the group, check that the revocation
        # events have been created
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=domain['id'],
                                         role_id=role['id'])
        grants = self.assignment_api.list_role_assignments(role_id=role['id'])
        self.assertThat(grants, matchers.HasLength(1))
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group2['id'])
        self.identity_api.add_user_to_group(user_id=user2['id'],
                                            group_id=group2['id'])
        self.assertEqual(
            2, len(self.identity_api.list_users_in_group(group2['id'])))
        self.identity_api.delete_group(group2['id'])
        self.assertEqual(2, len(revocation_backend.list_events()))


class UUIDSqlRevokeTests(test_backend_sql.SqlTests, RevokeTests):
    def config_overrides(self):
        super(UUIDSqlRevokeTests, self).config_overrides()
        self.config_fixture.config(
            group='token',
            provider='uuid',
            revoke_by_id=False)


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


def add_event(events, event):
    events.append(event)
    return event


def remove_event(events, event):
    for target in events:
        if target == event:
            events.remove(target)


class RevokeListTests(unit.TestCase):
    def setUp(self):
        super(RevokeListTests, self).setUp()
        self.events = []
        self.revoke_events = list()

    def _assertTokenRevoked(self, token_data):
        self.assertTrue(any([_matches(e, token_data) for e in self.events]))
        return self.assertTrue(
            revoke_model.is_revoked(self.revoke_events, token_data),
            'Token should be revoked')

    def _assertTokenNotRevoked(self, token_data):
        self.assertFalse(any([_matches(e, token_data) for e in self.events]))
        return self.assertFalse(
            revoke_model.is_revoked(self.revoke_events, token_data),
            'Token should not be revoked')

    def _revoke_by_user(self, user_id):
        return add_event(
            self.revoke_events,
            revoke_model.RevokeEvent(user_id=user_id))

    def _revoke_by_audit_chain_id(self, audit_chain_id, project_id=None,
                                  domain_id=None):
        event = add_event(
            self.revoke_events,
            revoke_model.RevokeEvent(audit_chain_id=audit_chain_id,
                                     project_id=project_id,
                                     domain_id=domain_id)
        )
        self.events.append(event)
        return event

    def _revoke_by_expiration(self, user_id, expires_at, project_id=None,
                              domain_id=None):
        event = add_event(
            self.revoke_events,
            revoke_model.RevokeEvent(user_id=user_id,
                                     expires_at=expires_at,
                                     project_id=project_id,
                                     domain_id=domain_id))
        self.events.append(event)
        return event

    def _revoke_by_user_and_project(self, user_id, project_id):
        event = add_event(self.revoke_events,
                          revoke_model.RevokeEvent(project_id=project_id,
                                                   user_id=user_id))
        self.events.append(event)
        return event

    def _revoke_by_project_role_assignment(self, project_id, role_id):
        event = add_event(self.revoke_events,
                          revoke_model.RevokeEvent(project_id=project_id,
                                                   role_id=role_id))
        self.events.append(event)
        return event

    def _revoke_by_domain_role_assignment(self, domain_id, role_id):
        event = add_event(self.revoke_events,
                          revoke_model.RevokeEvent(domain_id=domain_id,
                                                   role_id=role_id))
        self.events.append(event)
        return event

    def _revoke_by_domain(self, domain_id):
        event = add_event(self.revoke_events,
                          revoke_model.RevokeEvent(domain_id=domain_id))
        self.events.append(event)

    def test_revoke_by_audit_chain_id(self):
        audit_id = common.build_audit_info(parent_audit_id=None)[0]
        token_data_1 = _sample_blank_token()
        # Audit ID and Audit Chain ID are populated with the same value
        # if the token is an original token
        token_data_1['audit_id'] = audit_id
        token_data_1['audit_chain_id'] = audit_id
        event = self._revoke_by_audit_chain_id(audit_id)
        self._assertTokenRevoked(token_data_1)

        audit_id_2 = common.build_audit_info(parent_audit_id=audit_id)[0]
        token_data_2 = _sample_blank_token()
        token_data_2['audit_id'] = audit_id_2
        token_data_2['audit_chain_id'] = audit_id
        self._assertTokenRevoked(token_data_2)

        self.remove_event(event)
        self._assertTokenNotRevoked(token_data_1)
        self._assertTokenNotRevoked(token_data_2)

    def remove_event(self, event):
        self.events.remove(event)
        remove_event(self.revoke_events, event)

    def test_by_project_and_user_and_role(self):
        user_id1 = uuid.uuid4().hex
        user_id2 = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        self.events.append(self._revoke_by_user(user_id1))
        self.events.append(
            self._revoke_by_user_and_project(user_id2, project_id))
        token_data = _sample_blank_token()
        token_data['user_id'] = user_id2
        token_data['project_id'] = project_id
        self._assertTokenRevoked(token_data)

    def test_by_domain_user(self):
        # If revoke a domain, then a token for a user in the domain is revoked

        user_id = uuid.uuid4().hex
        domain_id = uuid.uuid4().hex

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['identity_domain_id'] = domain_id

        self._revoke_by_domain(domain_id)

        self._assertTokenRevoked(token_data)

    def test_by_domain_project(self):
        # If revoke a domain, then a token scoped to a project in the domain
        # is revoked.

        user_id = uuid.uuid4().hex
        user_domain_id = uuid.uuid4().hex

        project_id = uuid.uuid4().hex
        project_domain_id = uuid.uuid4().hex

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['identity_domain_id'] = user_domain_id
        token_data['project_id'] = project_id
        token_data['assignment_domain_id'] = project_domain_id

        self._revoke_by_domain(project_domain_id)

        self._assertTokenRevoked(token_data)

    def test_by_domain_domain(self):
        # If revoke a domain, then a token scoped to the domain is revoked.

        user_id = uuid.uuid4().hex
        user_domain_id = uuid.uuid4().hex

        domain_id = uuid.uuid4().hex

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['identity_domain_id'] = user_domain_id
        token_data['assignment_domain_id'] = domain_id

        self._revoke_by_domain(domain_id)

        self._assertTokenRevoked(token_data)

    def _assertEmpty(self, collection):
        return self.assertEqual(0, len(collection), "collection not empty")

    def test_cleanup(self):
        events = self.events
        self._assertEmpty(self.revoke_events)
        for i in range(0, 10):
            events.append(
                self._revoke_by_project_role_assignment(uuid.uuid4().hex,
                                                        uuid.uuid4().hex))
            events.append(
                self._revoke_by_domain_role_assignment(uuid.uuid4().hex,
                                                       uuid.uuid4().hex))
            events.append(
                self._revoke_by_domain_role_assignment(uuid.uuid4().hex,
                                                       uuid.uuid4().hex))
            events.append(
                self._revoke_by_user_and_project(uuid.uuid4().hex,
                                                 uuid.uuid4().hex))

        for event in self.events:
            remove_event(self.revoke_events, event)
        self._assertEmpty(self.revoke_events)
