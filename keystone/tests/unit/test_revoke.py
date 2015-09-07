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
from keystone.contrib.revoke import model
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import test_backend_sql
from keystone.token import provider


def _new_id():
    return uuid.uuid4().hex


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
    token_data = model.blank_token_data(issued_at)
    return token_data


def _matches(event, token_values):
    """See if the token matches the revocation event.

    Used as a secondary check on the logic to Check
    By Tree Below:  This is abrute force approach to checking.
    Compare each attribute from the event with the corresponding
    value from the token.  If the event does not have a value for
    the attribute, a match is still possible.  If the event has a
    value for the attribute, and it does not match the token, no match
    is possible, so skip the remaining checks.

    :param event one revocation event to match
    :param token_values dictionary with set of values taken from the
    token
    :returns if the token matches the revocation event, indicating the
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

    def test_list(self):
        self.revoke_api.revoke_by_user(user_id=1)
        self.assertEqual(1, len(self.revoke_api.list_events()))

        self.revoke_api.revoke_by_user(user_id=2)
        self.assertEqual(2, len(self.revoke_api.list_events()))

    def test_list_since(self):
        self.revoke_api.revoke_by_user(user_id=1)
        self.revoke_api.revoke_by_user(user_id=2)
        past = timeutils.utcnow() - datetime.timedelta(seconds=1000)
        self.assertEqual(2, len(self.revoke_api.list_events(past)))
        future = timeutils.utcnow() + datetime.timedelta(seconds=1000)
        self.assertEqual(0, len(self.revoke_api.list_events(future)))

    def test_past_expiry_are_removed(self):
        user_id = 1
        self.revoke_api.revoke_by_expiration(user_id, _future_time())
        self.assertEqual(1, len(self.revoke_api.list_events()))
        event = model.RevokeEvent()
        event.revoked_at = _past_time()
        self.revoke_api.revoke(event)
        self.assertEqual(1, len(self.revoke_api.list_events()))

    @mock.patch.object(timeutils, 'utcnow')
    def test_expired_events_removed_validate_token_success(self, mock_utcnow):
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

        user_id = _new_id()
        self.revoke_api.revoke_by_user(user_id)
        token_values['user_id'] = user_id
        self.assertRaises(exception.TokenNotFound,
                          self.revoke_api.check_token,
                          token_values)

        # Move our clock forward by 2h, build a new token and validate it.
        # 'synchronize' should now be exercised and remove old expired events
        mock_utcnow.return_value = now_plus_2h
        self.revoke_api.revoke_by_expiration(_new_id(), now_plus_2h)
        # should no longer throw an exception
        self.revoke_api.check_token(token_values)

    def test_revoke_by_expiration_project_and_domain_fails(self):
        user_id = _new_id()
        expires_at = utils.isotime(_future_time(), subsecond=True)
        domain_id = _new_id()
        project_id = _new_id()
        self.assertThat(
            lambda: self.revoke_api.revoke_by_expiration(
                user_id, expires_at, domain_id=domain_id,
                project_id=project_id),
            matchers.raises(exception.UnexpectedError))


class SqlRevokeTests(test_backend_sql.SqlTests, RevokeTests):
    def config_overrides(self):
        super(SqlRevokeTests, self).config_overrides()
        self.config_fixture.config(group='revoke', driver='sql')
        self.config_fixture.config(
            group='token',
            provider='pki',
            revoke_by_id=False)


class KvsRevokeTests(unit.TestCase, RevokeTests):
    def config_overrides(self):
        super(KvsRevokeTests, self).config_overrides()
        self.config_fixture.config(group='revoke', driver='kvs')
        self.config_fixture.config(
            group='token',
            provider='pki',
            revoke_by_id=False)

    def setUp(self):
        super(KvsRevokeTests, self).setUp()
        self.load_backends()


class RevokeTreeTests(unit.TestCase):
    def setUp(self):
        super(RevokeTreeTests, self).setUp()
        self.events = []
        self.tree = model.RevokeTree()
        self._sample_data()

    def _sample_data(self):
        user_ids = []
        project_ids = []
        role_ids = []
        for i in range(0, 3):
            user_ids.append(_new_id())
            project_ids.append(_new_id())
            role_ids.append(_new_id())

        project_tokens = []
        i = len(project_tokens)
        project_tokens.append(_sample_blank_token())
        project_tokens[i]['user_id'] = user_ids[0]
        project_tokens[i]['project_id'] = project_ids[0]
        project_tokens[i]['roles'] = [role_ids[1]]

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

        token_to_revoke = _sample_blank_token()
        token_to_revoke['user_id'] = user_ids[0]
        token_to_revoke['project_id'] = project_ids[0]
        token_to_revoke['roles'] = [role_ids[0]]

        self.project_tokens = project_tokens
        self.user_ids = user_ids
        self.project_ids = project_ids
        self.role_ids = role_ids
        self.token_to_revoke = token_to_revoke

    def _assertTokenRevoked(self, token_data):
        self.assertTrue(any([_matches(e, token_data) for e in self.events]))
        return self.assertTrue(self.tree.is_revoked(token_data),
                               'Token should be revoked')

    def _assertTokenNotRevoked(self, token_data):
        self.assertFalse(any([_matches(e, token_data) for e in self.events]))
        return self.assertFalse(self.tree.is_revoked(token_data),
                                'Token should not be revoked')

    def _revoke_by_user(self, user_id):
        return self.tree.add_event(
            model.RevokeEvent(user_id=user_id))

    def _revoke_by_audit_id(self, audit_id):
        event = self.tree.add_event(
            model.RevokeEvent(audit_id=audit_id))
        self.events.append(event)
        return event

    def _revoke_by_audit_chain_id(self, audit_chain_id, project_id=None,
                                  domain_id=None):
        event = self.tree.add_event(
            model.RevokeEvent(audit_chain_id=audit_chain_id,
                              project_id=project_id,
                              domain_id=domain_id)
        )
        self.events.append(event)
        return event

    def _revoke_by_expiration(self, user_id, expires_at, project_id=None,
                              domain_id=None):
        event = self.tree.add_event(
            model.RevokeEvent(user_id=user_id,
                              expires_at=expires_at,
                              project_id=project_id,
                              domain_id=domain_id))
        self.events.append(event)
        return event

    def _revoke_by_grant(self, role_id, user_id=None,
                         domain_id=None, project_id=None):
        event = self.tree.add_event(
            model.RevokeEvent(user_id=user_id,
                              role_id=role_id,
                              domain_id=domain_id,
                              project_id=project_id))
        self.events.append(event)
        return event

    def _revoke_by_user_and_project(self, user_id, project_id):
        event = self.tree.add_event(
            model.RevokeEvent(project_id=project_id,
                              user_id=user_id))
        self.events.append(event)
        return event

    def _revoke_by_project_role_assignment(self, project_id, role_id):
        event = self.tree.add_event(
            model.RevokeEvent(project_id=project_id,
                              role_id=role_id))
        self.events.append(event)
        return event

    def _revoke_by_domain_role_assignment(self, domain_id, role_id):
        event = self.tree.add_event(
            model.RevokeEvent(domain_id=domain_id,
                              role_id=role_id))
        self.events.append(event)
        return event

    def _revoke_by_domain(self, domain_id):
        event = self.tree.add_event(model.RevokeEvent(domain_id=domain_id))
        self.events.append(event)

    def _user_field_test(self, field_name):
        user_id = _new_id()
        event = self._revoke_by_user(user_id)
        self.events.append(event)
        token_data_u1 = _sample_blank_token()
        token_data_u1[field_name] = user_id
        self._assertTokenRevoked(token_data_u1)
        token_data_u2 = _sample_blank_token()
        token_data_u2[field_name] = _new_id()
        self._assertTokenNotRevoked(token_data_u2)
        self.tree.remove_event(event)
        self.events.remove(event)
        self._assertTokenNotRevoked(token_data_u1)

    def test_revoke_by_user(self):
        self._user_field_test('user_id')

    def test_revoke_by_user_matches_trustee(self):
        self._user_field_test('trustee_id')

    def test_revoke_by_user_matches_trustor(self):
        self._user_field_test('trustor_id')

    def test_by_user_expiration(self):
        future_time = _future_time()

        user_id = 1
        event = self._revoke_by_expiration(user_id, future_time)
        token_data_1 = _sample_blank_token()
        token_data_1['user_id'] = user_id
        token_data_1['expires_at'] = future_time.replace(microsecond=0)
        self._assertTokenRevoked(token_data_1)

        token_data_2 = _sample_blank_token()
        token_data_2['user_id'] = user_id
        expire_delta = datetime.timedelta(seconds=2000)
        future_time = timeutils.utcnow() + expire_delta
        token_data_2['expires_at'] = future_time
        self._assertTokenNotRevoked(token_data_2)

        self.remove_event(event)
        self._assertTokenNotRevoked(token_data_1)

    def test_revoke_by_audit_id(self):
        audit_id = provider.audit_info(parent_audit_id=None)[0]
        token_data_1 = _sample_blank_token()
        # Audit ID and Audit Chain ID are populated with the same value
        # if the token is an original token
        token_data_1['audit_id'] = audit_id
        token_data_1['audit_chain_id'] = audit_id
        event = self._revoke_by_audit_id(audit_id)
        self._assertTokenRevoked(token_data_1)

        audit_id_2 = provider.audit_info(parent_audit_id=audit_id)[0]
        token_data_2 = _sample_blank_token()
        token_data_2['audit_id'] = audit_id_2
        token_data_2['audit_chain_id'] = audit_id
        self._assertTokenNotRevoked(token_data_2)

        self.remove_event(event)
        self._assertTokenNotRevoked(token_data_1)

    def test_revoke_by_audit_chain_id(self):
        audit_id = provider.audit_info(parent_audit_id=None)[0]
        token_data_1 = _sample_blank_token()
        # Audit ID and Audit Chain ID are populated with the same value
        # if the token is an original token
        token_data_1['audit_id'] = audit_id
        token_data_1['audit_chain_id'] = audit_id
        event = self._revoke_by_audit_chain_id(audit_id)
        self._assertTokenRevoked(token_data_1)

        audit_id_2 = provider.audit_info(parent_audit_id=audit_id)[0]
        token_data_2 = _sample_blank_token()
        token_data_2['audit_id'] = audit_id_2
        token_data_2['audit_chain_id'] = audit_id
        self._assertTokenRevoked(token_data_2)

        self.remove_event(event)
        self._assertTokenNotRevoked(token_data_1)
        self._assertTokenNotRevoked(token_data_2)

    def test_by_user_project(self):
        # When a user has a project-scoped token and the project-scoped token
        # is revoked then the token is revoked.

        user_id = _new_id()
        project_id = _new_id()

        future_time = _future_time()

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['project_id'] = project_id
        token_data['expires_at'] = future_time.replace(microsecond=0)

        self._revoke_by_expiration(user_id, future_time, project_id=project_id)
        self._assertTokenRevoked(token_data)

    def test_by_user_domain(self):
        # When a user has a domain-scoped token and the domain-scoped token
        # is revoked then the token is revoked.

        user_id = _new_id()
        domain_id = _new_id()

        future_time = _future_time()

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['assignment_domain_id'] = domain_id
        token_data['expires_at'] = future_time.replace(microsecond=0)

        self._revoke_by_expiration(user_id, future_time, domain_id=domain_id)
        self._assertTokenRevoked(token_data)

    def remove_event(self, event):
        self.events.remove(event)
        self.tree.remove_event(event)

    def test_by_project_grant(self):
        token_to_revoke = self.token_to_revoke
        tokens = self.project_tokens

        self._assertTokenNotRevoked(token_to_revoke)
        for token in tokens:
            self._assertTokenNotRevoked(token)

        event = self._revoke_by_grant(role_id=self.role_ids[0],
                                      user_id=self.user_ids[0],
                                      project_id=self.project_ids[0])

        self._assertTokenRevoked(token_to_revoke)
        for token in tokens:
            self._assertTokenNotRevoked(token)

        self.remove_event(event)

        self._assertTokenNotRevoked(token_to_revoke)
        for token in tokens:
            self._assertTokenNotRevoked(token)

        token_to_revoke['roles'] = [self.role_ids[0],
                                    self.role_ids[1],
                                    self.role_ids[2]]

        event = self._revoke_by_grant(role_id=self.role_ids[0],
                                      user_id=self.user_ids[0],
                                      project_id=self.project_ids[0])
        self._assertTokenRevoked(token_to_revoke)
        self.remove_event(event)
        self._assertTokenNotRevoked(token_to_revoke)

        event = self._revoke_by_grant(role_id=self.role_ids[1],
                                      user_id=self.user_ids[0],
                                      project_id=self.project_ids[0])
        self._assertTokenRevoked(token_to_revoke)
        self.remove_event(event)
        self._assertTokenNotRevoked(token_to_revoke)

        self._revoke_by_grant(role_id=self.role_ids[0],
                              user_id=self.user_ids[0],
                              project_id=self.project_ids[0])
        self._revoke_by_grant(role_id=self.role_ids[1],
                              user_id=self.user_ids[0],
                              project_id=self.project_ids[0])
        self._revoke_by_grant(role_id=self.role_ids[2],
                              user_id=self.user_ids[0],
                              project_id=self.project_ids[0])
        self._assertTokenRevoked(token_to_revoke)

    def test_by_project_and_user_and_role(self):
        user_id1 = _new_id()
        user_id2 = _new_id()
        project_id = _new_id()
        self.events.append(self._revoke_by_user(user_id1))
        self.events.append(
            self._revoke_by_user_and_project(user_id2, project_id))
        token_data = _sample_blank_token()
        token_data['user_id'] = user_id2
        token_data['project_id'] = project_id
        self._assertTokenRevoked(token_data)

    def test_by_domain_user(self):
        # If revoke a domain, then a token for a user in the domain is revoked

        user_id = _new_id()
        domain_id = _new_id()

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['identity_domain_id'] = domain_id

        self._revoke_by_domain(domain_id)

        self._assertTokenRevoked(token_data)

    def test_by_domain_project(self):
        # If revoke a domain, then a token scoped to a project in the domain
        # is revoked.

        user_id = _new_id()
        user_domain_id = _new_id()

        project_id = _new_id()
        project_domain_id = _new_id()

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['identity_domain_id'] = user_domain_id
        token_data['project_id'] = project_id
        token_data['assignment_domain_id'] = project_domain_id

        self._revoke_by_domain(project_domain_id)

        self._assertTokenRevoked(token_data)

    def test_by_domain_domain(self):
        # If revoke a domain, then a token scoped to the domain is revoked.

        user_id = _new_id()
        user_domain_id = _new_id()

        domain_id = _new_id()

        token_data = _sample_blank_token()
        token_data['user_id'] = user_id
        token_data['identity_domain_id'] = user_domain_id
        token_data['assignment_domain_id'] = domain_id

        self._revoke_by_domain(domain_id)

        self._assertTokenRevoked(token_data)

    def _assertEmpty(self, collection):
        return self.assertEqual(0, len(collection), "collection not empty")

    def _assertEventsMatchIteration(self, turn):
        self.assertEqual(1, len(self.tree.revoke_map))
        self.assertEqual(turn + 1, len(self.tree.revoke_map
                                       ['trust_id=*']
                                       ['consumer_id=*']
                                       ['access_token_id=*']
                                       ['audit_id=*']
                                       ['audit_chain_id=*']))
        # two different functions add  domain_ids, +1 for None
        self.assertEqual(2 * turn + 1, len(self.tree.revoke_map
                                           ['trust_id=*']
                                           ['consumer_id=*']
                                           ['access_token_id=*']
                                           ['audit_id=*']
                                           ['audit_chain_id=*']
                                           ['expires_at=*']))
        # two different functions add  project_ids, +1 for None
        self.assertEqual(2 * turn + 1, len(self.tree.revoke_map
                                           ['trust_id=*']
                                           ['consumer_id=*']
                                           ['access_token_id=*']
                                           ['audit_id=*']
                                           ['audit_chain_id=*']
                                           ['expires_at=*']
                                           ['domain_id=*']))
        # 10 users added
        self.assertEqual(turn, len(self.tree.revoke_map
                                   ['trust_id=*']
                                   ['consumer_id=*']
                                   ['access_token_id=*']
                                   ['audit_id=*']
                                   ['audit_chain_id=*']
                                   ['expires_at=*']
                                   ['domain_id=*']
                                   ['project_id=*']))

    def test_cleanup(self):
        events = self.events
        self._assertEmpty(self.tree.revoke_map)
        expiry_base_time = _future_time()
        for i in range(0, 10):
            events.append(
                self._revoke_by_user(_new_id()))

            args = (_new_id(),
                    expiry_base_time + datetime.timedelta(seconds=i))
            events.append(
                self._revoke_by_expiration(*args))

            self.assertEqual(i + 2, len(self.tree.revoke_map
                                        ['trust_id=*']
                                        ['consumer_id=*']
                                        ['access_token_id=*']
                                        ['audit_id=*']
                                        ['audit_chain_id=*']),
                             'adding %s to %s' % (args,
                                                  self.tree.revoke_map))

            events.append(
                self._revoke_by_project_role_assignment(_new_id(), _new_id()))
            events.append(
                self._revoke_by_domain_role_assignment(_new_id(), _new_id()))
            events.append(
                self._revoke_by_domain_role_assignment(_new_id(), _new_id()))
            events.append(
                self._revoke_by_user_and_project(_new_id(), _new_id()))
            self._assertEventsMatchIteration(i + 1)

        for event in self.events:
            self.tree.remove_event(event)
        self._assertEmpty(self.tree.revoke_map)
