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
import datetime
import uuid

import freezegun
from oslo_utils import timeutils
import six
from six.moves import range

import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.token import provider


CONF = keystone.conf.CONF
NULL_OBJECT = object()


class TokenTests(object):
    def _create_token_id(self):
        return uuid.uuid4().hex

    def _assert_revoked_token_list_matches_token_persistence(
            self, revoked_token_id_list):
        # Assert that the list passed in matches the list returned by the
        # token persistence service
        persistence_list = [
            x['id']
            for x in self.token_provider_api.list_revoked_tokens()
        ]
        self.assertEqual(persistence_list, revoked_token_id_list)

    def test_token_crud(self):
        token_id = self._create_token_id()
        data = {'id': token_id, 'a': 'b',
                'trust_id': None,
                'user': {'id': 'testuserid'},
                'token_data': {'access': {'token': {
                    'audit_ids': [uuid.uuid4().hex]}}}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        expires = data_ref.pop('expires')
        data_ref.pop('user_id')
        self.assertIsInstance(expires, datetime.datetime)
        data_ref.pop('id')
        data.pop('id')
        self.assertDictEqual(data, data_ref)

        new_data_ref = self.token_provider_api._persistence.get_token(token_id)
        expires = new_data_ref.pop('expires')
        self.assertIsInstance(expires, datetime.datetime)
        new_data_ref.pop('user_id')
        new_data_ref.pop('id')

        self.assertEqual(data, new_data_ref)

        self.token_provider_api._persistence.delete_token(token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.get_token, token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.delete_token, token_id)

    def create_token_sample_data(self, token_id=None, tenant_id=None,
                                 trust_id=None, user_id=None, expires=None):
        if token_id is None:
            token_id = self._create_token_id()
        if user_id is None:
            user_id = 'testuserid'
        # FIXME(morganfainberg): These tokens look nothing like "Real" tokens.
        # This should be fixed when token issuance is cleaned up.
        data = {'id': token_id, 'a': 'b',
                'user': {'id': user_id},
                'access': {'token': {'audit_ids': [uuid.uuid4().hex]}}}
        if tenant_id is not None:
            data['tenant'] = {'id': tenant_id, 'name': tenant_id}
        if tenant_id is NULL_OBJECT:
            data['tenant'] = None
        if expires is not None:
            data['expires'] = expires
        if trust_id is not None:
            data['trust_id'] = trust_id
            data['access'].setdefault('trust', {})
            # Testuserid2 is used here since a trustee will be different in
            # the cases of impersonation and therefore should not match the
            # token's user_id.
            data['access']['trust']['trustee_user_id'] = 'testuserid2'
        data['token_version'] = provider.V2
        # Issue token stores a copy of all token data at token['token_data'].
        # This emulates that assumption as part of the test.
        data['token_data'] = copy.deepcopy(data)
        new_token = self.token_provider_api._persistence.create_token(token_id,
                                                                      data)
        return new_token['id'], data

    def test_delete_tokens(self):
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data(
            tenant_id='testtenantid')
        token_id2, data = self.create_token_sample_data(
            tenant_id='testtenantid')
        token_id3, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            user_id='testuserid1')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(2, len(tokens))
        self.assertIn(token_id2, tokens)
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_tokens(
            user_id='testuserid',
            tenant_id='testtenantid')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(0, len(tokens))
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id1)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id2)

        self.token_provider_api._persistence.get_token(token_id3)

    def test_delete_tokens_trust(self):
        tokens = self.token_provider_api._persistence._list_tokens(
            user_id='testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            trust_id='testtrustid')
        token_id2, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            user_id='testuserid1',
            trust_id='testtrustid1')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_tokens(
            user_id='testuserid',
            tenant_id='testtenantid',
            trust_id='testtrustid')
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id1)
        self.token_provider_api._persistence.get_token(token_id2)

    def _test_token_list(self, token_list_fn):
        tokens = token_list_fn('testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data()
        tokens = token_list_fn('testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id1, tokens)
        token_id2, data = self.create_token_sample_data()
        tokens = token_list_fn('testuserid')
        self.assertEqual(2, len(tokens))
        self.assertIn(token_id2, tokens)
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_token(token_id1)
        tokens = token_list_fn('testuserid')
        self.assertIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_token(token_id2)
        tokens = token_list_fn('testuserid')
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)

        # tenant-specific tokens
        tenant1 = uuid.uuid4().hex
        tenant2 = uuid.uuid4().hex
        token_id3, data = self.create_token_sample_data(tenant_id=tenant1)
        token_id4, data = self.create_token_sample_data(tenant_id=tenant2)
        # test for existing but empty tenant (LP:1078497)
        token_id5, data = self.create_token_sample_data(tenant_id=NULL_OBJECT)
        tokens = token_list_fn('testuserid')
        self.assertEqual(3, len(tokens))
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)
        self.assertIn(token_id5, tokens)
        tokens = token_list_fn('testuserid', tenant2)
        self.assertEqual(1, len(tokens))
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)

    def test_token_list(self):
        self._test_token_list(
            self.token_provider_api._persistence._list_tokens)

    def test_token_list_trust(self):
        trust_id = uuid.uuid4().hex
        token_id5, data = self.create_token_sample_data(trust_id=trust_id)
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid', trust_id=trust_id)
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id5, tokens)

    def test_get_token_returns_not_found(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          uuid.uuid4().hex)

    def test_delete_token_returns_not_found(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.delete_token,
                          uuid.uuid4().hex)

    def test_null_expires_token(self):
        token_id = uuid.uuid4().hex
        data = {'id': token_id, 'id_hash': token_id, 'a': 'b', 'expires': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        self.assertIsNotNone(data_ref['expires'])
        new_data_ref = self.token_provider_api._persistence.get_token(token_id)

        # MySQL doesn't store microseconds, so discard them before testing
        data_ref['expires'] = data_ref['expires'].replace(microsecond=0)
        new_data_ref['expires'] = new_data_ref['expires'].replace(
            microsecond=0)

        self.assertEqual(data_ref, new_data_ref)

    def check_list_revoked_tokens(self, token_infos):
        revocation_list = self.token_provider_api.list_revoked_tokens()
        revoked_ids = [x['id'] for x in revocation_list]
        revoked_audit_ids = [x['audit_id'] for x in revocation_list]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        for token_id, audit_id in token_infos:
            self.assertIn(token_id, revoked_ids)
            self.assertIn(audit_id, revoked_audit_ids)

    def delete_token(self):
        token_id = uuid.uuid4().hex
        audit_id = uuid.uuid4().hex
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'user': {'id': 'testuserid'},
                'token_data': {'token': {'audit_ids': [audit_id]}}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        self.token_provider_api._persistence.delete_token(token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.get_token,
            data_ref['id'])
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.delete_token,
            data_ref['id'])
        return (token_id, audit_id)

    def test_list_revoked_tokens_returns_empty_list(self):
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertEqual([], revoked_ids)

    def test_list_revoked_tokens_for_single_token(self):
        self.check_list_revoked_tokens([self.delete_token()])

    def test_list_revoked_tokens_for_multiple_tokens(self):
        self.check_list_revoked_tokens([self.delete_token()
                                        for x in range(2)])

    def test_flush_expired_token(self):
        token_id = uuid.uuid4().hex
        window = self.config_fixture.conf.token.allow_expired_window + 5
        expire_time = timeutils.utcnow() - datetime.timedelta(minutes=window)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data, data_ref)

        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() + datetime.timedelta(minutes=window)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data, data_ref)

        self.token_provider_api._persistence.flush_expired_tokens()
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id, tokens)

    @unit.skip_if_cache_disabled('token')
    def test_revocation_list_cache(self):
        expire_time = timeutils.utcnow() + datetime.timedelta(minutes=10)
        token_id = uuid.uuid4().hex
        token_data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                      'expires': expire_time,
                      'trust_id': None,
                      'user': {'id': 'testuserid'},
                      'token_data': {'token': {
                          'audit_ids': [uuid.uuid4().hex]}}}
        token2_id = uuid.uuid4().hex
        token2_data = {'id_hash': token2_id, 'id': token2_id, 'a': 'b',
                       'expires': expire_time,
                       'trust_id': None,
                       'user': {'id': 'testuserid'},
                       'token_data': {'token': {
                           'audit_ids': [uuid.uuid4().hex]}}}
        # Create 2 Tokens.
        self.token_provider_api._persistence.create_token(token_id,
                                                          token_data)
        self.token_provider_api._persistence.create_token(token2_id,
                                                          token2_data)
        # Verify the revocation list is empty.
        self.assertEqual(
            [], self.token_provider_api._persistence.list_revoked_tokens())
        self.assertEqual([], self.token_provider_api.list_revoked_tokens())
        # Delete a token directly, bypassing the manager.
        self.token_provider_api._persistence.driver.delete_token(token_id)
        # Verify the revocation list is still empty.
        self.assertEqual(
            [], self.token_provider_api._persistence.list_revoked_tokens())
        self.assertEqual([], self.token_provider_api.list_revoked_tokens())
        # Invalidate the revocation list.
        self.token_provider_api._persistence.invalidate_revocation_list()
        # Verify the deleted token is in the revocation list.
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id, revoked_ids)
        # Delete the second token, through the manager
        self.token_provider_api._persistence.delete_token(token2_id)
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        # Verify both tokens are in the revocation list.
        self.assertIn(token_id, revoked_ids)
        self.assertIn(token2_id, revoked_ids)

    def test_predictable_revoked_uuid_token_id(self):
        token_id = uuid.uuid4().hex
        token = {'user': {'id': uuid.uuid4().hex},
                 'token_data': {'token': {'audit_ids': [uuid.uuid4().hex]}}}

        self.token_provider_api._persistence.create_token(token_id, token)
        self.token_provider_api._persistence.delete_token(token_id)

        revoked_tokens = self.token_provider_api.list_revoked_tokens()
        revoked_ids = [x['id'] for x in revoked_tokens]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id, revoked_ids)
        for t in revoked_tokens:
            self.assertIn('expires', t)

    def test_create_unicode_token_id(self):
        token_id = six.text_type(self._create_token_id())
        self.create_token_sample_data(token_id=token_id)
        self.token_provider_api._persistence.get_token(token_id)

    def test_create_unicode_user_id(self):
        user_id = six.text_type(uuid.uuid4().hex)
        token_id, data = self.create_token_sample_data(user_id=user_id)
        self.token_provider_api._persistence.get_token(token_id)


class TokenCacheInvalidation(object):
    def _create_test_data(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            # Create an equivalent of a scoped token
            token_id, data = self.token_provider_api.issue_token(
                self.user_foo['id'],
                ['password'],
                project_id=self.tenant_bar['id']
            )
            self.scoped_token_id = token_id

            # ..and an un-scoped one
            token_id, data = self.token_provider_api.issue_token(
                self.user_foo['id'],
                ['password']
            )
            self.unscoped_token_id = token_id
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

            # Validate them, in the various ways possible - this will load the
            # responses into the token cache.
            self.token_provider_api.validate_token(self.scoped_token_id)
            self.token_provider_api.validate_token(self.unscoped_token_id)

    def test_delete_unscoped_token(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            self.token_provider_api._persistence.delete_token(
                self.unscoped_token_id)
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

            # Ensure the unscoped token is invalid
            self.assertRaises(
                exception.TokenNotFound,
                self.token_provider_api.validate_token,
                self.unscoped_token_id)
            # Ensure the scoped token is still valid
            self.token_provider_api.validate_token(self.scoped_token_id)

    def test_delete_scoped_token_by_id(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            self.token_provider_api._persistence.delete_token(
                self.scoped_token_id
            )
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

            # Ensure the project token is invalid
            self.assertRaises(
                exception.TokenNotFound,
                self.token_provider_api.validate_token,
                self.scoped_token_id)
            # Ensure the unscoped token is still valid
            self.token_provider_api.validate_token(self.unscoped_token_id)

    def test_delete_scoped_token_by_user(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            self.token_provider_api._persistence.delete_tokens(
                self.user_foo['id']
            )
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

            # Since we are deleting all tokens for this user, they should all
            # now be invalid.
            self.assertRaises(
                exception.TokenNotFound,
                self.token_provider_api.validate_token,
                self.scoped_token_id)
            self.assertRaises(
                exception.TokenNotFound,
                self.token_provider_api.validate_token,
                self.unscoped_token_id)

    def test_delete_scoped_token_by_user_and_tenant(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            self.token_provider_api._persistence.delete_tokens(
                self.user_foo['id'],
                tenant_id=self.tenant_bar['id'])
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

            # Ensure the scoped token is invalid
            self.assertRaises(
                exception.TokenNotFound,
                self.token_provider_api.validate_token,
                self.scoped_token_id)
            # Ensure the unscoped token is still valid
            self.token_provider_api.validate_token(self.unscoped_token_id)
