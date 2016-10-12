# Copyright 2012 OpenStack Foundation
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
import datetime
import uuid

from oslo_utils import timeutils
import six

from keystone.common import utils
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.token import test_backends as token_tests


class KvsToken(unit.TestCase, token_tests.TokenTests):
    def setUp(self):
        super(KvsToken, self).setUp()
        self.load_backends()

    def config_overrides(self):
        super(KvsToken, self).config_overrides()
        self.config_fixture.config(group='token', driver='kvs')

    def test_flush_expired_token(self):
        self.assertRaises(
            exception.NotImplemented,
            self.token_provider_api._persistence.flush_expired_tokens)

    def _update_user_token_index_direct(self, user_key, token_id, new_data):
        persistence = self.token_provider_api._persistence
        token_list = persistence.driver._get_user_token_list_with_expiry(
            user_key)
        # Update the user-index so that the expires time is _actually_ expired
        # since we do not do an explicit get on the token, we only reference
        # the data in the user index (to save extra round-trips to the kvs
        # backend).
        for i, data in enumerate(token_list):
            if data[0] == token_id:
                token_list[i] = new_data
                break
        self.token_provider_api._persistence.driver._store.set(user_key,
                                                               token_list)

    def test_cleanup_user_index_on_create(self):
        user_id = six.text_type(uuid.uuid4().hex)
        valid_token_id, data = self.create_token_sample_data(user_id=user_id)
        expired_token_id, expired_data = self.create_token_sample_data(
            user_id=user_id)

        expire_delta = datetime.timedelta(seconds=86400)

        # NOTE(morganfainberg): Directly access the data cache since we need to
        # get expired tokens as well as valid tokens.
        token_persistence = self.token_provider_api._persistence
        user_key = token_persistence.driver._prefix_user_id(user_id)
        user_token_list = token_persistence.driver._store.get(user_key)
        valid_token_ref = token_persistence.get_token(valid_token_id)
        expired_token_ref = token_persistence.get_token(expired_token_id)
        expected_user_token_list = [
            (valid_token_id, utils.isotime(valid_token_ref['expires'],
                                           subsecond=True)),
            (expired_token_id, utils.isotime(expired_token_ref['expires'],
                                             subsecond=True))]
        self.assertEqual(expected_user_token_list, user_token_list)
        new_expired_data = (expired_token_id,
                            utils.isotime(
                                (timeutils.utcnow() - expire_delta),
                                subsecond=True))
        self._update_user_token_index_direct(user_key, expired_token_id,
                                             new_expired_data)
        valid_token_id_2, valid_data_2 = self.create_token_sample_data(
            user_id=user_id)
        valid_token_ref_2 = token_persistence.get_token(valid_token_id_2)
        expected_user_token_list = [
            (valid_token_id, utils.isotime(valid_token_ref['expires'],
                                           subsecond=True)),
            (valid_token_id_2, utils.isotime(valid_token_ref_2['expires'],
                                             subsecond=True))]
        user_token_list = token_persistence.driver._store.get(user_key)
        self.assertEqual(expected_user_token_list, user_token_list)

        # Test that revoked tokens are removed from the list on create.
        token_persistence.delete_token(valid_token_id_2)
        new_token_id, data = self.create_token_sample_data(user_id=user_id)
        new_token_ref = token_persistence.get_token(new_token_id)
        expected_user_token_list = [
            (valid_token_id, utils.isotime(valid_token_ref['expires'],
                                           subsecond=True)),
            (new_token_id, utils.isotime(new_token_ref['expires'],
                                         subsecond=True))]
        user_token_list = token_persistence.driver._store.get(user_key)
        self.assertEqual(expected_user_token_list, user_token_list)


class KvsTokenCacheInvalidation(unit.TestCase,
                                token_tests.TokenCacheInvalidation):
    def setUp(self):
        super(KvsTokenCacheInvalidation, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

        # populate the engine with tables & fixtures
        self.load_fixtures(default_fixtures)
        # defaulted by the data load
        self.user_foo['enabled'] = True
        self._create_test_data()

    def config_overrides(self):
        super(KvsTokenCacheInvalidation, self).config_overrides()
        self.config_fixture.config(group='token', driver='kvs')
        self.config_fixture.config(group='token', provider='uuid')
