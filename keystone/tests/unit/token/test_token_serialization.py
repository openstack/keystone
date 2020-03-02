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

from keystone.common.cache import _context_cache
from keystone.common import utils as ks_utils
from keystone import exception
from keystone.models import token_model
from keystone.tests.unit import base_classes


class TestTokenSerialization(base_classes.TestCaseWithBootstrap):

    def setUp(self):
        super(TestTokenSerialization, self).setUp()
        self.admin_user_id = self.bootstrapper.admin_user_id
        self.admin_username = self.bootstrapper.admin_username
        self.admin_password = self.bootstrapper.admin_password
        self.project_id = self.bootstrapper.project_id
        self.project_name = self.bootstrapper.project_name
        self.admin_role_id = self.bootstrapper.admin_role_id
        self.member_role_id = self.bootstrapper.member_role_id
        self.reader_role_id = self.bootstrapper.reader_role_id

        self.token_id = uuid.uuid4().hex
        issued_at = datetime.datetime.utcnow()
        self.issued_at = ks_utils.isotime(at=issued_at, subsecond=True)

        # Reach into the cache registry and pull out an instance of the
        # _TokenModelHandler so that we can interact and test it directly (as
        # opposed to using PROVIDERS or managers to invoke it).
        token_handler_id = token_model._TokenModelHandler.identity
        self.token_handler = _context_cache._registry.get(token_handler_id)

        self.exp_token = token_model.TokenModel()
        self.exp_token.user_id = self.admin_user_id
        self.exp_token.project_id = self.project_id
        self.exp_token.mint(self.token_id, self.issued_at)

    def test_serialize_and_deserialize_token_model(self):
        serialized = self.token_handler.serialize(self.exp_token)
        token = self.token_handler.deserialize(serialized)

        self.assertEqual(self.exp_token.user_id, token.user_id)
        self.assertEqual(self.exp_token.project_id, token.project_id)
        self.assertEqual(self.exp_token.id, token.id)
        self.assertEqual(self.exp_token.issued_at, token.issued_at)

    @mock.patch.object(
        token_model.TokenModel, '__init__', side_effect=Exception)
    def test_error_handling_in_deserialize(self, handler_mock):
        serialized = self.token_handler.serialize(self.exp_token)
        self.assertRaises(
            exception.CacheDeserializationError,
            self.token_handler.deserialize,
            serialized
        )
