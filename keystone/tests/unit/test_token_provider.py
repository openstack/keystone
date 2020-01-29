# Copyright 2013 OpenStack Foundation
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

from oslo_utils import timeutils
import urllib

from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.models import token_model
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone import token
from keystone.token import provider


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

FUTURE_DELTA = datetime.timedelta(seconds=CONF.token.expiration)
CURRENT_DATE = timeutils.utcnow()


class TestTokenProvider(unit.TestCase):
    def setUp(self):
        super(TestTokenProvider, self).setUp()
        self.useFixture(database.Database())
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )
        self.load_backends()

    def test_strings_are_url_safe(self):
        s = provider.random_urlsafe_str()
        self.assertEqual(s, urllib.parse.quote_plus(s))

    def test_unsupported_token_provider(self):
        self.config_fixture.config(group='token',
                                   provider='MyProvider')
        self.assertRaises(ImportError,
                          token.provider.Manager)

    def test_provider_token_expiration_validation(self):
        token = token_model.TokenModel()
        token.issued_at = "2013-05-21T00:02:43.941473Z"
        token.expires_at = utils.isotime(CURRENT_DATE)

        self.assertRaises(exception.TokenNotFound,
                          PROVIDERS.token_provider_api._is_valid_token,
                          token)

        token = token_model.TokenModel()
        token.issued_at = "2013-05-21T00:02:43.941473Z"
        token.expires_at = utils.isotime(timeutils.utcnow() + FUTURE_DELTA)
        self.assertIsNone(PROVIDERS.token_provider_api._is_valid_token(token))

    def test_validate_v3_token_with_no_token_raises_token_not_found(self):
        self.assertRaises(
            exception.TokenNotFound,
            PROVIDERS.token_provider_api.validate_token,
            None)
