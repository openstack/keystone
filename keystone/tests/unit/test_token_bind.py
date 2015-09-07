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

import copy
import uuid

from keystone.common import wsgi
from keystone import exception
from keystone.models import token_model
from keystone.tests import unit
from keystone.tests.unit import test_token_provider


KERBEROS_BIND = 'USER@REALM'
ANY = 'any'


class BindTest(unit.TestCase):
    """Test binding tokens to a Principal.

    Even though everything in this file references kerberos the same concepts
    will apply to all future binding mechanisms.
    """

    def setUp(self):
        super(BindTest, self).setUp()
        self.TOKEN_BIND_KERB = copy.deepcopy(
            test_token_provider.SAMPLE_V3_TOKEN)
        self.TOKEN_BIND_KERB['token']['bind'] = {'kerberos': KERBEROS_BIND}
        self.TOKEN_BIND_UNKNOWN = copy.deepcopy(
            test_token_provider.SAMPLE_V3_TOKEN)
        self.TOKEN_BIND_UNKNOWN['token']['bind'] = {'FOO': 'BAR'}
        self.TOKEN_BIND_NONE = copy.deepcopy(
            test_token_provider.SAMPLE_V3_TOKEN)

        self.ALL_TOKENS = [self.TOKEN_BIND_KERB, self.TOKEN_BIND_UNKNOWN,
                           self.TOKEN_BIND_NONE]

    def assert_kerberos_bind(self, tokens, bind_level,
                             use_kerberos=True, success=True):
        if not isinstance(tokens, dict):
            for token in tokens:
                self.assert_kerberos_bind(token, bind_level,
                                          use_kerberos=use_kerberos,
                                          success=success)
        elif use_kerberos == ANY:
            for val in (True, False):
                self.assert_kerberos_bind(tokens, bind_level,
                                          use_kerberos=val, success=success)
        else:
            context = {'environment': {}}
            self.config_fixture.config(group='token',
                                       enforce_token_bind=bind_level)

            if use_kerberos:
                context['environment']['REMOTE_USER'] = KERBEROS_BIND
                context['environment']['AUTH_TYPE'] = 'Negotiate'

            # NOTE(morganfainberg): This assumes a V3 token.
            token_ref = token_model.KeystoneToken(
                token_id=uuid.uuid4().hex,
                token_data=tokens)

            if not success:
                self.assertRaises(exception.Unauthorized,
                                  wsgi.validate_token_bind,
                                  context, token_ref)
            else:
                wsgi.validate_token_bind(context, token_ref)

    # DISABLED

    def test_bind_disabled_with_kerb_user(self):
        self.assert_kerberos_bind(self.ALL_TOKENS,
                                  bind_level='disabled',
                                  use_kerberos=ANY,
                                  success=True)

    # PERMISSIVE

    def test_bind_permissive_with_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='permissive',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_permissive_with_regular_token(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_NONE,
                                  bind_level='permissive',
                                  use_kerberos=ANY,
                                  success=True)

    def test_bind_permissive_without_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='permissive',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_permissive_with_unknown_bind(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_UNKNOWN,
                                  bind_level='permissive',
                                  use_kerberos=ANY,
                                  success=True)

    # STRICT

    def test_bind_strict_with_regular_token(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_NONE,
                                  bind_level='strict',
                                  use_kerberos=ANY,
                                  success=True)

    def test_bind_strict_with_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='strict',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_strict_without_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='strict',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_strict_with_unknown_bind(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_UNKNOWN,
                                  bind_level='strict',
                                  use_kerberos=ANY,
                                  success=False)

    # REQUIRED

    def test_bind_required_with_regular_token(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_NONE,
                                  bind_level='required',
                                  use_kerberos=ANY,
                                  success=False)

    def test_bind_required_with_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='required',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_required_without_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='required',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_required_with_unknown_bind(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_UNKNOWN,
                                  bind_level='required',
                                  use_kerberos=ANY,
                                  success=False)

    # NAMED

    def test_bind_named_with_regular_token(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_NONE,
                                  bind_level='kerberos',
                                  use_kerberos=ANY,
                                  success=False)

    def test_bind_named_with_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='kerberos',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_named_without_kerb_user(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_KERB,
                                  bind_level='kerberos',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_named_with_unknown_bind(self):
        self.assert_kerberos_bind(self.TOKEN_BIND_UNKNOWN,
                                  bind_level='kerberos',
                                  use_kerberos=ANY,
                                  success=False)

    def test_bind_named_with_unknown_scheme(self):
        self.assert_kerberos_bind(self.ALL_TOKENS,
                                  bind_level='unknown',
                                  use_kerberos=ANY,
                                  success=False)
