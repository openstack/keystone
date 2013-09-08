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

from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import tests

CONF = config.CONF

KERBEROS_BIND = 'USER@REALM'

# the only thing the function checks for is the presence of bind
TOKEN_BIND_KERB = {'bind': {'kerberos': KERBEROS_BIND}}
TOKEN_BIND_UNKNOWN = {'bind': {'FOO': 'BAR'}}
TOKEN_BIND_NONE = {}

ANY = 'any'
ALL_TOKENS = [TOKEN_BIND_KERB, TOKEN_BIND_UNKNOWN, TOKEN_BIND_NONE]


class BindTest(tests.TestCase):
    """Test binding tokens to a Principal.

    Even though everything in this file references kerberos the same concepts
    will apply to all future binding mechanisms.
    """

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
            context = {}
            CONF.token.enforce_token_bind = bind_level

            if use_kerberos:
                context['REMOTE_USER'] = KERBEROS_BIND
                context['AUTH_TYPE'] = 'Negotiate'

            if not success:
                self.assertRaises(exception.Unauthorized,
                                  wsgi.validate_token_bind,
                                  context, tokens)
            else:
                wsgi.validate_token_bind(context, tokens)

    # DISABLED

    def test_bind_disabled_with_kerb_user(self):
        self.assert_kerberos_bind(ALL_TOKENS,
                                  bind_level='disabled',
                                  use_kerberos=ANY,
                                  success=True)

    # PERMISSIVE

    def test_bind_permissive_with_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='permissive',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_permissive_with_regular_token(self):
        self.assert_kerberos_bind(TOKEN_BIND_NONE,
                                  bind_level='permissive',
                                  use_kerberos=ANY,
                                  success=True)

    def test_bind_permissive_without_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='permissive',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_permissive_with_unknown_bind(self):
        self.assert_kerberos_bind(TOKEN_BIND_UNKNOWN,
                                  bind_level='permissive',
                                  use_kerberos=ANY,
                                  success=True)

    # STRICT

    def test_bind_strict_with_regular_token(self):
        self.assert_kerberos_bind(TOKEN_BIND_NONE,
                                  bind_level='strict',
                                  use_kerberos=ANY,
                                  success=True)

    def test_bind_strict_with_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='strict',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_strict_without_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='strict',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_strict_with_unknown_bind(self):
        self.assert_kerberos_bind(TOKEN_BIND_UNKNOWN,
                                  bind_level='strict',
                                  use_kerberos=ANY,
                                  success=False)

    # REQUIRED

    def test_bind_required_with_regular_token(self):
        self.assert_kerberos_bind(TOKEN_BIND_NONE,
                                  bind_level='required',
                                  use_kerberos=ANY,
                                  success=False)

    def test_bind_required_with_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='required',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_required_without_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='required',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_required_with_unknown_bind(self):
        self.assert_kerberos_bind(TOKEN_BIND_UNKNOWN,
                                  bind_level='required',
                                  use_kerberos=ANY,
                                  success=False)

    # NAMED

    def test_bind_named_with_regular_token(self):
        self.assert_kerberos_bind(TOKEN_BIND_NONE,
                                  bind_level='kerberos',
                                  use_kerberos=ANY,
                                  success=False)

    def test_bind_named_with_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='kerberos',
                                  use_kerberos=True,
                                  success=True)

    def test_bind_named_without_kerb_user(self):
        self.assert_kerberos_bind(TOKEN_BIND_KERB,
                                  bind_level='kerberos',
                                  use_kerberos=False,
                                  success=False)

    def test_bind_named_with_unknown_bind(self):
        self.assert_kerberos_bind(TOKEN_BIND_UNKNOWN,
                                  bind_level='kerberos',
                                  use_kerberos=ANY,
                                  success=False)

    def test_bind_named_with_unknown_scheme(self):
        self.assert_kerberos_bind(ALL_TOKENS,
                                  bind_level='unknown',
                                  use_kerberos=ANY,
                                  success=False)
