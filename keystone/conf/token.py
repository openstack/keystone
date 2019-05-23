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

import sys

from oslo_config import cfg
from oslo_log import versionutils

from keystone.conf import utils

expiration = cfg.IntOpt(
    'expiration',
    default=3600,
    min=0,
    max=sys.maxsize,
    help=utils.fmt("""
The amount of time that a token should remain valid (in seconds). Drastically
reducing this value may break "long-running" operations that involve multiple
services to coordinate together, and will force users to authenticate with
keystone more frequently. Drastically increasing this value will increase the
number of tokens that will be simultaneously valid. Keystone tokens are also
bearer tokens, so a shorter duration will also reduce the potential security
impact of a compromised token.
"""))

provider = cfg.StrOpt(
    'provider',
    default='fernet',
    help=utils.fmt("""
Entry point for the token provider in the `keystone.token.provider` namespace.
The token provider controls the token construction, validation, and revocation
operations. Supported upstream providers are `fernet` and `jws`. Neither
`fernet` or `jws` tokens require persistence and both require additional setup.
If using `fernet`, you're required to run `keystone-manage fernet_setup`, which
creates symmetric keys used to encrypt tokens. If using `jws`, you're required
to generate an ECDSA keypair using a SHA-256 hash algorithm for signing and
validating token, which can be done with `keystone-manage create_jws_keypair`.
Note that `fernet` tokens are encrypted and `jws` tokens are only signed.
Please be sure to consider this if your deployment has security requirements
regarding payload contents used to generate token IDs.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for caching token creation and validation data. This has no effect
unless global caching is enabled.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    min=0,
    max=sys.maxsize,
    help=utils.fmt("""
The number of seconds to cache token creation and validation data. This has no
effect unless both global and `[token] caching` are enabled.
"""))

revoke_by_id = cfg.BoolOpt(
    'revoke_by_id',
    default=True,
    help=utils.fmt("""
This toggles support for revoking individual tokens by the token identifier and
thus various token enumeration operations (such as listing all tokens issued to
a specific user). These operations are used to determine the list of tokens to
consider revoked. Do not disable this option if you're using the `kvs`
`[revoke] driver`.
"""))

allow_rescope_scoped_token = cfg.BoolOpt(
    'allow_rescope_scoped_token',
    default=True,
    help=utils.fmt("""
This toggles whether scoped tokens may be re-scoped to a new project or
domain, thereby preventing users from exchanging a scoped token (including
those with a default project scope) for any other token. This forces users to
either authenticate for unscoped tokens (and later exchange that unscoped token
for tokens with a more specific scope) or to provide their credentials in every
request for a scoped token to avoid re-scoping altogether.
"""))

cache_on_issue = cfg.BoolOpt(
    'cache_on_issue',
    default=True,
    deprecated_since=versionutils.deprecated.STEIN,
    deprecated_reason=utils.fmt("""
Keystone already exposes a configuration option for caching tokens. Having a
separate configuration option to cache tokens when they are issued is
redundant, unnecessarily complicated, and is misleading if token caching is
disabled because tokens will still be pre-cached by default when they are
issued. The ability to pre-cache tokens when they are issued is going to rely
exclusively on the ``keystone.conf [token] caching`` option in the future.
"""),
    deprecated_for_removal=True,
    help=utils.fmt("""
Enable storing issued token data to token validation cache so that first token
validation doesn't actually cause full validation cycle. This option has no
effect unless global caching is enabled and will still cache tokens even if
`[token] caching = False`.
"""))

allow_expired_window = cfg.IntOpt(
    'allow_expired_window',
    default=48 * 60 * 60,
    help=utils.fmt("""
This controls the number of seconds that a token can be retrieved for beyond
the built-in expiry time. This allows long running operations to succeed.
Defaults to two days.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    expiration,
    provider,
    caching,
    cache_time,
    revoke_by_id,
    allow_rescope_scoped_token,
    cache_on_issue,
    allow_expired_window,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
