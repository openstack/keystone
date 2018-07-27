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

bind = cfg.ListOpt(
    'bind',
    default=[],
    deprecated_since=versionutils.deprecated.PIKE,
    deprecated_for_removal=True,
    help=utils.fmt("""
This is a list of external authentication mechanisms which should add token
binding metadata to tokens, such as `kerberos` or `x509`. Note that this option
is deprecated as keystone no longer supports binding metadata to tokens
directly. This option is silently ignored and will be removed in the future.
This option no longer has any impact on the behavior of tokens and can be
removed.
"""))

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
operations. Keystone includes `fernet` token provider.
`fernet` tokens do not need to be persisted at all, but require that you run
`keystone-manage fernet_setup` (also see the `keystone-manage fernet_rotate`
command).
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

infer_roles = cfg.BoolOpt(
    'infer_roles',
    default=True,
    deprecated_since=versionutils.deprecated.ROCKY,
    deprecated_reason=utils.fmt("""
Default roles depend on a chain of implied role assignments. Ex: an admin user
will also have the reader and member role. By ensuring that all these roles
will always appear on the token validation response, we can improve the
simplicity and readability of policy files.
"""),
    deprecated_for_removal=True,
    help=utils.fmt("""
This controls whether roles should be included with tokens that are not
directly assigned to the token's scope, but are instead linked implicitly to
other role assignments.
"""))

cache_on_issue = cfg.BoolOpt(
    'cache_on_issue',
    default=True,
    help=utils.fmt("""
Enable storing issued token data to token validation cache so that first token
validation doesn't actually cause full validation cycle. This option has no
effect unless global caching and token caching are enabled.
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
    infer_roles,
    cache_on_issue,
    allow_expired_window,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
