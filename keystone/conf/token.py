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

from oslo_config import cfg

from keystone.conf import constants
from keystone.conf import utils


bind = cfg.ListOpt(
    'bind',
    default=[],
    help=utils.fmt("""
External auth mechanisms that should add bind information to token, e.g.,
kerberos,x509.
"""))

enforce_token_bind = cfg.StrOpt(
    'enforce_token_bind',
    default='permissive',
    help=utils.fmt("""
Enforcement policy on tokens presented to Keystone with bind information. One
of disabled, permissive, strict, required or a specifically required bind mode,
e.g., kerberos or x509 to require binding to that authentication.
"""))

expiration = cfg.IntOpt(
    'expiration',
    default=3600,
    help=utils.fmt("""
Amount of time a token should remain valid (in seconds).
"""))

provider = cfg.StrOpt(
    'provider',
    default='uuid',
    help=utils.fmt("""
Controls the token construction, validation, and revocation operations.
Entrypoint in the keystone.token.provider namespace. Core providers are
[fernet|pkiz|pki|uuid].
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entrypoint for the token persistence backend driver in the
keystone.token.persistence namespace. Supplied drivers are kvs, memcache,
memcache_pool, and sql.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for token system caching. This has no effect unless global caching is
enabled.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    help=utils.fmt("""
Time to cache tokens (in seconds). This has no effect unless global and token
caching are enabled.
"""))

revoke_by_id = cfg.BoolOpt(
    'revoke_by_id',
    default=True,
    help=utils.fmt("""
Revoke token by token identifier. Setting revoke_by_id to true enables various
forms of enumerating tokens, e.g. `list tokens for user`. These enumerations
are processed to determine the list of tokens to revoke. Only disable if you
are switching to using the Revoke extension with a backend other than KVS,
which stores events in memory.
"""))

allow_rescope_scoped_token = cfg.BoolOpt(
    'allow_rescope_scoped_token',
    default=True,
    help=utils.fmt("""
Allow rescoping of scoped token. Setting allow_rescoped_scoped_token to false
prevents a user from exchanging a scoped token for any other token.
"""))

hash_algorithm = cfg.StrOpt(
    'hash_algorithm',
    default='md5',
    deprecated_for_removal=True,
    deprecated_reason=constants._DEPRECATE_PKI_MSG,
    help=utils.fmt("""
The hash algorithm to use for PKI tokens. This can be set to any algorithm that
hashlib supports. WARNING: Before changing this value, the auth_token
middleware must be configured with the hash_algorithms, otherwise token
revocation will not be processed correctly.
"""))

infer_roles = cfg.BoolOpt(
    'infer_roles',
    default=True,
    help=utils.fmt("""
Add roles to token that are not explicitly added, but that are linked
implicitly to other roles.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    bind,
    enforce_token_bind,
    expiration,
    provider,
    driver,
    caching,
    cache_time,
    revoke_by_id,
    allow_rescope_scoped_token,
    hash_algorithm,
    infer_roles,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
