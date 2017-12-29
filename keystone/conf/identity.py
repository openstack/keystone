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
import passlib.utils

from keystone.conf import utils


default_domain_id = cfg.StrOpt(
    'default_domain_id',
    default='default',
    help=utils.fmt("""
This references the domain to use for all Identity API v2 requests (which are
not aware of domains). A domain with this ID can optionally be created for you
by `keystone-manage bootstrap`. The domain referenced by this ID cannot be
deleted on the v3 API, to prevent accidentally breaking the v2 API. There is
nothing special about this domain, other than the fact that it must exist to
order to maintain support for your v2 clients. There is typically no reason to
change this value.
"""))

domain_specific_drivers_enabled = cfg.BoolOpt(
    'domain_specific_drivers_enabled',
    default=False,
    help=utils.fmt("""
A subset (or all) of domains can have their own identity driver, each with
their own partial configuration options, stored in either the resource backend
or in a file in a domain configuration directory (depending on the setting of
`[identity] domain_configurations_from_database`). Only values specific to the
domain need to be specified in this manner. This feature is disabled by
default, but may be enabled by default in a future release; set to true to
enable.
"""))

domain_configurations_from_database = cfg.BoolOpt(
    'domain_configurations_from_database',
    default=False,
    help=utils.fmt("""
By default, domain-specific configuration data is read from files in the
directory identified by `[identity] domain_config_dir`. Enabling this
configuration option allows you to instead manage domain-specific
configurations through the API, which are then persisted in the backend
(typically, a SQL database), rather than using configuration files on disk.
"""))

domain_config_dir = cfg.StrOpt(
    'domain_config_dir',
    default='/etc/keystone/domains',
    help=utils.fmt("""
Absolute path where keystone should locate domain-specific `[identity]`
configuration files. This option has no effect unless `[identity]
domain_specific_drivers_enabled` is set to true. There is typically no reason
to change this value.
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entry point for the identity backend driver in the `keystone.identity`
namespace. Keystone provides a `sql` and `ldap` driver. This option is also
used as the default driver selection (along with the other configuration
variables in this section) in the event that `[identity]
domain_specific_drivers_enabled` is enabled, but no applicable domain-specific
configuration is defined for the domain in question. Unless your deployment
primarily relies on `ldap` AND is not using domain-specific configuration, you
should typically leave this set to `sql`.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for identity caching. This has no effect unless global caching is
enabled. There is typically no reason to disable this.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    default=600,
    help=utils.fmt("""
Time to cache identity data (in seconds). This has no effect unless global and
identity caching are enabled.
"""))

max_password_length = cfg.IntOpt(
    'max_password_length',
    default=4096,
    max=passlib.utils.MAX_PASSWORD_SIZE,
    help=utils.fmt("""
Maximum allowed length for user passwords. Decrease this value to improve
performance. Changing this value does not effect existing passwords.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
Maximum number of entities that will be returned in an identity collection.
"""))

password_hash_algorithm = cfg.StrOpt(
    'password_hash_algorithm',
    choices=['bcrypt', 'scrypt', 'pbkdf2_sha512'],
    default='bcrypt',
    help=utils.fmt("""
The password hashing algorithm to use for passwords stored within keystone.
"""))

password_hash_rounds = cfg.IntOpt(
    'password_hash_rounds',
    help=utils.fmt("""
This option represents a trade off between security and performance. Higher
values lead to slower performance, but higher security. Changing this option
will only affect newly created passwords as existing password hashes already
have a fixed number of rounds applied, so it is safe to tune this option in a
running cluster.

The default for bcrypt is 12, must be between 4 and 31, inclusive.

The default for scrypt is 16, must be within `range(1,32)`.

The default for pbkdf_sha512 is 60000, must be within `range(1,1<<32)`

WARNING: If using scrypt, increasing this value increases BOTH time AND
memory requirements to hash a password.
"""))

salt_bytesize = cfg.IntOpt(
    'salt_bytesize',
    min=0,
    max=96,
    help=utils.fmt("""
Number of bytes to use in scrypt and pbkfd2_sha512 hashing salt.

Default for scrypt is 16 bytes.
Default for pbkfd2_sha512 is 16 bytes.

Limited to a maximum of 96 bytes due to the size of the column used to store
password hashes.
"""))

scrypt_block_size = cfg.IntOpt(
    'scrypt_block_size',
    help=utils.fmt("""
Optional block size to pass to scrypt hash function (the `r` parameter).
Useful for tuning scrypt to optimal performance for your CPU architecture.
This option is only used when the `password_hash_algorithm` option is set
to `scrypt`. Defaults to 8.
"""))

scrypt_paralellism = cfg.IntOpt(
    'scrypt_parallelism',
    help=utils.fmt("""
Optional parallelism to pass to scrypt hash function (the `p` parameter).
This option is only used when the `password_hash_algorithm` option is set
to `scrypt`. Defaults to 1.
"""))

GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    default_domain_id,
    domain_specific_drivers_enabled,
    domain_configurations_from_database,
    domain_config_dir,
    driver,
    caching,
    cache_time,
    max_password_length,
    list_limit,
    password_hash_algorithm,
    password_hash_rounds,
    scrypt_block_size,
    scrypt_paralellism,
    salt_bytesize,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
