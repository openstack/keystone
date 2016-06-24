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
not aware of domains). A domain with this ID will be created for you by
keystone-manage db_sync in migration 008. The domain referenced by this ID
cannot be deleted on the v3 API, to prevent accidentally breaking the v2 API.
There is nothing special about this domain, other than the fact that it must
exist to order to maintain support for your v2 clients.
"""))

domain_specific_drivers_enabled = cfg.BoolOpt(
    'domain_specific_drivers_enabled',
    default=False,
    help=utils.fmt("""
A subset (or all) of domains can have their own identity driver, each with
their own partial configuration options, stored in either the resource backend
or in a file in a domain configuration directory (depending on the setting of
domain_configurations_from_database). Only values specific to the domain need
to be specified in this manner. This feature is disabled by default; set to
true to enable.
"""))

domain_configurations_from_database = cfg.BoolOpt(
    'domain_configurations_from_database',
    default=False,
    help=utils.fmt("""
Extract the domain specific configuration options from the resource backend
where they have been stored with the domain data. This feature is disabled by
default (in which case the domain specific options will be loaded from files in
the domain configuration directory); set to true to enable.
"""))

domain_config_dir = cfg.StrOpt(
    'domain_config_dir',
    default='/etc/keystone/domains',
    help=utils.fmt("""
Path for Keystone to locate the domain specific identity configuration files if
domain_specific_drivers_enabled is set to true.
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entrypoint for the identity backend driver in the keystone.identity namespace.
Supplied drivers are ldap and sql.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for identity caching. This has no effect unless global caching is
enabled.
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
Maximum supported length for user passwords; decrease to improve
performance.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
Maximum number of entities that will be returned in an identity collection.
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
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
