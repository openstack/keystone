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

from keystone.conf import utils


driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entrypoint for an implementation of the backend for persisting revocation
events in the keystone.revoke namespace. Supplied drivers are kvs and sql.
"""))

expiration_buffer = cfg.IntOpt(
    'expiration_buffer',
    default=1800,
    help=utils.fmt("""
This value (calculated in seconds) is added to token expiration before a
revocation event may be removed from the backend.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for revocation event caching. This has no effect unless global caching
is enabled.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    default=3600,
    deprecated_opts=[
        cfg.DeprecatedOpt('revocation_cache_time', group='token')],
    help=utils.fmt("""
Time to cache the revocation list and the revocation events (in seconds). This
has no effect unless global and token caching are enabled.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    expiration_buffer,
    caching,
    cache_time,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
