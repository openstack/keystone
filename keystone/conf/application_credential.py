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
Entry point for the application credential backend driver in the
`keystone.application_credential` namespace.  Keystone only provides a `sql`
driver, so there is no reason to change this unless you are providing a custom
entry point.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for application credential caching. This has no effect unless global
caching is enabled.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    help=utils.fmt("""
Time to cache application credential data in seconds. This has no effect
unless global caching is enabled.
"""))

user_limit = cfg.IntOpt(
    'user_limit',
    default=-1,
    help=utils.fmt("""
Maximum number of application credentials a user is permitted to create. A
value of -1 means unlimited. If a limit is not set, users are permitted to
create application credentials at will, which could lead to bloat in the
keystone database or open keystone to a DoS attack.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    caching,
    cache_time,
    user_limit,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
