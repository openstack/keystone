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
Entry point for the unified limit backend driver in the
`keystone.unified_limit` namespace. Keystone only provides a `sql` driver, so
there's no reason to change this unless you are providing a custom entry point.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for unified limit caching. This has no effect unless global caching is
enabled. In a typical deployment, there is no reason to disable this.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    help=utils.fmt("""
Time to cache unified limit data, in seconds. This has no effect unless both
global caching and `[unified_limit] caching` are enabled.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
Maximum number of entities that will be returned in a unified limit
collection. This may be useful to tune if you have a large number of
unified limits in your deployment.
"""))

enforcement_model = cfg.StrOpt(
    'enforcement_model',
    default='flat',
    choices=['flat', 'strict_two_level'],
    help=utils.fmt("""
The enforcement model to use when validating limits associated to projects.
Enforcement models will behave differently depending on the existing limits,
which may result in backwards incompatible changes if a model is switched in a
running deployment.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    caching,
    cache_time,
    list_limit,
    enforcement_model,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
