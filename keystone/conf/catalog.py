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


template_file = cfg.StrOpt(
    'template_file',
    default='default_catalog.templates',
    help=utils.fmt("""
Absolute path to the file used for the templated catalog backend. This option
is only used if the `[catalog] driver` is set to `templated`.
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entry point for the catalog driver in the `keystone.catalog` namespace.
Keystone provides a `sql` option (which supports basic CRUD operations through
SQL), a `templated` option (which loads the catalog from a templated catalog
file on disk), and a `endpoint_filter.sql` option (which supports arbitrary
service catalogs per project).
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for catalog caching. This has no effect unless global caching is
enabled. In a typical deployment, there is no reason to disable this.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    help=utils.fmt("""
Time to cache catalog data (in seconds). This has no effect unless global and
catalog caching are both enabled. Catalog data (services, endpoints, etc.)
typically does not change frequently, and so a longer duration than the global
default may be desirable.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
Maximum number of entities that will be returned in a catalog collection. There
is typically no reason to set this, as it would be unusual for a deployment to
have enough services or endpoints to exceed a reasonable limit.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    template_file,
    driver,
    caching,
    cache_time,
    list_limit,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
