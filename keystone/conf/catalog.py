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
Catalog template file name for use with the template catalog backend.
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entrypoint for the catalog backend driver in the keystone.catalog namespace.
Supplied drivers are kvs, sql, templated, and endpoint_filter.sql
"""))

aching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for catalog caching. This has no effect unless global caching is
enabled.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    help=utils.fmt("""
Time to cache catalog data (in seconds). This has no effect unless global and
catalog caching are enabled.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
Maximum number of entities that will be returned in a catalog collection.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    template_file,
    driver,
    aching,
    cache_time,
    list_limit,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
