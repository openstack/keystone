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
Entry point for the resource driver in the `keystone.resource` namespace. Only
a `sql` driver is supplied by keystone. Unless you are writing proprietary
drivers for keystone, you do not need to set this option.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    deprecated_opts=[cfg.DeprecatedOpt('caching', group='assignment')],
    help=utils.fmt("""
Toggle for resource caching. This has no effect unless global caching is
enabled.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    deprecated_opts=[cfg.DeprecatedOpt('cache_time', group='assignment')],
    help=utils.fmt("""
Time to cache resource data in seconds. This has no effect unless global
caching is enabled.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    deprecated_opts=[cfg.DeprecatedOpt('list_limit', group='assignment')],
    help=utils.fmt("""
Maximum number of entities that will be returned in a resource collection.
"""))

admin_project_domain_name = cfg.StrOpt(
    'admin_project_domain_name',
    help=utils.fmt("""
Name of the domain that owns the `admin_project_name`. If left unset, then
there is no admin project. `[resource] admin_project_name` must also be set to
use this option.
"""))

admin_project_name = cfg.StrOpt(
    'admin_project_name',
    help=utils.fmt("""
This is a special project which represents cloud-level administrator privileges
across services. Tokens scoped to this project will contain a true
`is_admin_project` attribute to indicate to policy systems that the role
assignments on that specific project should apply equally across every project.
If left unset, then there is no admin project, and thus no explicit means of
cross-project role assignments. `[resource] admin_project_domain_name` must
also be set to use this option.
"""))

project_name_url_safe = cfg.StrOpt(
    'project_name_url_safe',
    choices=['off', 'new', 'strict'],
    default='off',
    help=utils.fmt("""
This controls whether the names of projects are restricted from containing
URL-reserved characters. If set to `new`, attempts to create or update a
project with a URL-unsafe name will fail. If set to `strict`, attempts to scope
a token with a URL-unsafe project name will fail, thereby forcing all project
names to be updated to be URL-safe.
"""))

domain_name_url_safe = cfg.StrOpt(
    'domain_name_url_safe',
    choices=['off', 'new', 'strict'],
    default='off',
    help=utils.fmt("""
This controls whether the names of domains are restricted from containing
URL-reserved characters. If set to `new`, attempts to create or update a domain
with a URL-unsafe name will fail. If set to `strict`, attempts to scope a token
with a URL-unsafe domain name will fail, thereby forcing all domain names to be
updated to be URL-safe.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    caching,
    cache_time,
    list_limit,
    admin_project_domain_name,
    admin_project_name,
    project_name_url_safe,
    domain_name_url_safe,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
