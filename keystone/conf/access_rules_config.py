# Copyright 2019 SUSE Linux GmbH
#
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
    default='json',
    help=utils.fmt("""
Entry point for the access rules config backend driver in the
`keystone.access_rules_config` namespace.  Keystone only provides a `json`
driver, so there is no reason to change this unless you are providing a custom
entry point.
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for access rules caching. This has no effect unless global caching is
enabled.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    help=utils.fmt("""
Time to cache access rule data in seconds. This has no effect unless global
caching is enabled.
"""))

rules_file = cfg.StrOpt(
    'rules_file',
    default='/etc/keystone/access_rules.json',
    help=utils.fmt("""
Path to access rules configuration. If not present, no access rule
configuration will be loaded and application credential access rules will be
unavailable.
"""))

permissive = cfg.BoolOpt(
    'permissive',
    default=False,
    help=utils.fmt("""
Toggles permissive mode for access rules. When enabled, application
credentials can be created with any access rules regardless of operator's
configuration.
"""))

GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    caching,
    cache_time,
    rules_file,
    permissive,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
