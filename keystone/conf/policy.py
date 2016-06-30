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
Entry point for the policy backend driver in the `keystone.policy` namespace.
Supplied drivers are `rules` (which does not support any CRUD operations for
the v3 policy API) and `sql`. Typically, there is no reason to set this option
unless you are providing a custom entry point.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
Maximum number of entities that will be returned in a policy collection.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    list_limit,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
