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
    help=utils.fmt("""
Entrypoint for the assignment backend driver in the keystone.assignment
namespace. Only an SQL driver is supplied. If an assignment driver is not
specified, the identity driver will choose the assignment driver (driver
selection based on `[identity]/driver` option is deprecated and will be removed
in the "O" release).
"""))

prohibited_implied_role = cfg.ListOpt(
    'prohibited_implied_role',
    default=['admin'],
    help=utils.fmt("""
A list of role names which are prohibited from being an implied role.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    prohibited_implied_role
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
