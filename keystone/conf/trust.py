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


enabled = cfg.BoolOpt(
    'enabled',
    default=True,
    help=utils.fmt("""
Delegation and impersonation features can be optionally disabled.
"""))

allow_redelegation = cfg.BoolOpt(
    'allow_redelegation',
    default=False,
    help=utils.fmt("""
Enable redelegation feature.
"""))

max_redelegation_count = cfg.IntOpt(
    'max_redelegation_count',
    default=3,
    help=utils.fmt("""
Maximum depth of trust redelegation.
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entrypoint for the trust backend driver in the keystone.trust namespace.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    enabled,
    allow_redelegation,
    max_redelegation_count,
    driver,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
