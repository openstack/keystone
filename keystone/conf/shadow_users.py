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
    help=utils.fmt(
        """
Entry point for the shadow users backend driver in the
`keystone.identity.shadow_users` namespace. This driver is used for persisting
local user references to externally-managed identities (via federation, LDAP,
etc). Keystone only provides a `sql` driver, so there is no reason to change
this option unless you are providing a custom entry point.
"""
    ),
)


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [driver]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
