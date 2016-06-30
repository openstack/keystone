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
    deprecated_for_removal=True,
    deprecated_reason=utils.fmt("""
The option to enable the OS-ENDPOINT-POLICY API extension has been deprecated
in the M release and will be removed in the O release. The OS-ENDPOINT-POLICY
API extension will be enabled by default.
"""),
    help=utils.fmt("""
Enable endpoint-policy functionality, which allows policies to be associated
with either specific endpoints, or endpoints of a given service type.
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entry point for the endpoint policy driver in the `keystone.endpoint_policy`
namespace. Only a `sql` driver is provided by keystone, so there is no reason
to set this unless you are providing a custom entry point.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    enabled,
    driver,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
