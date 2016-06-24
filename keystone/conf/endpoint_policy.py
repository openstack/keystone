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
The option to enable the OS-ENDPOINT-POLICY extension has been deprecated in
the M release and will be removed in the O release. The OS-ENDPOINT-POLICY
extension will be enabled by default.
"""),
    help=utils.fmt("""
Enable endpoint_policy functionality.
"""))

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entrypoint for the endpoint policy backend driver in the
keystone.endpoint_policy namespace.
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
