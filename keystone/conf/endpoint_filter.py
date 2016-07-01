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
Entry point for the endpoint filter driver in the
`keystone.endpoint_filter` namespace. Only a `sql` option is provided by
keystone, so there is no reason to set this unless you are providing a custom
entry point.
"""))

return_all_endpoints_if_no_filter = cfg.BoolOpt(
    'return_all_endpoints_if_no_filter',
    default=True,
    help=utils.fmt("""
This controls keystone's behavior if the configured endpoint filters do not
result in any endpoints for a user + project pair (and therefore a potentially
empty service catalog). If set to true, keystone will return the entire service
catalog. If set to false, keystone will return an empty service catalog.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    return_all_endpoints_if_no_filter,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
