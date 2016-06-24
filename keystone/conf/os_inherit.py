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


_DEPRECATE_INHERIT_MSG = utils.fmt("""
The option to enable the OS-INHERIT extension has been deprecated in the M
release and will be removed in the O release. The OS-INHERIT extension will be
enabled by default.
""")


enabled = cfg.BoolOpt(
    'enabled',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_INHERIT_MSG,
    help=utils.fmt("""
role-assignment inheritance to projects from owning domain or from projects
higher in the hierarchy can be optionally disabled. In the future, this option
will be removed and the hierarchy will be always enabled.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    enabled,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
