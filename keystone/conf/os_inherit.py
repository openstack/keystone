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
from oslo_log import versionutils

from keystone.conf import utils


_DEPRECATE_INHERIT_MSG = utils.fmt("""
The option to disable the OS-INHERIT functionality has been deprecated in the
Mitaka release and will be removed in the Ocata release. Starting in the Ocata
release, OS-INHERIT functionality will always be enabled.
""")


enabled = cfg.BoolOpt(
    'enabled',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_INHERIT_MSG,
    deprecated_since=versionutils.deprecated.MITAKA,
    help=utils.fmt("""
This allows domain-based role assignments to be inherited to projects owned by
that domain, or from parent projects to child projects.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    enabled,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
