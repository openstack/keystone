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


config_file = cfg.StrOpt(
    'config_file',
    default='keystone-paste.ini',
    help=utils.fmt("""
Name of (or absolute path to) the Paste Deploy configuration file that composes
middleware and the keystone application itself into actual WSGI entry points.
See http://pythonpaste.org/deploy/ for additional documentation on the file's
format.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    config_file,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
