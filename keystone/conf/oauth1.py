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
Entrypoint for the OAuth backend driver in the keystone.oauth1 namespace.
"""))

request_token_duration = cfg.IntOpt(
    'request_token_duration',
    default=28800,
    help=utils.fmt("""
Duration (in seconds) for the OAuth Request Token.
"""))

access_token_duration = cfg.IntOpt(
    'access_token_duration',
    default=86400,
    help=utils.fmt("""
Duration (in seconds) for the OAuth Access Token.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    request_token_duration,
    access_token_duration,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
