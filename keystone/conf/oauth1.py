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
Entry point for the OAuth backend driver in the `keystone.oauth1` namespace.
Typically, there is no reason to set this option unless you are providing a
custom entry point.
"""))

request_token_duration = cfg.IntOpt(
    'request_token_duration',
    min=0,
    default=28800,
    help=utils.fmt("""
Number of seconds for the OAuth Request Token to remain valid after being
created. This is the amount of time the user has to authorize the token.
Setting this option to zero means that request tokens will last forever.
"""))

access_token_duration = cfg.IntOpt(
    'access_token_duration',
    min=0,
    default=86400,
    help=utils.fmt("""
Number of seconds for the OAuth Access Token to remain valid after being
created. This is the amount of time the consumer has to interact with the
service provider (which is typically keystone). Setting this option to zero
means that access tokens will last forever.
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
