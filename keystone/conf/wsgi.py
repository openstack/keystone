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


debug_middleware = cfg.BoolOpt(
    'debug_middleware',
    default=False,
    help=utils.fmt("""
If set to true, this enables the oslo debug middleware in Keystone. This
Middleware prints a lot of information about the request and the response. It
is useful for getting information about the data on the wire (decoded) and
passed to the WSGI application pipeline. This middleware has no effect on
the "debug" setting in the [DEFAULT] section of the config file or setting
Keystone's log-level to "DEBUG"; it is specific to debugging the WSGI data
as it enters and leaves Keystone (specific request-related data). This option
is used for introspection on the request and response data between the web
server (apache, nginx, etc) and Keystone.

This middleware is inserted as the first element in the middleware chain
and will show the data closest to the wire.

WARNING: NOT INTENDED FOR USE IN PRODUCTION. THIS MIDDLEWARE CAN AND WILL EMIT
SENSITIVE/PRIVILEGED DATA.
"""))

GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    debug_middleware,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
