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


dead_retry = cfg.IntOpt(
    'dead_retry',
    default=5 * 60,
    help=utils.fmt("""
Number of seconds memcached server is considered dead before it is tried again.
This is used by the key value store system.
"""))

socket_timeout = cfg.IntOpt(
    'socket_timeout',
    default=3,
    help=utils.fmt("""
Timeout in seconds for every call to a server. This is used by the key value
store system.
"""))

pool_maxsize = cfg.IntOpt(
    'pool_maxsize',
    default=10,
    help=utils.fmt("""
Max total number of open connections to every memcached server. This is used by
the key value store system.
"""))

pool_unused_timeout = cfg.IntOpt(
    'pool_unused_timeout',
    default=60,
    help=utils.fmt("""
Number of seconds a connection to memcached is held unused in the pool before
it is closed. This is used by the key value store system.
"""))

pool_connection_get_timeout = cfg.IntOpt(
    'pool_connection_get_timeout',
    default=10,
    help=utils.fmt("""
Number of seconds that an operation will wait to get a memcache client
connection. This is used by the key value store system.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    dead_retry,
    socket_timeout,
    pool_maxsize,
    pool_unused_timeout,
    pool_connection_get_timeout,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
