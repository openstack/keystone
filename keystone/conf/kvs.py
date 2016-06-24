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


backends = cfg.ListOpt(
    'backends',
    default=[],
    help=utils.fmt("""
Extra dogpile.cache backend modules to register with the dogpile.cache
library.
"""))

config_prefix = cfg.StrOpt(
    'config_prefix',
    default='keystone.kvs',
    help=utils.fmt("""
Prefix for building the configuration dictionary for the KVS region. This
should not need to be changed unless there is another dogpile.cache region with
the same configuration name.
"""))

enable_key_mangler = cfg.BoolOpt(
    'enable_key_mangler',
    default=True,
    help=utils.fmt("""
Toggle to disable using a key-mangling function to ensure fixed length keys.
This is toggle-able for debugging purposes, it is highly recommended to always
leave this set to true.
"""))

default_lock_timeout = cfg.IntOpt(
    'default_lock_timeout',
    default=5,
    help=utils.fmt("""
Default lock timeout (in seconds) for distributed locking.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    backends,
    config_prefix,
    enable_key_mangler,
    default_lock_timeout,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
