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


_DEPRECATE_KVS_MSG = utils.fmt("""
This option has been deprecated in the O release and will be removed in the P
release. Use SQL backends instead.
""")


backends = cfg.ListOpt(
    'backends',
    default=[],
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_KVS_MSG,
    deprecated_since=versionutils.deprecated.OCATA,
    help=utils.fmt("""
Extra `dogpile.cache` backend modules to register with the `dogpile.cache`
library. It is not necessary to set this value unless you are providing a
custom KVS backend beyond what `dogpile.cache` already supports.
"""))

config_prefix = cfg.StrOpt(
    'config_prefix',
    default='keystone.kvs',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_KVS_MSG,
    deprecated_since=versionutils.deprecated.OCATA,
    help=utils.fmt("""
Prefix for building the configuration dictionary for the KVS region. This
should not need to be changed unless there is another `dogpile.cache` region
with the same configuration name.
"""))

enable_key_mangler = cfg.BoolOpt(
    'enable_key_mangler',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_KVS_MSG,
    deprecated_since=versionutils.deprecated.OCATA,
    help=utils.fmt("""
Set to false to disable using a key-mangling function, which ensures
fixed-length keys are used in the KVS store. This is configurable for debugging
purposes, and it is therefore highly recommended to always leave this set to
true.
"""))

default_lock_timeout = cfg.IntOpt(
    'default_lock_timeout',
    default=5,
    min=0,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_KVS_MSG,
    deprecated_since=versionutils.deprecated.OCATA,
    help=utils.fmt("""
Number of seconds after acquiring a distributed lock that the backend should
consider the lock to be expired. This option should be tuned relative to the
longest amount of time that it takes to perform a successful operation. If this
value is set too low, then a cluster will end up performing work redundantly.
If this value is set too high, then a cluster will not be able to efficiently
recover and retry after a failed operation. A non-zero value is recommended if
the backend supports lock timeouts, as zero prevents locks from expiring
altogether.
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
