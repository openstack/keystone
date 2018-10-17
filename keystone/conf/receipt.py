# Copyright 2018 Catalyst Cloud Ltd
#
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


expiration = cfg.IntOpt(
    'expiration',
    default=300,
    min=0,
    max=86400,
    help=utils.fmt("""
The amount of time that a receipt should remain valid (in seconds). This value
should always be very short, as it represents how long a user has to reattempt
auth with the missing auth methods.
"""))

provider = cfg.StrOpt(
    'provider',
    default='fernet',
    help=utils.fmt("""
Entry point for the receipt provider in the `keystone.receipt.provider`
namespace. The receipt provider controls the receipt construction and
validation operations. Keystone includes just the `fernet` receipt provider for
now. `fernet` receipts do not need to be persisted at all, but require that you
run `keystone-manage fernet_setup` (also see the `keystone-manage
fernet_rotate` command).
"""))

caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for caching receipt creation and validation data. This has no effect
unless global caching is enabled, or if cache_on_issue is disabled as we only
cache receipts on issue.
"""))

cache_time = cfg.IntOpt(
    'cache_time',
    default=300,
    min=0,
    help=utils.fmt("""
The number of seconds to cache receipt creation and validation data. This has
no effect unless both global and `[receipt] caching` are enabled.
"""))

cache_on_issue = cfg.BoolOpt(
    'cache_on_issue',
    default=True,
    help=utils.fmt("""
Enable storing issued receipt data to receipt validation cache so that first
receipt validation doesn't actually cause full validation cycle. This option
has no effect unless global caching and receipt caching are enabled.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    expiration,
    provider,
    caching,
    cache_time,
    cache_on_issue,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
