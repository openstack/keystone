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


key_repository = cfg.StrOpt(
    'key_repository',
    default='/etc/keystone/fernet-keys/',
    help=utils.fmt("""
Directory containing Fernet receipt keys. This directory must exist before
using `keystone-manage fernet_setup` for the first time, must be writable by
the user running `keystone-manage fernet_setup` or `keystone-manage
fernet_rotate`, and of course must be readable by keystone's server process.
The repository may contain keys in one of three states: a single staged key
(always index 0) used for receipt validation, a single primary key (always the
highest index) used for receipt creation and validation, and any number of
secondary keys (all other index values) used for receipt validation. With
multiple keystone nodes, each node must share the same key repository contents,
with the exception of the staged key (index 0). It is safe to run
`keystone-manage fernet_rotate` once on any one node to promote a staged key
(index 0) to be the new primary (incremented from the previous highest index),
and produce a new staged key (a new key with index 0); the resulting repository
can then be atomically replicated to other nodes without any risk of race
conditions (for example, it is safe to run `keystone-manage fernet_rotate` on
host A, wait any amount of time, create a tarball of the directory on host A,
unpack it on host B to a temporary location, and atomically move (`mv`) the
directory into place on host B). Running `keystone-manage fernet_rotate`
*twice* on a key repository without syncing other nodes will result in receipts
that can not be validated by all nodes.
"""))

max_active_keys = cfg.IntOpt(
    'max_active_keys',
    default=3,
    min=1,
    help=utils.fmt("""
This controls how many keys are held in rotation by `keystone-manage
fernet_rotate` before they are discarded. The default value of 3 means that
keystone will maintain one staged key (always index 0), one primary key (the
highest numerical index), and one secondary key (every other index). Increasing
this value means that additional secondary keys will be kept in the rotation.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    key_repository,
    max_active_keys,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
