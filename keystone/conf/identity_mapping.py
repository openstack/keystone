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
Entrypoint for the identity mapping backend driver in the
keystone.identity.id_mapping namespace.
"""))

generator = cfg.StrOpt(
    'generator',
    default='sha256',
    help=utils.fmt("""
Entrypoint for the public ID generator for user and group entities in the
keystone.identity.id_generator namespace. The Keystone identity mapper only
supports generators that produce no more than 64 characters.
"""))

backward_compatible_ids = cfg.BoolOpt(
    'backward_compatible_ids',
    default=True,
    help=utils.fmt("""
The format of user and group IDs changed in Juno for backends that do not
generate UUIDs (e.g. LDAP), with keystone providing a hash mapping to the
underlying attribute in LDAP. By default this mapping is disabled, which
ensures that existing IDs will not change. Even when the mapping is enabled by
using domain specific drivers, any users and groups from the default domain
being handled by LDAP will still not be mapped to ensure their IDs remain
backward compatible. Setting this value to False will enable the mapping for
even the default LDAP driver. It is only safe to do this if you do not already
have assignments for users and groups from the default LDAP domain, and it is
acceptable for Keystone to provide the different IDs to clients than it did
previously. Typically this means that the only time you can set this value to
False is when configuring a fresh installation.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    generator,
    backward_compatible_ids,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
