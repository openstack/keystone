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
Entry point for the credential backend driver in the `keystone.credential`
namespace. Keystone only provides a `sql` driver, so there's no reason to
change this unless you are providing a custom entry point.
"""))

provider = cfg.StrOpt(
    'provider',
    default='fernet',
    help=utils.fmt("""
Entry point for credential encryption and decryption operations in the
`keystone.credential.provider` namespace. Keystone only provides a `fernet`
driver, so there's no reason to change this unless you are providing a custom
entry point to encrypt and decrypt credentials.
"""))

key_repository = cfg.StrOpt(
    'key_repository',
    default='/etc/keystone/credential-keys/',
    help=utils.fmt("""
Directory containing Fernet keys used to encrypt and decrypt credentials stored
in the credential backend. Fernet keys used to encrypt credentials have no
relationship to Fernet keys used to encrypt Fernet tokens. Both sets of keys
should be managed separately and require different rotation policies. Do not
share this repository with the repository used to manage keys for Fernet
tokens.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    provider,
    key_repository
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
