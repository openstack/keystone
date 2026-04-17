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

SUPPORTED_JWS_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'EdDSA']

jws_algorithm = cfg.StrOpt(
    'jws_algorithm',
    default='ES256',
    choices=SUPPORTED_JWS_ALGORITHMS,
    help=utils.fmt(
        """
The algorithm used to sign JWS tokens. Changing this value requires
regenerating the JWS key pair via `keystone-manage create_jws_keypair` since
each algorithm uses a different key type. Supported values: ES256 (ECDSA
P-256, default), ES384 (ECDSA P-384), ES512 (ECDSA P-521), EdDSA (Ed25519).
This option is only applicable when `keystone.conf [token] provider = jws`.
"""
    ),
)

jws_accepted_algorithms = cfg.ListOpt(
    'jws_accepted_algorithms',
    default=['ES256'],
    help=utils.fmt(
        """
List of algorithms accepted when validating JWS token signatures. During an
algorithm migration, this should include both the old and new algorithm so that
tokens signed with the old algorithm remain valid until they expire. Each value
must be one of: ES256, ES384, ES512, EdDSA. This option is only applicable
when `keystone.conf [token] provider = jws`.
"""
    ),
)

jws_public_key_repository = cfg.StrOpt(
    'jws_public_key_repository',
    default='/etc/keystone/jws-keys/public',
    help=utils.fmt(
        """
Directory containing public keys for validating JWS token signatures. This
directory must exist in order for keystone's server process to start. It must
also be readable by keystone's server process. It must contain at least one
public key that corresponds to a private key in `keystone.conf [jwt_tokens]
jws_private_key_repository`. This option is only applicable in deployments
issuing JWS tokens and setting `keystone.conf [token] provider = jws`.
"""
    ),
)
jws_private_key_repository = cfg.StrOpt(
    'jws_private_key_repository',
    default='/etc/keystone/jws-keys/private',
    help=utils.fmt(
        """
Directory containing private keys for signing JWS tokens. This directory must
exist in order for keystone's server process to start. It must also be readable
by keystone's server process. It must contain at least one private key that
corresponds to a public key in `keystone.conf [jwt_tokens]
jws_public_key_repository`. In the event there are multiple private keys in
this directory, keystone will use a key named `private.pem` to sign tokens. In
the future, keystone may support the ability to sign tokens with multiple
private keys. For now, only a key named `private.pem` within this directory is
required to issue JWS tokens. This option is only applicable in deployments
issuing JWS tokens and setting `keystone.conf [token] provider = jws`.
"""
    ),
)


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    jws_algorithm,
    jws_accepted_algorithms,
    jws_public_key_repository,
    jws_private_key_repository,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
