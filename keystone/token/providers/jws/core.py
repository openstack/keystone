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

import datetime
import os

import jwt
from oslo_utils import timeutils

from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.token.providers import base

CONF = keystone.conf.CONF


class Provider(base.Provider):

    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)

        # NOTE(lbragstad): We add these checks here because if the jws
        # provider is going to be used and either the `key_repository` is empty
        # or doesn't exist we should fail, hard. It doesn't make sense to start
        # keystone and just 500 because we can't do anything with an empty or
        # non-existant key repository.
        private_key = os.path.join(
            CONF.jwt_tokens.jws_private_key_repository, 'private.pem'
        )
        public_key_repo = CONF.jwt_tokens.jws_public_key_repository

        if not os.path.exists(private_key):
            subs = {'private_key': private_key}
            raise SystemExit(_(
                '%(private_key)s does not exist. You can generate a key pair '
                'using `keystone-manage create_jws_keypair`.') % subs)
        if not os.path.exists(public_key_repo):
            subs = {'public_key_repo': public_key_repo}
            raise SystemExit(_(
                '%(public_key_repo)s does not exist. Please make sure the '
                'directory exists and is readable by the process running '
                'keystone.') % subs)
        if len(os.listdir(public_key_repo)) == 0:
            subs = {'public_key_repo': public_key_repo}
            msg = _(
                '%(public_key_repo)s must contain at least one public '
                'key but it is empty. You can generate a key pair using '
                '`keystone-manage create_jws_keypair`.'
            )
            raise SystemExit(msg % subs)
        self.token_formatter = JWSFormatter()

    def generate_id_and_issued_at(self, token):
        return self.token_formatter.create_token(
            token.user_id, token.expires_at, token.audit_ids, token.methods,
            system=token.system, domain_id=token.domain_id,
            project_id=token.project_id, trust_id=token.trust_id,
            federated_group_ids=token.federated_groups,
            identity_provider_id=token.identity_provider_id,
            protocol_id=token.protocol_id,
            access_token_id=token.access_token_id,
            app_cred_id=token.application_credential_id
        )

    def validate_token(self, token_id):
        return self.token_formatter.validate_token(token_id)


class JWSFormatter(object):

    # NOTE(lbragstad): If in the future we expand support for different
    # algorithms, make this configurable and validate it against a blessed list
    # of supported algorithms.
    algorithm = 'ES256'

    @property
    def private_key(self):
        private_key_path = os.path.join(
            CONF.jwt_tokens.jws_private_key_repository, 'private.pem'
        )
        with open(private_key_path, 'r') as f:
            key = f.read()
        return key

    @property
    def public_keys(self):
        keys = []
        key_repo = CONF.jwt_tokens.jws_public_key_repository
        for keyfile in os.listdir(key_repo):
            with open(os.path.join(key_repo, keyfile), 'r') as f:
                keys.append(f.read())
        return keys

    def create_token(self, user_id, expires_at, audit_ids, methods,
                     system=None, domain_id=None, project_id=None,
                     trust_id=None, federated_group_ids=None,
                     identity_provider_id=None, protocol_id=None,
                     access_token_id=None, app_cred_id=None):

        issued_at = utils.isotime(subsecond=True)
        issued_at_int = self._convert_time_string_to_int(issued_at)
        expires_at_int = self._convert_time_string_to_int(expires_at)

        payload = {
            # public claims
            'sub': user_id,
            'iat': issued_at_int,
            'exp': expires_at_int,
            # private claims
            'openstack_methods': methods,
            'openstack_audit_ids': audit_ids,
            'openstack_system': system,
            'openstack_domain_id': domain_id,
            'openstack_project_id': project_id,
            'openstack_trust_id': trust_id,
            'openstack_group_ids': federated_group_ids,
            'openstack_idp_id': identity_provider_id,
            'openstack_protocol_id': protocol_id,
            'openstack_access_token_id': access_token_id,
            'openstack_app_cred_id': app_cred_id
        }

        # NOTE(lbragstad): Calling .items() on a dictionary in python 2 returns
        # a list but returns an iterable in python 3. Casting to a list makes
        # it safe to modify the dictionary while iterating over it, regardless
        # of the python version.
        for k, v in list(payload.items()):
            if v is None:
                payload.pop(k)

        token_id = jwt.encode(
            payload,
            self.private_key,
            algorithm=JWSFormatter.algorithm
        )
        return token_id, issued_at

    def validate_token(self, token_id):
        payload = self._decode_token_from_id(token_id)

        user_id = payload['sub']
        expires_at_int = payload['exp']
        issued_at_int = payload['iat']
        methods = payload['openstack_methods']
        audit_ids = payload['openstack_audit_ids']

        system = payload.get('openstack_system', None)
        domain_id = payload.get('openstack_domain_id', None)
        project_id = payload.get('openstack_project_id', None)
        trust_id = payload.get('openstack_trust_id', None)
        federated_group_ids = payload.get('openstack_group_ids', None)
        identity_provider_id = payload.get('openstack_idp_id', None)
        protocol_id = payload.get('openstack_protocol_id', None)
        access_token_id = payload.get('openstack_access_token_id', None)
        app_cred_id = payload.get('openstack_app_cred_id', None)

        issued_at = self._convert_time_int_to_string(issued_at_int)
        expires_at = self._convert_time_int_to_string(expires_at_int)

        return (
            user_id, methods, audit_ids, system, domain_id, project_id,
            trust_id, federated_group_ids, identity_provider_id, protocol_id,
            access_token_id, app_cred_id, issued_at, expires_at
        )

    def _decode_token_from_id(self, token_id):
        options = dict()
        options['verify_exp'] = False
        for public_key in self.public_keys:
            try:
                return jwt.decode(
                    token_id, public_key, algorithms=JWSFormatter.algorithm,
                    options=options
                )
            except (jwt.InvalidSignatureError, jwt.DecodeError):
                pass    # nosec: We want to exhaustively try all public keys
        raise exception.TokenNotFound(token_id=token_id)

    def _convert_time_string_to_int(self, time_str):
        time_object = timeutils.parse_isotime(time_str)
        normalized = timeutils.normalize_time(time_object)
        epoch = datetime.datetime.utcfromtimestamp(0)
        return int((normalized - epoch).total_seconds())

    def _convert_time_int_to_string(self, time_int):
        time_object = datetime.datetime.utcfromtimestamp(time_int)
        return utils.isotime(at=time_object, subsecond=True)
