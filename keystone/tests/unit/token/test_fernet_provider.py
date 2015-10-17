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

import base64
import datetime
import hashlib
import os
import uuid

import msgpack
from oslo_utils import timeutils
from six.moves import urllib

from keystone.common import config
from keystone.common import utils
from keystone.contrib.federation import constants as federation_constants
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone.token import provider
from keystone.token.providers import fernet
from keystone.token.providers.fernet import token_formatters
from keystone.token.providers.fernet import utils as fernet_utils


CONF = config.CONF


class TestFernetTokenProvider(unit.TestCase):
    def setUp(self):
        super(TestFernetTokenProvider, self).setUp()
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))
        self.provider = fernet.Provider()

    def test_supports_bind_authentication_returns_false(self):
        self.assertFalse(self.provider._supports_bind_authentication)

    def test_needs_persistence_returns_false(self):
        self.assertFalse(self.provider.needs_persistence())

    def test_invalid_v3_token_raises_404(self):
        self.assertRaises(
            exception.TokenNotFound,
            self.provider.validate_v3_token,
            uuid.uuid4().hex)

    def test_invalid_v2_token_raises_404(self):
        self.assertRaises(
            exception.TokenNotFound,
            self.provider.validate_v2_token,
            uuid.uuid4().hex)


class TestValidate(unit.TestCase):
    def setUp(self):
        super(TestValidate, self).setUp()
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))
        self.useFixture(database.Database())
        self.load_backends()

    def config_overrides(self):
        super(TestValidate, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')

    def test_validate_v3_token_simple(self):
        # Check the fields in the token result when use validate_v3_token
        # with a simple token.

        domain_ref = unit.new_domain_ref()
        domain_ref = self.resource_api.create_domain(domain_ref['id'],
                                                     domain_ref)

        user_ref = unit.new_user_ref(domain_ref['id'])
        user_ref = self.identity_api.create_user(user_ref)

        method_names = ['password']
        token_id, token_data_ = self.token_provider_api.issue_v3_token(
            user_ref['id'], method_names)

        token_data = self.token_provider_api.validate_v3_token(token_id)
        token = token_data['token']
        self.assertIsInstance(token['audit_ids'], list)
        self.assertIsInstance(token['expires_at'], str)
        self.assertEqual({}, token['extras'])
        self.assertIsInstance(token['issued_at'], str)
        self.assertEqual(method_names, token['methods'])
        exp_user_info = {
            'id': user_ref['id'],
            'name': user_ref['name'],
            'domain': {
                'id': domain_ref['id'],
                'name': domain_ref['name'],
            },
        }
        self.assertEqual(exp_user_info, token['user'])

    def test_validate_v3_token_federated_info(self):
        # Check the user fields in the token result when use validate_v3_token
        # when the token has federated info.

        domain_ref = unit.new_domain_ref()
        domain_ref = self.resource_api.create_domain(domain_ref['id'],
                                                     domain_ref)

        user_ref = unit.new_user_ref(domain_ref['id'])
        user_ref = self.identity_api.create_user(user_ref)

        method_names = ['mapped']

        group_ids = [uuid.uuid4().hex, ]
        identity_provider = uuid.uuid4().hex
        protocol = uuid.uuid4().hex
        auth_context = {
            'user_id': user_ref['id'],
            'group_ids': group_ids,
            federation_constants.IDENTITY_PROVIDER: identity_provider,
            federation_constants.PROTOCOL: protocol,
        }
        token_id, token_data_ = self.token_provider_api.issue_v3_token(
            user_ref['id'], method_names, auth_context=auth_context)

        token_data = self.token_provider_api.validate_v3_token(token_id)
        token = token_data['token']
        exp_user_info = {
            'id': user_ref['id'],
            'name': user_ref['id'],
            'domain': {'id': CONF.federation.federated_domain_name,
                       'name': CONF.federation.federated_domain_name, },
            federation_constants.FEDERATION: {
                'groups': [{'id': group_id} for group_id in group_ids],
                'identity_provider': {'id': identity_provider, },
                'protocol': {'id': protocol, },
            },
        }
        self.assertEqual(exp_user_info, token['user'])

    def test_validate_v3_token_trust(self):
        # Check the trust fields in the token result when use validate_v3_token
        # when the token has trust info.

        domain_ref = unit.new_domain_ref()
        domain_ref = self.resource_api.create_domain(domain_ref['id'],
                                                     domain_ref)

        user_ref = unit.new_user_ref(domain_ref['id'])
        user_ref = self.identity_api.create_user(user_ref)

        trustor_user_ref = unit.new_user_ref(domain_ref['id'])
        trustor_user_ref = self.identity_api.create_user(trustor_user_ref)

        project_ref = unit.new_project_ref(domain_id=domain_ref['id'])
        project_ref = self.resource_api.create_project(project_ref['id'],
                                                       project_ref)

        role_ref = unit.new_role_ref()
        role_ref = self.role_api.create_role(role_ref['id'], role_ref)

        self.assignment_api.create_grant(
            role_ref['id'], user_id=user_ref['id'],
            project_id=project_ref['id'])

        self.assignment_api.create_grant(
            role_ref['id'], user_id=trustor_user_ref['id'],
            project_id=project_ref['id'])

        trustor_user_id = trustor_user_ref['id']
        trustee_user_id = user_ref['id']
        trust_ref = unit.new_trust_ref(
            trustor_user_id, trustee_user_id, project_id=project_ref['id'],
            role_ids=[role_ref['id'], ])
        trust_ref = self.trust_api.create_trust(trust_ref['id'], trust_ref,
                                                trust_ref['roles'])

        method_names = ['password']

        token_id, token_data_ = self.token_provider_api.issue_v3_token(
            user_ref['id'], method_names, project_id=project_ref['id'],
            trust=trust_ref)

        token_data = self.token_provider_api.validate_v3_token(token_id)
        token = token_data['token']
        exp_trust_info = {
            'id': trust_ref['id'],
            'impersonation': False,
            'trustee_user': {'id': user_ref['id'], },
            'trustor_user': {'id': trustor_user_ref['id'], },
        }
        self.assertEqual(exp_trust_info, token['OS-TRUST:trust'])

    def test_validate_v3_token_validation_error_exc(self):
        # When the token format isn't recognized, TokenNotFound is raised.

        # A uuid string isn't a valid fernet token.
        token_id = uuid.uuid4().hex
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_v3_token, token_id)


class TestTokenFormatter(unit.TestCase):
    def setUp(self):
        super(TestTokenFormatter, self).setUp()
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))

    def test_restore_padding(self):
        # 'a' will result in '==' padding, 'aa' will result in '=' padding, and
        # 'aaa' will result in no padding.
        strings_to_test = ['a', 'aa', 'aaa']

        for string in strings_to_test:
            encoded_string = base64.urlsafe_b64encode(string)
            encoded_str_without_padding = encoded_string.rstrip('=')
            self.assertFalse(encoded_str_without_padding.endswith('='))
            encoded_str_with_padding_restored = (
                token_formatters.TokenFormatter.restore_padding(
                    encoded_str_without_padding)
            )
            self.assertEqual(encoded_string, encoded_str_with_padding_restored)

    def test_legacy_padding_validation(self):
        first_value = uuid.uuid4().hex
        second_value = uuid.uuid4().hex
        payload = (first_value, second_value)
        msgpack_payload = msgpack.packb(payload)

        # NOTE(lbragstad): This method perserves the way that keystone used to
        # percent encode the tokens, prior to bug #1491926.
        def legacy_pack(payload):
            tf = token_formatters.TokenFormatter()
            encrypted_payload = tf.crypto.encrypt(payload)

            # the encrypted_payload is returned with padding appended
            self.assertTrue(encrypted_payload.endswith('='))

            # using urllib.parse.quote will percent encode the padding, like
            # keystone did in Kilo.
            percent_encoded_payload = urllib.parse.quote(encrypted_payload)

            # ensure that the padding was actaully percent encoded
            self.assertTrue(percent_encoded_payload.endswith('%3D'))
            return percent_encoded_payload

        token_with_legacy_padding = legacy_pack(msgpack_payload)
        tf = token_formatters.TokenFormatter()

        # demonstrate the we can validate a payload that has been percent
        # encoded with the Fernet logic that existed in Kilo
        serialized_payload = tf.unpack(token_with_legacy_padding)
        returned_payload = msgpack.unpackb(serialized_payload)
        self.assertEqual(first_value, returned_payload[0])
        self.assertEqual(second_value, returned_payload[1])


class TestPayloads(unit.TestCase):
    def test_uuid_hex_to_byte_conversions(self):
        payload_cls = token_formatters.BasePayload

        expected_hex_uuid = uuid.uuid4().hex
        uuid_obj = uuid.UUID(expected_hex_uuid)
        expected_uuid_in_bytes = uuid_obj.bytes
        actual_uuid_in_bytes = payload_cls.convert_uuid_hex_to_bytes(
            expected_hex_uuid)
        self.assertEqual(expected_uuid_in_bytes, actual_uuid_in_bytes)
        actual_hex_uuid = payload_cls.convert_uuid_bytes_to_hex(
            expected_uuid_in_bytes)
        self.assertEqual(expected_hex_uuid, actual_hex_uuid)

    def test_time_string_to_int_conversions(self):
        payload_cls = token_formatters.BasePayload

        expected_time_str = utils.isotime(subsecond=True)
        time_obj = timeutils.parse_isotime(expected_time_str)
        expected_time_int = (
            (timeutils.normalize_time(time_obj) -
             datetime.datetime.utcfromtimestamp(0)).total_seconds())

        actual_time_int = payload_cls._convert_time_string_to_int(
            expected_time_str)
        self.assertEqual(expected_time_int, actual_time_int)

        actual_time_str = payload_cls._convert_int_to_time_string(
            actual_time_int)
        self.assertEqual(expected_time_str, actual_time_str)

    def test_unscoped_payload(self):
        exp_user_id = uuid.uuid4().hex
        exp_methods = ['password']
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = token_formatters.UnscopedPayload.assemble(
            exp_user_id, exp_methods, exp_expires_at, exp_audit_ids)

        (user_id, methods, expires_at, audit_ids) = (
            token_formatters.UnscopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)

    def test_project_scoped_payload(self):
        exp_user_id = uuid.uuid4().hex
        exp_methods = ['password']
        exp_project_id = uuid.uuid4().hex
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = token_formatters.ProjectScopedPayload.assemble(
            exp_user_id, exp_methods, exp_project_id, exp_expires_at,
            exp_audit_ids)

        (user_id, methods, project_id, expires_at, audit_ids) = (
            token_formatters.ProjectScopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_project_id, project_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)

    def test_domain_scoped_payload(self):
        exp_user_id = uuid.uuid4().hex
        exp_methods = ['password']
        exp_domain_id = uuid.uuid4().hex
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = token_formatters.DomainScopedPayload.assemble(
            exp_user_id, exp_methods, exp_domain_id, exp_expires_at,
            exp_audit_ids)

        (user_id, methods, domain_id, expires_at, audit_ids) = (
            token_formatters.DomainScopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_domain_id, domain_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)

    def test_domain_scoped_payload_with_default_domain(self):
        exp_user_id = uuid.uuid4().hex
        exp_methods = ['password']
        exp_domain_id = CONF.identity.default_domain_id
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = token_formatters.DomainScopedPayload.assemble(
            exp_user_id, exp_methods, exp_domain_id, exp_expires_at,
            exp_audit_ids)

        (user_id, methods, domain_id, expires_at, audit_ids) = (
            token_formatters.DomainScopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_domain_id, domain_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)

    def test_trust_scoped_payload(self):
        exp_user_id = uuid.uuid4().hex
        exp_methods = ['password']
        exp_project_id = uuid.uuid4().hex
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]
        exp_trust_id = uuid.uuid4().hex

        payload = token_formatters.TrustScopedPayload.assemble(
            exp_user_id, exp_methods, exp_project_id, exp_expires_at,
            exp_audit_ids, exp_trust_id)

        (user_id, methods, project_id, expires_at, audit_ids, trust_id) = (
            token_formatters.TrustScopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_project_id, project_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)
        self.assertEqual(exp_trust_id, trust_id)

    def _test_unscoped_payload_with_user_id(self, exp_user_id):
        exp_methods = ['password']
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = token_formatters.UnscopedPayload.assemble(
            exp_user_id, exp_methods, exp_expires_at, exp_audit_ids)

        (user_id, methods, expires_at, audit_ids) = (
            token_formatters.UnscopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)

    def test_unscoped_payload_with_non_uuid_user_id(self):
        self._test_unscoped_payload_with_user_id('someNonUuidUserId')

    def test_unscoped_payload_with_16_char_non_uuid_user_id(self):
        self._test_unscoped_payload_with_user_id('0123456789abcdef')

    def _test_project_scoped_payload_with_ids(self, exp_user_id,
                                              exp_project_id):
        exp_methods = ['password']
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = token_formatters.ProjectScopedPayload.assemble(
            exp_user_id, exp_methods, exp_project_id, exp_expires_at,
            exp_audit_ids)

        (user_id, methods, project_id, expires_at, audit_ids) = (
            token_formatters.ProjectScopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_project_id, project_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)

    def test_project_scoped_payload_with_non_uuid_user_id(self):
        self._test_project_scoped_payload_with_ids('someNonUuidUserId',
                                                   'someNonUuidProjectId')

    def test_project_scoped_payload_with_16_char_non_uuid_user_id(self):
        self._test_project_scoped_payload_with_ids('0123456789abcdef',
                                                   '0123456789abcdef')

    def _test_domain_scoped_payload_with_user_id(self, exp_user_id):
        exp_methods = ['password']
        exp_domain_id = uuid.uuid4().hex
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = token_formatters.DomainScopedPayload.assemble(
            exp_user_id, exp_methods, exp_domain_id, exp_expires_at,
            exp_audit_ids)

        (user_id, methods, domain_id, expires_at, audit_ids) = (
            token_formatters.DomainScopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_domain_id, domain_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)

    def test_domain_scoped_payload_with_non_uuid_user_id(self):
        self._test_domain_scoped_payload_with_user_id('nonUuidUserId')

    def test_domain_scoped_payload_with_16_char_non_uuid_user_id(self):
        self._test_domain_scoped_payload_with_user_id('0123456789abcdef')

    def _test_trust_scoped_payload_with_ids(self, exp_user_id, exp_project_id):
        exp_methods = ['password']
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]
        exp_trust_id = uuid.uuid4().hex

        payload = token_formatters.TrustScopedPayload.assemble(
            exp_user_id, exp_methods, exp_project_id, exp_expires_at,
            exp_audit_ids, exp_trust_id)

        (user_id, methods, project_id, expires_at, audit_ids, trust_id) = (
            token_formatters.TrustScopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_project_id, project_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)
        self.assertEqual(exp_trust_id, trust_id)

    def test_trust_scoped_payload_with_non_uuid_user_id(self):
        self._test_trust_scoped_payload_with_ids('someNonUuidUserId',
                                                 'someNonUuidProjectId')

    def test_trust_scoped_payload_with_16_char_non_uuid_user_id(self):
        self._test_trust_scoped_payload_with_ids('0123456789abcdef',
                                                 '0123456789abcdef')

    def _test_federated_payload_with_ids(self, exp_user_id, exp_group_id):
        exp_methods = ['password']
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]
        exp_federated_info = {'group_ids': [{'id': exp_group_id}],
                              'idp_id': uuid.uuid4().hex,
                              'protocol_id': uuid.uuid4().hex}

        payload = token_formatters.FederatedUnscopedPayload.assemble(
            exp_user_id, exp_methods, exp_expires_at, exp_audit_ids,
            exp_federated_info)

        (user_id, methods, expires_at, audit_ids, federated_info) = (
            token_formatters.FederatedUnscopedPayload.disassemble(payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)
        self.assertEqual(exp_federated_info['group_ids'][0]['id'],
                         federated_info['group_ids'][0]['id'])
        self.assertEqual(exp_federated_info['idp_id'],
                         federated_info['idp_id'])
        self.assertEqual(exp_federated_info['protocol_id'],
                         federated_info['protocol_id'])

    def test_federated_payload_with_non_uuid_ids(self):
        self._test_federated_payload_with_ids('someNonUuidUserId',
                                              'someNonUuidGroupId')

    def test_federated_payload_with_16_char_non_uuid_ids(self):
        self._test_federated_payload_with_ids('0123456789abcdef',
                                              '0123456789abcdef')

    def test_federated_project_scoped_payload(self):
        exp_user_id = 'someNonUuidUserId'
        exp_methods = ['token']
        exp_project_id = uuid.uuid4().hex
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]
        exp_federated_info = {'group_ids': [{'id': 'someNonUuidGroupId'}],
                              'idp_id': uuid.uuid4().hex,
                              'protocol_id': uuid.uuid4().hex}

        payload = token_formatters.FederatedProjectScopedPayload.assemble(
            exp_user_id, exp_methods, exp_project_id, exp_expires_at,
            exp_audit_ids, exp_federated_info)

        (user_id, methods, project_id, expires_at, audit_ids,
         federated_info) = (
            token_formatters.FederatedProjectScopedPayload.disassemble(
                payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_project_id, project_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)
        self.assertDictEqual(exp_federated_info, federated_info)

    def test_federated_domain_scoped_payload(self):
        exp_user_id = 'someNonUuidUserId'
        exp_methods = ['token']
        exp_domain_id = uuid.uuid4().hex
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]
        exp_federated_info = {'group_ids': [{'id': 'someNonUuidGroupId'}],
                              'idp_id': uuid.uuid4().hex,
                              'protocol_id': uuid.uuid4().hex}

        payload = token_formatters.FederatedDomainScopedPayload.assemble(
            exp_user_id, exp_methods, exp_domain_id, exp_expires_at,
            exp_audit_ids, exp_federated_info)

        (user_id, methods, domain_id, expires_at, audit_ids,
         federated_info) = (
            token_formatters.FederatedDomainScopedPayload.disassemble(
                payload))

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertEqual(exp_domain_id, domain_id)
        self.assertEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)
        self.assertDictEqual(exp_federated_info, federated_info)


class TestFernetKeyRotation(unit.TestCase):
    def setUp(self):
        super(TestFernetKeyRotation, self).setUp()

        # A collection of all previously-seen signatures of the key
        # repository's contents.
        self.key_repo_signatures = set()

    @property
    def keys(self):
        """Key files converted to numbers."""
        return sorted(
            int(x) for x in os.listdir(CONF.fernet_tokens.key_repository))

    @property
    def key_repository_size(self):
        """The number of keys in the key repository."""
        return len(self.keys)

    @property
    def key_repository_signature(self):
        """Create a "thumbprint" of the current key repository.

        Because key files are renamed, this produces a hash of the contents of
        the key files, ignoring their filenames.

        The resulting signature can be used, for example, to ensure that you
        have a unique set of keys after you perform a key rotation (taking a
        static set of keys, and simply shuffling them, would fail such a test).

        """
        # Load the keys into a list.
        keys = fernet_utils.load_keys()

        # Sort the list of keys by the keys themselves (they were previously
        # sorted by filename).
        keys.sort()

        # Create the thumbprint using all keys in the repository.
        signature = hashlib.sha1()
        for key in keys:
            signature.update(key)
        return signature.hexdigest()

    def assertRepositoryState(self, expected_size):
        """Validate the state of the key repository."""
        self.assertEqual(expected_size, self.key_repository_size)
        self.assertUniqueRepositoryState()

    def assertUniqueRepositoryState(self):
        """Ensures that the current key repo state has not been seen before."""
        # This is assigned to a variable because it takes some work to
        # calculate.
        signature = self.key_repository_signature

        # Ensure the signature is not in the set of previously seen signatures.
        self.assertNotIn(signature, self.key_repo_signatures)

        # Add the signature to the set of repository signatures to validate
        # that we don't see it again later.
        self.key_repo_signatures.add(signature)

    def test_rotation(self):
        # Initializing a key repository results in this many keys. We don't
        # support max_active_keys being set any lower.
        min_active_keys = 2

        # Simulate every rotation strategy up to "rotating once a week while
        # maintaining a year's worth of keys."
        for max_active_keys in range(min_active_keys, 52 + 1):
            self.config_fixture.config(group='fernet_tokens',
                                       max_active_keys=max_active_keys)

            # Ensure that resetting the key repository always results in 2
            # active keys.
            self.useFixture(ksfixtures.KeyRepository(self.config_fixture))

            # Validate the initial repository state.
            self.assertRepositoryState(expected_size=min_active_keys)

            # The repository should be initialized with a staged key (0) and a
            # primary key (1). The next key is just auto-incremented.
            exp_keys = [0, 1]
            next_key_number = exp_keys[-1] + 1  # keep track of next key
            self.assertEqual(exp_keys, self.keys)

            # Rotate the keys just enough times to fully populate the key
            # repository.
            for rotation in range(max_active_keys - min_active_keys):
                fernet_utils.rotate_keys()
                self.assertRepositoryState(expected_size=rotation + 3)

                exp_keys.append(next_key_number)
                next_key_number += 1
                self.assertEqual(exp_keys, self.keys)

            # We should have a fully populated key repository now.
            self.assertEqual(max_active_keys, self.key_repository_size)

            # Rotate an additional number of times to ensure that we maintain
            # the desired number of active keys.
            for rotation in range(10):
                fernet_utils.rotate_keys()
                self.assertRepositoryState(expected_size=max_active_keys)

                exp_keys.pop(1)
                exp_keys.append(next_key_number)
                next_key_number += 1
                self.assertEqual(exp_keys, self.keys)

    def test_non_numeric_files(self):
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))
        evil_file = os.path.join(CONF.fernet_tokens.key_repository, '99.bak')
        with open(evil_file, 'w'):
            pass
        fernet_utils.rotate_keys()
        self.assertTrue(os.path.isfile(evil_file))
        keys = 0
        for x in os.listdir(CONF.fernet_tokens.key_repository):
            if x == '99.bak':
                continue
            keys += 1
        self.assertEqual(3, keys)


class TestLoadKeys(unit.TestCase):
    def test_non_numeric_files(self):
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))
        evil_file = os.path.join(CONF.fernet_tokens.key_repository, '~1')
        with open(evil_file, 'w'):
            pass
        keys = fernet_utils.load_keys()
        self.assertEqual(2, len(keys))
        self.assertTrue(len(keys[0]))
