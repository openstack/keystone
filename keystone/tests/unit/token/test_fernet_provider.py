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
import mock
import os
import uuid

from oslo_utils import timeutils
import six

from keystone import auth
from keystone.common import fernet_utils
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone.token import provider
from keystone.token.providers import fernet
from keystone.token import token_formatters


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TestFernetTokenProvider(unit.TestCase):
    def setUp(self):
        super(TestFernetTokenProvider, self).setUp()
        self.provider = fernet.Provider()

    def test_invalid_token_raises_token_not_found(self):
        token_id = uuid.uuid4().hex
        e = self.assertRaises(
            exception.TokenNotFound,
            self.provider.validate_token,
            token_id)
        self.assertIn(token_id, u'%s' % e)


class TestValidate(unit.TestCase):
    def setUp(self):
        super(TestValidate, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

    def config_overrides(self):
        super(TestValidate, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')

    def test_validate_v3_token_simple(self):
        # Check the fields in the token result when use validate_v3_token
        # with a simple token.

        domain_ref = unit.new_domain_ref()
        domain_ref = PROVIDERS.resource_api.create_domain(
            domain_ref['id'], domain_ref
        )

        user_ref = unit.new_user_ref(domain_ref['id'])
        user_ref = PROVIDERS.identity_api.create_user(user_ref)

        method_names = ['password']
        token = PROVIDERS.token_provider_api.issue_token(
            user_ref['id'], method_names)

        token = PROVIDERS.token_provider_api.validate_token(token.id)
        self.assertIsInstance(token.audit_ids, list)
        self.assertIsInstance(token.expires_at, str)
        self.assertIsInstance(token.issued_at, str)
        self.assertEqual(method_names, token.methods)
        self.assertEqual(user_ref['id'], token.user_id)
        self.assertEqual(user_ref['name'], token.user['name'])
        self.assertDictEqual(domain_ref, token.user_domain)
        self.assertEqual(
            user_ref['password_expires_at'], token.user['password_expires_at']
        )

    def test_validate_v3_token_federated_info(self):
        # Check the user fields in the token result when use validate_v3_token
        # when the token has federated info.

        domain_ref = unit.new_domain_ref()
        domain_ref = PROVIDERS.resource_api.create_domain(
            domain_ref['id'], domain_ref
        )

        user_ref = unit.new_user_ref(domain_ref['id'])
        user_ref = PROVIDERS.identity_api.create_user(user_ref)

        method_names = ['mapped']

        group_ids = [uuid.uuid4().hex, ]
        idp_id = uuid.uuid4().hex
        idp_ref = {
            'id': idp_id,
            'description': uuid.uuid4().hex,
            'enabled': True
        }
        self.federation_api.create_idp(idp_id, idp_ref)
        protocol = uuid.uuid4().hex
        auth_context_params = {
            'user_id': user_ref['id'],
            'user_name': user_ref['name'],
            'group_ids': group_ids,
            federation_constants.IDENTITY_PROVIDER: idp_id,
            federation_constants.PROTOCOL: protocol,
        }
        auth_context = auth.core.AuthContext(**auth_context_params)
        token = PROVIDERS.token_provider_api.issue_token(
            user_ref['id'], method_names, auth_context=auth_context)

        token = PROVIDERS.token_provider_api.validate_token(token.id)

        self.assertEqual(user_ref['id'], token.user_id)
        self.assertEqual(user_ref['name'], token.user['name'])
        self.assertDictEqual(domain_ref, token.user_domain)
        exp_group_ids = [{'id': group_id} for group_id in group_ids]
        self.assertEqual(exp_group_ids, token.federated_groups)
        self.assertEqual(idp_id, token.identity_provider_id)
        self.assertEqual(protocol, token.protocol_id)

    def test_validate_v3_token_trust(self):
        # Check the trust fields in the token result when use validate_v3_token
        # when the token has trust info.

        domain_ref = unit.new_domain_ref()
        domain_ref = PROVIDERS.resource_api.create_domain(
            domain_ref['id'], domain_ref
        )

        user_ref = unit.new_user_ref(domain_ref['id'])
        user_ref = PROVIDERS.identity_api.create_user(user_ref)

        trustor_user_ref = unit.new_user_ref(domain_ref['id'])
        trustor_user_ref = PROVIDERS.identity_api.create_user(trustor_user_ref)

        project_ref = unit.new_project_ref(domain_id=domain_ref['id'])
        project_ref = PROVIDERS.resource_api.create_project(
            project_ref['id'], project_ref
        )

        role_ref = unit.new_role_ref()
        role_ref = PROVIDERS.role_api.create_role(role_ref['id'], role_ref)

        PROVIDERS.assignment_api.create_grant(
            role_ref['id'], user_id=user_ref['id'],
            project_id=project_ref['id'])

        PROVIDERS.assignment_api.create_grant(
            role_ref['id'], user_id=trustor_user_ref['id'],
            project_id=project_ref['id'])

        trustor_user_id = trustor_user_ref['id']
        trustee_user_id = user_ref['id']
        trust_ref = unit.new_trust_ref(
            trustor_user_id, trustee_user_id, project_id=project_ref['id'],
            role_ids=[role_ref['id'], ])
        trust_ref = PROVIDERS.trust_api.create_trust(
            trust_ref['id'], trust_ref, trust_ref['roles']
        )

        method_names = ['password']

        token = PROVIDERS.token_provider_api.issue_token(
            user_ref['id'], method_names, project_id=project_ref['id'],
            trust_id=trust_ref['id'])

        token = PROVIDERS.token_provider_api.validate_token(token.id)
        self.assertEqual(trust_ref['id'], token.trust_id)
        self.assertFalse(token.trust['impersonation'])
        self.assertEqual(user_ref['id'], token.trustee['id'])
        self.assertEqual(trustor_user_ref['id'], token.trustor['id'])

    def test_validate_v3_token_validation_error_exc(self):
        # When the token format isn't recognized, TokenNotFound is raised.

        # A uuid string isn't a valid Fernet token.
        token_id = uuid.uuid4().hex
        self.assertRaises(
            exception.TokenNotFound,
            PROVIDERS.token_provider_api.validate_token,
            token_id
        )


class TestTokenFormatter(unit.TestCase):
    def test_restore_padding(self):
        # 'a' will result in '==' padding, 'aa' will result in '=' padding, and
        # 'aaa' will result in no padding.
        binary_to_test = [b'a', b'aa', b'aaa']

        for binary in binary_to_test:
            # base64.urlsafe_b64encode takes six.binary_type and returns
            # six.binary_type.
            encoded_string = base64.urlsafe_b64encode(binary)
            encoded_string = encoded_string.decode('utf-8')
            # encoded_string is now six.text_type.
            encoded_str_without_padding = encoded_string.rstrip('=')
            self.assertFalse(encoded_str_without_padding.endswith('='))
            encoded_str_with_padding_restored = (
                token_formatters.TokenFormatter.restore_padding(
                    encoded_str_without_padding)
            )
            self.assertEqual(encoded_string, encoded_str_with_padding_restored)


class TestPayloads(unit.TestCase):
    def assertTimestampsEqual(self, expected, actual):
        # The timestamp that we get back when parsing the payload may not
        # exactly match the timestamp that was put in the payload due to
        # conversion to and from a float.

        exp_time = timeutils.parse_isotime(expected)
        actual_time = timeutils.parse_isotime(actual)

        # the granularity of timestamp string is microseconds and it's only the
        # last digit in the representation that's different, so use a delta
        # just above nanoseconds.
        return self.assertCloseEnoughForGovernmentWork(exp_time, actual_time,
                                                       delta=1e-05)

    def test_strings_can_be_converted_to_bytes(self):
        s = provider.random_urlsafe_str()
        self.assertIsInstance(s, six.text_type)

        b = token_formatters.BasePayload.random_urlsafe_str_to_bytes(s)
        self.assertIsInstance(b, six.binary_type)

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

    def test_time_string_to_float_conversions(self):
        payload_cls = token_formatters.BasePayload

        original_time_str = utils.isotime(subsecond=True)
        time_obj = timeutils.parse_isotime(original_time_str)
        expected_time_float = (
            (timeutils.normalize_time(time_obj) -
             datetime.datetime.utcfromtimestamp(0)).total_seconds())

        # NOTE(lbragstad): The token expiration time for Fernet tokens is
        # passed in the payload of the token. This is different from the token
        # creation time, which is handled by Fernet and doesn't support
        # subsecond precision because it is a timestamp integer.
        self.assertIsInstance(expected_time_float, float)

        actual_time_float = payload_cls._convert_time_string_to_float(
            original_time_str)
        self.assertIsInstance(actual_time_float, float)
        self.assertEqual(expected_time_float, actual_time_float)

        # Generate expected_time_str using the same time float. Using
        # original_time_str from utils.isotime will occasionally fail due to
        # floating point rounding differences.
        time_object = datetime.datetime.utcfromtimestamp(actual_time_float)
        expected_time_str = utils.isotime(time_object, subsecond=True)

        actual_time_str = payload_cls._convert_float_to_time_string(
            actual_time_float)
        self.assertEqual(expected_time_str, actual_time_str)

    def _test_payload(self, payload_class, exp_user_id=None, exp_methods=None,
                      exp_system=None, exp_project_id=None, exp_domain_id=None,
                      exp_trust_id=None, exp_federated_group_ids=None,
                      exp_identity_provider_id=None, exp_protocol_id=None,
                      exp_access_token_id=None, exp_app_cred_id=None):
        exp_user_id = exp_user_id or uuid.uuid4().hex
        exp_methods = exp_methods or ['password']
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)
        exp_audit_ids = [provider.random_urlsafe_str()]

        payload = payload_class.assemble(
            exp_user_id, exp_methods, exp_system, exp_project_id,
            exp_domain_id, exp_expires_at, exp_audit_ids, exp_trust_id,
            exp_federated_group_ids, exp_identity_provider_id, exp_protocol_id,
            exp_access_token_id, exp_app_cred_id)

        (user_id, methods, system, project_id,
         domain_id, expires_at, audit_ids,
         trust_id, federated_group_ids, identity_provider_id, protocol_id,
         access_token_id, app_cred_id) = payload_class.disassemble(payload)

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertTimestampsEqual(exp_expires_at, expires_at)
        self.assertEqual(exp_audit_ids, audit_ids)
        self.assertEqual(exp_system, system)
        self.assertEqual(exp_project_id, project_id)
        self.assertEqual(exp_domain_id, domain_id)
        self.assertEqual(exp_federated_group_ids, federated_group_ids)
        self.assertEqual(exp_identity_provider_id, identity_provider_id)
        self.assertEqual(exp_protocol_id, protocol_id)
        self.assertEqual(exp_trust_id, trust_id)
        self.assertEqual(exp_access_token_id, access_token_id)
        self.assertEqual(exp_app_cred_id, app_cred_id)

    def test_unscoped_payload(self):
        self._test_payload(token_formatters.UnscopedPayload)

    def test_system_scoped_payload(self):
        self._test_payload(token_formatters.SystemScopedPayload,
                           exp_system='all')

    def test_project_scoped_payload(self):
        self._test_payload(token_formatters.ProjectScopedPayload,
                           exp_project_id=uuid.uuid4().hex)

    def test_domain_scoped_payload(self):
        self._test_payload(token_formatters.DomainScopedPayload,
                           exp_domain_id=uuid.uuid4().hex)

    def test_domain_scoped_payload_with_default_domain(self):
        self._test_payload(token_formatters.DomainScopedPayload,
                           exp_domain_id=CONF.identity.default_domain_id)

    def test_trust_scoped_payload(self):
        self._test_payload(token_formatters.TrustScopedPayload,
                           exp_project_id=uuid.uuid4().hex,
                           exp_trust_id=uuid.uuid4().hex)

    def test_unscoped_payload_with_non_uuid_user_id(self):
        self._test_payload(token_formatters.UnscopedPayload,
                           exp_user_id='someNonUuidUserId')

    def test_unscoped_payload_with_16_char_non_uuid_user_id(self):
        self._test_payload(token_formatters.UnscopedPayload,
                           exp_user_id='0123456789abcdef')

    def test_project_scoped_payload_with_non_uuid_ids(self):
        self._test_payload(token_formatters.ProjectScopedPayload,
                           exp_user_id='someNonUuidUserId',
                           exp_project_id='someNonUuidProjectId')

    def test_project_scoped_payload_with_16_char_non_uuid_ids(self):
        self._test_payload(token_formatters.ProjectScopedPayload,
                           exp_user_id='0123456789abcdef',
                           exp_project_id='0123456789abcdef')

    def test_domain_scoped_payload_with_non_uuid_user_id(self):
        self._test_payload(token_formatters.DomainScopedPayload,
                           exp_user_id='nonUuidUserId',
                           exp_domain_id=uuid.uuid4().hex)

    def test_domain_scoped_payload_with_16_char_non_uuid_user_id(self):
        self._test_payload(token_formatters.DomainScopedPayload,
                           exp_user_id='0123456789abcdef',
                           exp_domain_id=uuid.uuid4().hex)

    def test_trust_scoped_payload_with_non_uuid_ids(self):
        self._test_payload(token_formatters.TrustScopedPayload,
                           exp_user_id='someNonUuidUserId',
                           exp_project_id='someNonUuidProjectId',
                           exp_trust_id=uuid.uuid4().hex)

    def test_trust_scoped_payload_with_16_char_non_uuid_ids(self):
        self._test_payload(token_formatters.TrustScopedPayload,
                           exp_user_id='0123456789abcdef',
                           exp_project_id='0123456789abcdef',
                           exp_trust_id=uuid.uuid4().hex)

    def _test_federated_payload_with_ids(self, exp_user_id, exp_group_id):
        exp_federated_group_ids = [{'id': exp_group_id}]
        exp_idp_id = uuid.uuid4().hex
        exp_protocol_id = uuid.uuid4().hex

        self._test_payload(token_formatters.FederatedUnscopedPayload,
                           exp_user_id=exp_user_id,
                           exp_federated_group_ids=exp_federated_group_ids,
                           exp_identity_provider_id=exp_idp_id,
                           exp_protocol_id=exp_protocol_id)

    def test_federated_payload_with_non_uuid_ids(self):
        self._test_federated_payload_with_ids('someNonUuidUserId',
                                              'someNonUuidGroupId')

    def test_federated_payload_with_16_char_non_uuid_ids(self):
        self._test_federated_payload_with_ids('0123456789abcdef',
                                              '0123456789abcdef')

    def test_federated_project_scoped_payload(self):
        exp_federated_group_ids = [{'id': 'someNonUuidGroupId'}]
        exp_idp_id = uuid.uuid4().hex
        exp_protocol_id = uuid.uuid4().hex

        self._test_payload(token_formatters.FederatedProjectScopedPayload,
                           exp_user_id='someNonUuidUserId',
                           exp_methods=['token'],
                           exp_project_id=uuid.uuid4().hex,
                           exp_federated_group_ids=exp_federated_group_ids,
                           exp_identity_provider_id=exp_idp_id,
                           exp_protocol_id=exp_protocol_id)

    def test_federated_domain_scoped_payload(self):
        exp_federated_group_ids = [{'id': 'someNonUuidGroupId'}]
        exp_idp_id = uuid.uuid4().hex
        exp_protocol_id = uuid.uuid4().hex

        self._test_payload(token_formatters.FederatedDomainScopedPayload,
                           exp_user_id='someNonUuidUserId',
                           exp_methods=['token'],
                           exp_domain_id=uuid.uuid4().hex,
                           exp_federated_group_ids=exp_federated_group_ids,
                           exp_identity_provider_id=exp_idp_id,
                           exp_protocol_id=exp_protocol_id)

    def test_oauth_scoped_payload(self):
        self._test_payload(token_formatters.OauthScopedPayload,
                           exp_project_id=uuid.uuid4().hex,
                           exp_access_token_id=uuid.uuid4().hex)

    def test_app_cred_scoped_payload_with_non_uuid_ids(self):
        self._test_payload(token_formatters.ApplicationCredentialScopedPayload,
                           exp_user_id='someNonUuidUserId',
                           exp_project_id='someNonUuidProjectId',
                           exp_app_cred_id='someNonUuidAppCredId')

    def test_app_cred_scoped_payload_with_16_char_non_uuid_ids(self):
        self._test_payload(token_formatters.ApplicationCredentialScopedPayload,
                           exp_user_id='0123456789abcdef',
                           exp_project_id='0123456789abcdef',
                           exp_app_cred_id='0123456789abcdef')


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
        # Load the keys into a list, keys is list of six.text_type.
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_tokens.key_repository,
            CONF.fernet_tokens.max_active_keys,
            'fernet_tokens'
        )
        keys = key_utils.load_keys()

        # Sort the list of keys by the keys themselves (they were previously
        # sorted by filename).
        keys.sort()

        # Create the thumbprint using all keys in the repository.
        signature = hashlib.sha1()
        for key in keys:
            # Need to convert key to six.binary_type for update.
            signature.update(key.encode('utf-8'))
        return signature.hexdigest()

    def assertRepositoryState(self, expected_size):
        """Validate the state of the key repository."""
        self.assertEqual(expected_size, self.key_repository_size)
        self.assertUniqueRepositoryState()

    def assertUniqueRepositoryState(self):
        """Ensure that the current key repo state has not been seen before."""
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
            self.useFixture(
                ksfixtures.KeyRepository(
                    self.config_fixture,
                    'fernet_tokens',
                    CONF.fernet_tokens.max_active_keys
                )
            )

            # Validate the initial repository state.
            self.assertRepositoryState(expected_size=min_active_keys)

            # The repository should be initialized with a staged key (0) and a
            # primary key (1). The next key is just auto-incremented.
            exp_keys = [0, 1]
            next_key_number = exp_keys[-1] + 1  # keep track of next key
            self.assertEqual(exp_keys, self.keys)

            # Rotate the keys just enough times to fully populate the key
            # repository.
            key_utils = fernet_utils.FernetUtils(
                CONF.fernet_tokens.key_repository,
                CONF.fernet_tokens.max_active_keys,
                'fernet_tokens'
            )
            for rotation in range(max_active_keys - min_active_keys):
                key_utils.rotate_keys()
                self.assertRepositoryState(expected_size=rotation + 3)

                exp_keys.append(next_key_number)
                next_key_number += 1
                self.assertEqual(exp_keys, self.keys)

            # We should have a fully populated key repository now.
            self.assertEqual(max_active_keys, self.key_repository_size)

            # Rotate an additional number of times to ensure that we maintain
            # the desired number of active keys.
            key_utils = fernet_utils.FernetUtils(
                CONF.fernet_tokens.key_repository,
                CONF.fernet_tokens.max_active_keys,
                'fernet_tokens'
            )
            for rotation in range(10):
                key_utils.rotate_keys()
                self.assertRepositoryState(expected_size=max_active_keys)

                exp_keys.pop(1)
                exp_keys.append(next_key_number)
                next_key_number += 1
                self.assertEqual(exp_keys, self.keys)

    def test_rotation_disk_write_fail(self):
        # Make sure that the init key repository contains 2 keys
        self.assertRepositoryState(expected_size=2)

        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_tokens.key_repository,
            CONF.fernet_tokens.max_active_keys,
            'fernet_tokens'
        )

        # Simulate the disk full situation
        mock_open = mock.mock_open()
        file_handle = mock_open()
        file_handle.flush.side_effect = IOError('disk full')

        with mock.patch('keystone.common.fernet_utils.open', mock_open):
            self.assertRaises(IOError, key_utils.rotate_keys)

        # Assert that the key repository is unchanged
        self.assertEqual(self.key_repository_size, 2)

        with mock.patch('keystone.common.fernet_utils.open', mock_open):
            self.assertRaises(IOError, key_utils.rotate_keys)

        # Assert that the key repository is still unchanged, even after
        # repeated rotation attempts.
        self.assertEqual(self.key_repository_size, 2)

        # Rotate the keys normally, without any mocking, to show that the
        # system can recover.
        key_utils.rotate_keys()

        # Assert that the key repository is now expanded.
        self.assertEqual(self.key_repository_size, 3)

    def test_rotation_empty_file(self):
        active_keys = 2
        self.assertRepositoryState(expected_size=active_keys)
        empty_file = os.path.join(CONF.fernet_tokens.key_repository, '2')
        with open(empty_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_tokens.key_repository,
            CONF.fernet_tokens.max_active_keys,
            'fernet_tokens'
        )
        # Rotate the keys to overwrite the empty file
        key_utils.rotate_keys()
        self.assertTrue(os.path.isfile(empty_file))
        keys = key_utils.load_keys()
        self.assertEqual(3, len(keys))
        self.assertTrue(os.path.getsize(empty_file) > 0)

    def test_non_numeric_files(self):
        evil_file = os.path.join(CONF.fernet_tokens.key_repository, '99.bak')
        with open(evil_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_tokens.key_repository,
            CONF.fernet_tokens.max_active_keys,
            'fernet_tokens'
        )
        key_utils.rotate_keys()
        self.assertTrue(os.path.isfile(evil_file))
        keys = 0
        for x in os.listdir(CONF.fernet_tokens.key_repository):
            if x == '99.bak':
                continue
            keys += 1
        self.assertEqual(3, keys)


class TestLoadKeys(unit.TestCase):

    def assertValidFernetKeys(self, keys):
        # Make sure each key is a non-empty string
        for key in keys:
            self.assertGreater(len(key), 0)
            self.assertIsInstance(key, str)

    def test_non_numeric_files(self):
        evil_file = os.path.join(CONF.fernet_tokens.key_repository, '~1')
        with open(evil_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_tokens.key_repository,
            CONF.fernet_tokens.max_active_keys,
            'fernet_tokens'
        )
        keys = key_utils.load_keys()
        self.assertEqual(2, len(keys))
        self.assertValidFernetKeys(keys)

    def test_empty_files(self):
        empty_file = os.path.join(CONF.fernet_tokens.key_repository, '2')
        with open(empty_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_tokens.key_repository,
            CONF.fernet_tokens.max_active_keys,
            'fernet_tokens'
        )
        keys = key_utils.load_keys()
        self.assertEqual(2, len(keys))
        self.assertValidFernetKeys(keys)
