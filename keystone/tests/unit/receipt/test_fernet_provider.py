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
from unittest import mock
import uuid

from oslo_utils import timeutils

from keystone.common import fernet_utils
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.identity.backends import resource_options as ro
from keystone.receipt.providers import fernet
from keystone.receipt import receipt_formatters
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone.token import provider as token_provider


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TestFernetReceiptProvider(unit.TestCase):
    def setUp(self):
        super(TestFernetReceiptProvider, self).setUp()
        self.provider = fernet.Provider()

    def test_invalid_receipt_raises_receipt_not_found(self):
        receipt_id = uuid.uuid4().hex
        e = self.assertRaises(
            exception.ReceiptNotFound,
            self.provider.validate_receipt,
            receipt_id)
        self.assertIn(receipt_id, u'%s' % e)


class TestValidate(unit.TestCase):
    def setUp(self):
        super(TestValidate, self).setUp()
        self.useFixture(database.Database())
        self.useFixture(
            ksfixtures.ConfigAuthPlugins(
                self.config_fixture,
                ['totp', 'token', 'password']))
        self.load_backends()
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)

    def config_overrides(self):
        super(TestValidate, self).config_overrides()
        self.config_fixture.config(group='receipt', provider='fernet')

    def test_validate_v3_receipt_simple(self):
        # Check the fields in the receipt result when use validate_v3_receipt
        # with a simple receipt.

        domain_ref = unit.new_domain_ref()
        domain_ref = PROVIDERS.resource_api.create_domain(
            domain_ref['id'], domain_ref
        )

        rule_list = [
            ['password', 'totp'],
            ['password', 'totp', 'token'],
        ]

        user_ref = unit.new_user_ref(domain_ref['id'])
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        user_ref['options'][ro.MFA_RULES_OPT.option_name] = rule_list
        user_ref['options'][ro.MFA_ENABLED_OPT.option_name] = True
        PROVIDERS.identity_api.update_user(user_ref['id'], user_ref)

        method_names = ['password']
        receipt = PROVIDERS.receipt_provider_api.\
            issue_receipt(user_ref['id'], method_names)

        receipt = PROVIDERS.receipt_provider_api.validate_receipt(
            receipt.id)
        self.assertIsInstance(receipt.expires_at, str)
        self.assertIsInstance(receipt.issued_at, str)
        self.assertEqual(set(method_names), set(receipt.methods))
        self.assertEqual(
            set(frozenset(r) for r in rule_list),
            set(frozenset(r) for r in
                receipt.required_methods))
        self.assertEqual(user_ref['id'], receipt.user_id)

    def test_validate_v3_receipt_validation_error_exc(self):
        # When the receipt format isn't recognized, ReceiptNotFound is raised.

        # A uuid string isn't a valid Fernet receipt.
        receipt_id = uuid.uuid4().hex
        self.assertRaises(
            exception.ReceiptNotFound,
            PROVIDERS.receipt_provider_api.validate_receipt,
            receipt_id
        )


class TestReceiptFormatter(unit.TestCase):
    def test_restore_padding(self):
        # 'a' will result in '==' padding, 'aa' will result in '=' padding, and
        # 'aaa' will result in no padding.
        binary_to_test = [b'a', b'aa', b'aaa']

        for binary in binary_to_test:
            # base64.urlsafe_b64encode takes bytes and returns
            # bytes.
            encoded_string = base64.urlsafe_b64encode(binary)
            encoded_string = encoded_string.decode('utf-8')
            # encoded_string is now str.
            encoded_str_without_padding = encoded_string.rstrip('=')
            self.assertFalse(encoded_str_without_padding.endswith('='))
            encoded_str_with_padding_restored = (
                receipt_formatters.ReceiptFormatter.restore_padding(
                    encoded_str_without_padding)
            )
            self.assertEqual(encoded_string, encoded_str_with_padding_restored)


class TestPayloads(unit.TestCase):

    def setUp(self):
        super(TestPayloads, self).setUp()
        self.useFixture(
            ksfixtures.ConfigAuthPlugins(
                self.config_fixture, ['totp', 'token', 'password']))

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
        s = token_provider.random_urlsafe_str()
        self.assertIsInstance(s, str)

        b = receipt_formatters.ReceiptPayload.random_urlsafe_str_to_bytes(s)
        self.assertIsInstance(b, bytes)

    def test_uuid_hex_to_byte_conversions(self):
        payload_cls = receipt_formatters.ReceiptPayload

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
        payload_cls = receipt_formatters.ReceiptPayload

        original_time_str = utils.isotime(subsecond=True)
        time_obj = timeutils.parse_isotime(original_time_str)
        expected_time_float = (
            (timeutils.normalize_time(time_obj) -
             datetime.datetime.utcfromtimestamp(0)).total_seconds())

        # NOTE(lbragstad): The receipt expiration time for Fernet receipts is
        # passed in the payload of the receipt. This is different from the
        # receipt creation time, which is handled by Fernet and doesn't support
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

    def _test_payload(self, payload_class, exp_user_id=None, exp_methods=None):
        exp_user_id = exp_user_id or uuid.uuid4().hex
        exp_methods = exp_methods or ['password']
        exp_expires_at = utils.isotime(timeutils.utcnow(), subsecond=True)

        payload = payload_class.assemble(
            exp_user_id, exp_methods, exp_expires_at)

        (user_id, methods, expires_at) = payload_class.disassemble(payload)

        self.assertEqual(exp_user_id, user_id)
        self.assertEqual(exp_methods, methods)
        self.assertTimestampsEqual(exp_expires_at, expires_at)

    def test_payload(self):
        self._test_payload(receipt_formatters.ReceiptPayload)

    def test_payload_multiple_methods(self):
        self._test_payload(
            receipt_formatters.ReceiptPayload,
            exp_methods=['password', 'totp'])


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
            int(x) for x in os.listdir(CONF.fernet_receipts.key_repository))

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
        # Load the keys into a list, keys is list of str.
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_receipts.key_repository,
            CONF.fernet_receipts.max_active_keys,
            'fernet_receipts'
        )
        keys = key_utils.load_keys()

        # Sort the list of keys by the keys themselves (they were previously
        # sorted by filename).
        keys.sort()

        # Create the thumbprint using all keys in the repository.
        signature = hashlib.sha1()
        for key in keys:
            # Need to convert key to bytes for update.
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
            self.config_fixture.config(group='fernet_receipts',
                                       max_active_keys=max_active_keys)

            # Ensure that resetting the key repository always results in 2
            # active keys.
            self.useFixture(
                ksfixtures.KeyRepository(
                    self.config_fixture,
                    'fernet_receipts',
                    CONF.fernet_receipts.max_active_keys
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
                CONF.fernet_receipts.key_repository,
                CONF.fernet_receipts.max_active_keys,
                'fernet_receipts'
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
                CONF.fernet_receipts.key_repository,
                CONF.fernet_receipts.max_active_keys,
                'fernet_receipts'
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
            CONF.fernet_receipts.key_repository,
            CONF.fernet_receipts.max_active_keys,
            'fernet_receipts'
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
        empty_file = os.path.join(CONF.fernet_receipts.key_repository, '2')
        with open(empty_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_receipts.key_repository,
            CONF.fernet_receipts.max_active_keys,
            'fernet_receipts'
        )
        # Rotate the keys to overwrite the empty file
        key_utils.rotate_keys()
        self.assertTrue(os.path.isfile(empty_file))
        keys = key_utils.load_keys()
        self.assertEqual(3, len(keys))
        self.assertTrue(os.path.getsize(empty_file) > 0)

    def test_non_numeric_files(self):
        evil_file = os.path.join(CONF.fernet_receipts.key_repository, '99.bak')
        with open(evil_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_receipts.key_repository,
            CONF.fernet_receipts.max_active_keys,
            'fernet_receipts'
        )
        key_utils.rotate_keys()
        self.assertTrue(os.path.isfile(evil_file))
        keys = 0
        for x in os.listdir(CONF.fernet_receipts.key_repository):
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
        evil_file = os.path.join(CONF.fernet_receipts.key_repository, '~1')
        with open(evil_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_receipts.key_repository,
            CONF.fernet_receipts.max_active_keys,
            'fernet_receipts'
        )
        keys = key_utils.load_keys()
        self.assertEqual(2, len(keys))
        self.assertValidFernetKeys(keys)

    def test_empty_files(self):
        empty_file = os.path.join(CONF.fernet_receipts.key_repository, '2')
        with open(empty_file, 'w'):
            pass
        key_utils = fernet_utils.FernetUtils(
            CONF.fernet_receipts.key_repository,
            CONF.fernet_receipts.max_active_keys,
            'fernet_receipts'
        )
        keys = key_utils.load_keys()
        self.assertEqual(2, len(keys))
        self.assertValidFernetKeys(keys)
