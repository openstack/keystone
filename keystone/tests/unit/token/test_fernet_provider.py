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
import uuid

from oslo_utils import timeutils

from keystone.common import config
from keystone import exception
from keystone.tests import unit as tests
from keystone.tests.unit import ksfixtures
from keystone.token import provider
from keystone.token.providers import fernet
from keystone.token.providers.fernet import token_formatters


CONF = config.CONF


class TestFernetTokenProvider(tests.TestCase):
    def setUp(self):
        super(TestFernetTokenProvider, self).setUp()
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))
        self.provider = fernet.Provider()

    def test_get_token_id_raises_not_implemented(self):
        """Test that an exception is raised when calling _get_token_id."""
        token_data = {}
        self.assertRaises(exception.NotImplemented,
                          self.provider._get_token_id, token_data)

    def test_invalid_v3_token_raises_401(self):
        self.assertRaises(
            exception.Unauthorized,
            self.provider.validate_v3_token,
            uuid.uuid4().hex)

    def test_invalid_v2_token_raises_401(self):
        self.assertRaises(
            exception.Unauthorized,
            self.provider.validate_v2_token,
            uuid.uuid4().hex)


class TestPayloads(tests.TestCase):
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

        expected_time_str = timeutils.isotime()
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
        exp_expires_at = timeutils.isotime(timeutils.utcnow())
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
        exp_expires_at = timeutils.isotime(timeutils.utcnow())
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
        exp_expires_at = timeutils.isotime(timeutils.utcnow())
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
        exp_expires_at = timeutils.isotime(timeutils.utcnow())
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
        exp_expires_at = timeutils.isotime(timeutils.utcnow())
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
