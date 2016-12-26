# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

from keystone.assignment import schema as assignment_schema
from keystone.catalog import schema as catalog_schema
from keystone.common.validation import validators
from keystone import exception
from keystone.identity import schema as identity_schema
from keystone.resource import schema as resource_schema
from keystone.tests import unit


_INVALID_NAMES = [True, 24, ' ', '']

_VALID_ENABLED_FORMATS = [True, False]

_INVALID_ENABLED_FORMATS = ['some string', 1, 0, 'True', 'False']


class RoleValidationTestCase(unit.BaseTestCase):
    """Test for V2 Roles API Validation."""

    def setUp(self):
        super(RoleValidationTestCase, self).setUp()

        schema_role_create = assignment_schema.role_create
        self.create_validator = validators.SchemaValidator(schema_role_create)

    def test_validate_role_create_succeeds(self):
        request = {
            'name': uuid.uuid4().hex
        }
        self.create_validator.validate(request)

    def test_validate_role_create_succeeds_with_extra_params(self):
        request = {
            'name': uuid.uuid4().hex,
            'asdf': uuid.uuid4().hex
        }
        self.create_validator.validate(request)

    def test_validate_role_create_fails_with_invalid_params(self):
        request = {
            'bogus': uuid.uuid4().hex
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_role_create_fails_with_no_params(self):
        request = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_role_create_fails_with_invalid_name(self):
        """Exception when validating a create request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_validator.validate,
                              request_to_validate)


class TenantValidationTestCase(unit.BaseTestCase):
    """Test for v2 Tenant API Validation."""

    def setUp(self):
        super(TenantValidationTestCase, self).setUp()
        schema_tenant_create = resource_schema.tenant_create
        schema_tenant_update = resource_schema.tenant_update
        self.create_validator = validators.SchemaValidator(
            schema_tenant_create)
        self.update_validator = validators.SchemaValidator(
            schema_tenant_update)

    def test_validate_tenant_create_success(self):
        request = {
            'name': uuid.uuid4().hex
        }
        self.create_validator.validate(request)

    def test_validate_tenant_create_success_with_empty_description(self):
        request = {
            'name': uuid.uuid4().hex,
            'description': ''
        }
        self.create_validator.validate(request)

    def test_validate_tenant_create_success_with_extra_parameters(self):
        request = {
            'name': uuid.uuid4().hex,
            'description': 'Test tenant',
            'enabled': True,
            'extra': 'test'
        }
        self.create_validator.validate(request)

    def test_validate_tenant_create_failure_with_missing_name(self):
        request = {
            'description': 'Test tenant',
            'enabled': True
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_tenant_create_fails_with_invalid_name(self):
        """Exception when validating a create request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_validator.validate,
                              request)

    def test_validate_tenant_create_failure_with_empty_request(self):
        request = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_tenant_create_failure_with_is_domain(self):
        request = {
            'name': uuid.uuid4().hex,
            'description': 'Test tenant',
            'enabled': True,
            'is_domain': False
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_tenant_create_with_enabled(self):
        """Validate `enabled` as boolean-like values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': valid_enabled
            }
            self.create_validator.validate(request)

    def test_validate_tenant_create_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': invalid_enabled
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.create_validator.validate,
                              request)

    def test_validate_tenant_update_success(self):
        request = {
            'name': uuid.uuid4().hex,
            'description': 'Test tenant',
            'enabled': True
        }
        self.update_validator.validate(request)

    def test_validate_tenant_update_success_with_optional_ids(self):
        request = {
            'name': uuid.uuid4().hex,
            'description': 'Test tenant',
            'enabled': True,
            'tenantId': uuid.uuid4().hex,
            'id': uuid.uuid4().hex
        }
        self.update_validator.validate(request)

    def test_validate_tenant_update_with_domain_id(self):
        request = {
            'name': uuid.uuid4().hex,
            'domain_id': uuid.uuid4().hex
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.update_validator.validate,
                          request)

    def test_validate_tenant_update_with_is_domain(self):
        request = {
            'name': uuid.uuid4().hex,
            'is_domain': False
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.update_validator.validate,
                          request)

    def test_validate_tenant_update_with_empty_request(self):
        request = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_validator.validate,
                          request)

    def test_validate_tenant_update_fails_with_invalid_name(self):
        """Exception when validating an update request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_validator.validate,
                              request)

    def test_validate_tenant_update_with_enabled(self):
        """Validate `enabled` as boolean-like values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': valid_enabled
            }
            self.update_validator.validate(request)

    def test_validate_tenant_update_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': invalid_enabled
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.update_validator.validate,
                              request)


class ServiceValidationTestCase(unit.BaseTestCase):
    """Test for V2 Service API Validation."""

    def setUp(self):
        super(ServiceValidationTestCase, self).setUp()

        schema_create = catalog_schema.service_create
        self.create_validator = validators.SchemaValidator(schema_create)

    def test_validate_service_create_succeeds(self):
        request = {
            'name': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'description': uuid.uuid4().hex
        }
        self.create_validator.validate(request)

    def test_validate_service_create_fails_with_invalid_params(self):
        request = {
            'bogus': uuid.uuid4().hex
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_service_create_fails_with_invalid_name(self):
        for invalid_name in _INVALID_NAMES:
            request = {
                'type': uuid.uuid4().hex,
                'name': invalid_name
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.create_validator.validate,
                              request)

    def test_validate_service_create_with_enabled(self):
        """Validate `enabled` as boolean-like values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request = {
                'type': uuid.uuid4().hex,
                'enabled': valid_enabled
            }
            self.create_validator.validate(request)

    def test_validate_service_create_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request = {
                'type': uuid.uuid4().hex,
                'enabled': invalid_enabled
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.create_validator.validate,
                              request)

    def test_validate_service_create_with_invalid_type(self):
        request = {
            'type': -42
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_service_create_with_type_too_large(self):
        request = {
            'type': 'a' * 256
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)


class UserValidationTestCase(unit.BaseTestCase):
    """Test for V2 User API Validation."""

    def setUp(self):
        super(UserValidationTestCase, self).setUp()

        schema_user_create = identity_schema.user_create_v2
        schema_user_update = identity_schema.user_update_v2
        self.create_validator = validators.SchemaValidator(schema_user_create)
        self.update_validator = validators.SchemaValidator(schema_user_update)

    def test_validate_user_create_succeeds_with_name(self):
        request = {
            'name': uuid.uuid4().hex
        }
        self.create_validator.validate(request)

    def test_validate_user_create_succeeds_with_username(self):
        request = {
            'username': uuid.uuid4().hex
        }
        self.create_validator.validate(request)

    def test_validate_user_create_fails_with_invalid_params(self):
        request = {
            'bogus': uuid.uuid4().hex
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)

    def test_validate_user_create_fails_with_invalid_name(self):
        for invalid_name in _INVALID_NAMES:
            request = {
                'name': invalid_name
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.create_validator.validate,
                              request)

    def test_validate_user_create_with_enabled(self):
        """Validate `enabled` as boolean-like values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': valid_enabled
            }
            self.create_validator.validate(request)

    def test_validate_user_create_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': invalid_enabled
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.create_validator.validate,
                              request)

    def test_validate_user_update_succeeds_with_name(self):
        request = {
            'name': uuid.uuid4().hex,
            'enabled': True
        }
        self.update_validator.validate(request)

    def test_validate_user_update_succeeds_with_username(self):
        request = {
            'username': uuid.uuid4().hex,
            'enabled': True
        }
        self.update_validator.validate(request)

    def test_validate_user_update_succeeds_with_no_params(self):
        request = {}
        self.update_validator.validate(request)

    def test_validate_user_update_fails_with_invalid_name(self):
        for invalid_name in _INVALID_NAMES:
            request = {
                'name': invalid_name
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.update_validator.validate,
                              request)

    def test_validate_user_update_with_enabled(self):
        """Validate `enabled` as boolean-like values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': valid_enabled
            }
            self.update_validator.validate(request)

    def test_validate_user_update_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request = {
                'name': uuid.uuid4().hex,
                'enabled': invalid_enabled
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.update_validator.validate,
                              request)
