# -*- coding: utf-8 -*-
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
from keystone.common.validation import validators
from keystone import exception
from keystone.resource import schema as resource_schema
from keystone.tests import unit


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
        request = {
            'name': 42
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_validator.validate,
                          request)


class TenantValidationTestCase(unit.BaseTestCase):
    """Test for v2 Tenant API Validation."""

    def setUp(self):
        super(TenantValidationTestCase, self).setUp()
        schema_tenant_create = resource_schema.tenant_create
        self.create_validator = validators.SchemaValidator(
            schema_tenant_create)

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

    def test_validate_tenant_create_failure_with_empty_name(self):
        request = {
            'name': '',
            'description': uuid.uuid4().hex,
            'enabled': True
        }
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
