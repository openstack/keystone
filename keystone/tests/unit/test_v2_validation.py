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
