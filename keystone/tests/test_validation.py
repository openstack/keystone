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

from keystone.common.validation import parameter_types
from keystone.common.validation import validators
from keystone import exception
from keystone import tests


# Test schema to validate create requests against
_CREATE = {
    'type': 'object',
    'properties': {
        'name': parameter_types.name,
        'description': parameter_types.description,
        'enabled': parameter_types.boolean,
        'url': parameter_types.url,
        'email': parameter_types.email
    },
    'required': ['name'],
    'additionalProperties': True,
}


class ValidationTestCase(tests.TestCase):

    def setUp(self):
        super(ValidationTestCase, self).setUp()
        self.resource_name = 'some resource name'
        self.description = 'Some valid description'
        self.valid_enabled = True
        self.valid_url = 'http://example.com'
        self.valid_email = 'joe@example.com'
        self.create_schema_validator = validators.SchemaValidator(_CREATE)

    def test_create_schema_with_all_valid_parameters(self):
        """Validate proper values against test schema."""
        request_to_validate = {'name': self.resource_name,
                               'some_uuid': uuid.uuid4().hex,
                               'description': self.description,
                               'enabled': self.valid_enabled,
                               'url': self.valid_url}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_schema_with_name_too_long_raises_exception(self):
        """Validate long names.

        Validate that an exception is raised when validating a string of 255+
        characters passed in as a name.
        """
        invalid_name = ''
        for i in range(255):
            invalid_name = invalid_name + str(i)

        request_to_validate = {'name': invalid_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_schema_validator.validate,
                          request_to_validate)

    def test_create_schema_with_name_too_short_raises_exception(self):
        """Validate short names.

        Test that an exception is raised when passing a string of length
        zero as a name parameter.
        """
        request_to_validate = {'name': ''}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_schema_validator.validate,
                          request_to_validate)

    def test_create_schema_with_unicode_name_is_successful(self):
        """Test that we successfully validate a unicode string."""
        request_to_validate = {'name': u'αβγδ'}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_schema_with_invalid_enabled_format_raises_exception(self):
        """Validate invalid enabled formats.

        Test that an exception is raised when passing invalid boolean-like
        values as `enabled`.
        """
        invalid_enabled_formats = 'some string'
        request_to_validate = {'name': self.resource_name,
                               'enabled': invalid_enabled_formats}

        self.assertRaises(exception.SchemaValidationError,
                          self.create_schema_validator.validate,
                          request_to_validate)

    def test_create_schema_with_valid_enabled_formats(self):
        """Validate valid enabled formats.

        Test that we have successful validation on boolean values for
        `enabled`.
        """
        valid_enabled_formats = [True, False]

        for valid_enabled in valid_enabled_formats:
            request_to_validate = {'name': self.resource_name,
                                   'enabled': valid_enabled}
            # Make sure validation doesn't raise a validation exception
            self.create_schema_validator.validate(request_to_validate)

    def test_create_schema_with_valid_urls(self):
        """Test that proper urls are successfully validated."""
        valid_urls = ['https://169.254.0.1', 'https://example.com',
                      'https://EXAMPLE.com', 'https://127.0.0.1:35357',
                      'https://localhost']

        for valid_url in valid_urls:
            request_to_validate = {'name': self.resource_name,
                                   'url': valid_url}
            self.create_schema_validator.validate(request_to_validate)

    def test_create_schema_with_invalid_urls(self):
        """Test that an exception is raised when validating improper urls."""
        invalid_urls = ['http//something.com',
                        'https//something.com',
                        'https://9.9.9']

        for invalid_url in invalid_urls:
            request_to_validate = {'name': self.resource_name,
                                   'url': invalid_url}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_schema_validator.validate,
                              request_to_validate)

    def test_create_schema_with_valid_email(self):
        """Validate email address

        Test that we successfully validate properly formatted email
        addresses.
        """
        request_to_validate = {'name': self.resource_name,
                               'email': self.valid_email}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_schema_with_invalid_email(self):
        """Validate invalid email address

        Test that an exception is raised when validating improperly
        formatted email addresses.
        """
        request_to_validate = {'name': self.resource_name,
                               'email': 'some invalid email value'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_schema_validator.validate,
                          request_to_validate)
