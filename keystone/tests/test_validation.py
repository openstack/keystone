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

import testtools

from keystone.common import validation
from keystone.common.validation import parameter_types
from keystone.common.validation import validators
from keystone import exception

"""Example model to validate create requests against. Assume that this is
the only backend for the create and validate schemas. This is just an
example to show how a backend can be used to construct a schema. In
Keystone, schemas are built according to the Identity API and the backends
available in Keystone. This example does not mean that all schema in
Keystone were strictly based of the SQL backends.

class Entity(sql.ModelBase):
    __tablename__ = 'entity'
    attributes = ['id', 'name', 'domain_id', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    description = sql.Column(sql.Text(), nullable=True)
    enabled = sql.Column(sql.Boolean, default=True, nullable=False)
    url = sql.Column(sql.String(225), nullable=True)
    email = sql.Column(sql.String(64), nullable=True)
"""

# Test schema to validate create requests against

_entity_properties = {
    'name': parameter_types.name,
    'description': validation.nullable(parameter_types.description),
    'enabled': parameter_types.boolean,
    'url': validation.nullable(parameter_types.url),
    'email': validation.nullable(parameter_types.email)
}

entity_create = {
    'type': 'object',
    'properties': _entity_properties,
    'required': ['name'],
    'additionalProperties': True,
}

entity_update = {
    'type': 'object',
    'properties': _entity_properties,
    'minProperties': 1,
    'additionalProperties': True,
}

_VALID_ENABLED_FORMATS = [True, False]

_INVALID_ENABLED_FORMATS = ['some string', 1, 0, 'True', 'False']


class EntityValidationTestCase(testtools.TestCase):

    def setUp(self):
        super(EntityValidationTestCase, self).setUp()
        self.resource_name = 'some resource name'
        self.description = 'Some valid description'
        self.valid_enabled = True
        self.valid_url = 'http://example.com'
        self.valid_email = 'joe@example.com'
        self.create_schema_validator = validators.SchemaValidator(
            entity_create)
        self.update_schema_validator = validators.SchemaValidator(
            entity_update)

    def test_create_entity_with_all_valid_parameters_validates(self):
        """Validate all parameter values against test schema."""
        request_to_validate = {'name': self.resource_name,
                               'description': self.description,
                               'enabled': self.valid_enabled,
                               'url': self.valid_url,
                               'email': self.valid_email}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_only_required_valid_parameters_validates(self):
        """Validate correct for only parameters values against test schema."""
        request_to_validate = {'name': self.resource_name}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_name_too_long_raises_exception(self):
        """Validate long names.

        Validate that an exception is raised when validating a string of 255+
        characters passed in as a name.
        """
        invalid_name = 'a' * 256
        request_to_validate = {'name': invalid_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_schema_validator.validate,
                          request_to_validate)

    def test_create_entity_with_name_too_short_raises_exception(self):
        """Validate short names.

        Test that an exception is raised when passing a string of length
        zero as a name parameter.
        """
        request_to_validate = {'name': ''}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_schema_validator.validate,
                          request_to_validate)

    def test_create_entity_with_unicode_name_validates(self):
        """Test that we successfully validate a unicode string."""
        request_to_validate = {'name': u'αβγδ'}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_invalid_enabled_format_raises_exception(self):
        """Validate invalid enabled formats.

        Test that an exception is raised when passing invalid boolean-like
        values as `enabled`.
        """
        for format in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.resource_name,
                                   'enabled': format}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_schema_validator.validate,
                              request_to_validate)

    def test_create_entity_with_valid_enabled_formats_validates(self):
        """Validate valid enabled formats.

        Test that we have successful validation on boolean values for
        `enabled`.
        """
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.resource_name,
                                   'enabled': valid_enabled}
            # Make sure validation doesn't raise a validation exception
            self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_valid_urls_validates(self):
        """Test that proper urls are successfully validated."""
        valid_urls = ['https://169.254.0.1', 'https://example.com',
                      'https://EXAMPLE.com', 'https://127.0.0.1:35357',
                      'https://localhost']

        for valid_url in valid_urls:
            request_to_validate = {'name': self.resource_name,
                                   'url': valid_url}
            self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_invalid_urls_fails(self):
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

    def test_create_entity_with_valid_email_validates(self):
        """Validate email address

        Test that we successfully validate properly formatted email
        addresses.
        """
        request_to_validate = {'name': self.resource_name,
                               'email': self.valid_email}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_invalid_email_fails(self):
        """Validate invalid email address.

        Test that an exception is raised when validating improperly
        formatted email addresses.
        """
        request_to_validate = {'name': self.resource_name,
                               'email': 'some invalid email value'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_schema_validator.validate,
                          request_to_validate)

    def test_update_entity_with_no_parameters_fails(self):
        """At least one parameter needs to be present for an update."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_schema_validator.validate,
                          request_to_validate)

    def test_update_entity_with_all_parameters_valid_validates(self):
        """Simulate updating an entity by ID."""
        request_to_validate = {'name': self.resource_name,
                               'description': self.description,
                               'enabled': self.valid_enabled,
                               'url': self.valid_url,
                               'email': self.valid_email}
        self.update_schema_validator.validate(request_to_validate)

    def test_update_entity_with_a_valid_required_parameter_validates(self):
        """Succeed if a valid required parameter is provided."""
        request_to_validate = {'name': self.resource_name}
        self.update_schema_validator.validate(request_to_validate)

    def test_update_entity_with_invalid_required_parameter_fails(self):
        """Fail if a provided required parameter is invalid."""
        request_to_validate = {'name': 'a' * 256}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_schema_validator.validate,
                          request_to_validate)

    def test_update_entity_with_a_null_optional_parameter_validates(self):
        """Optional parameters can be null to removed the value."""
        request_to_validate = {'email': None}
        self.update_schema_validator.validate(request_to_validate)

    def test_update_entity_with_a_required_null_parameter_fails(self):
        """The `name` parameter can't be null."""
        request_to_validate = {'name': None}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_schema_validator.validate,
                          request_to_validate)

    def test_update_entity_with_a_valid_optional_parameter_validates(self):
        """Succeeds with only a single valid optional parameter."""
        request_to_validate = {'email': self.valid_email}
        self.update_schema_validator.validate(request_to_validate)

    def test_update_entity_with_invalid_optional_parameter_fails(self):
        """Fails when an optional parameter is invalid."""
        request_to_validate = {'email': 0}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_schema_validator.validate,
                          request_to_validate)
