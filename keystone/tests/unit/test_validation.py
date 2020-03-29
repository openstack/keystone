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

import copy
import uuid

from keystone.application_credential import schema as app_cred_schema
from keystone.assignment import schema as assignment_schema
from keystone.catalog import schema as catalog_schema
from keystone.common import validation
from keystone.common.validation import parameter_types
from keystone.common.validation import validators
from keystone.credential import schema as credential_schema
from keystone import exception
from keystone.federation import schema as federation_schema
from keystone.identity.backends import resource_options as ro
from keystone.identity import schema as identity_schema
from keystone.limit import schema as limit_schema
from keystone.oauth1 import schema as oauth1_schema
from keystone.policy import schema as policy_schema
from keystone.resource import schema as resource_schema
from keystone.tests import unit
from keystone.trust import schema as trust_schema

"""Example model to validate create requests against. Assume that this is
the only backend for the create and validate schemas. This is just an
example to show how a backend can be used to construct a schema. In
Keystone, schemas are built according to the Identity API and the backends
available in Keystone. This example does not mean that all schema in
Keystone were strictly based on the SQL backends.

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
    'email': validation.nullable(parameter_types.email),
    'id_string': validation.nullable(parameter_types.id_string)
}

entity_create = {
    'type': 'object',
    'properties': _entity_properties,
    'required': ['name'],
    'additionalProperties': True,
}

entity_create_optional_body = {
    'type': 'object',
    'properties': _entity_properties,
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

_INVALID_DESC_FORMATS = [False, 1, 2.0]

_VALID_URLS = ['https://example.com', 'http://EXAMPLE.com/v3',
               'http://localhost', 'http://127.0.0.1:5000',
               'http://1.1.1.1', 'http://255.255.255.255',
               'http://[::1]', 'http://[::1]:35357',
               'http://[1::8]', 'http://[fe80::8%25eth0]',
               'http://[::1.2.3.4]', 'http://[2001:DB8::1.2.3.4]',
               'http://[::a:1.2.3.4]', 'http://[a::b:1.2.3.4]',
               'http://[1:2:3:4:5:6:7:8]', 'http://[1:2:3:4:5:6:1.2.3.4]',
               'http://[abcd:efAB:CDEF:1111:9999::]']

_INVALID_URLS = [False, 'this is not a URL', 1234, 'www.example.com',
                 'localhost', 'http//something.com',
                 'https//something.com', ' http://example.com']

_VALID_FILTERS = [{'interface': 'admin'},
                  {'region': 'US-WEST',
                   'interface': 'internal'}]

_INVALID_FILTERS = ['some string', 1, 0, True, False]

_INVALID_NAMES = [True, 24, ' ', '', 'a' * 256, None]


class CommonValidationTestCase(unit.BaseTestCase):

    def test_nullable_type_only(self):
        bool_without_enum = copy.deepcopy(parameter_types.boolean)
        bool_without_enum.pop('enum')
        schema_type_only = {
            'type': 'object',
            'properties': {'test': validation.nullable(bool_without_enum)},
            'additionalProperties': False,
            'required': ['test']}

        # Null should be in the types
        self.assertIn('null', schema_type_only['properties']['test']['type'])
        # No Enum, and nullable should not have added it.
        self.assertNotIn('enum', schema_type_only['properties']['test'].keys())
        validator = validators.SchemaValidator(schema_type_only)
        reqs_to_validate = [{'test': val} for val in [True, False, None]]
        for req in reqs_to_validate:
            validator.validate(req)

    def test_nullable_with_enum(self):
        schema_with_enum = {
            'type': 'object',
            'properties': {
                'test': validation.nullable(parameter_types.boolean)},
            'additionalProperties': False,
            'required': ['test']}

        # Null should be in enum and type
        self.assertIn('null', schema_with_enum['properties']['test']['type'])
        self.assertIn(None, schema_with_enum['properties']['test']['enum'])
        validator = validators.SchemaValidator(schema_with_enum)
        reqs_to_validate = [{'test': val} for val in [True, False, None]]
        for req in reqs_to_validate:
            validator.validate(req)


class EntityValidationTestCase(unit.BaseTestCase):

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
        for valid_url in _VALID_URLS:
            request_to_validate = {'name': self.resource_name,
                                   'url': valid_url}
            self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_invalid_urls_fails(self):
        """Test that an exception is raised when validating improper urls."""
        for invalid_url in _INVALID_URLS:
            request_to_validate = {'name': self.resource_name,
                                   'url': invalid_url}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_schema_validator.validate,
                              request_to_validate)

    def test_create_entity_with_valid_email_validates(self):
        """Validate email address.

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

    def test_create_entity_with_valid_id_strings(self):
        """Validate acceptable id strings."""
        valid_id_strings = [str(uuid.uuid4()), uuid.uuid4().hex, 'default']
        for valid_id in valid_id_strings:
            request_to_validate = {'name': self.resource_name,
                                   'id_string': valid_id}
            self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_invalid_id_strings(self):
        """Exception raised when using invalid id strings."""
        long_string = 'A' * 65
        invalid_id_strings = ['', long_string]
        for invalid_id in invalid_id_strings:
            request_to_validate = {'name': self.resource_name,
                                   'id_string': invalid_id}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_schema_validator.validate,
                              request_to_validate)

    def test_create_entity_with_null_id_string(self):
        """Validate that None is an acceptable optional string type."""
        request_to_validate = {'name': self.resource_name,
                               'id_string': None}
        self.create_schema_validator.validate(request_to_validate)

    def test_create_entity_with_null_string_succeeds(self):
        """Exception raised when passing None on required id strings."""
        request_to_validate = {'name': self.resource_name,
                               'id_string': None}
        self.create_schema_validator.validate(request_to_validate)

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
        """Succeed with only a single valid optional parameter."""
        request_to_validate = {'email': self.valid_email}
        self.update_schema_validator.validate(request_to_validate)

    def test_update_entity_with_invalid_optional_parameter_fails(self):
        """Fail when an optional parameter is invalid."""
        request_to_validate = {'email': 0}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_schema_validator.validate,
                          request_to_validate)


class ProjectValidationTestCase(unit.BaseTestCase):
    """Test for V3 Project API validation."""

    def setUp(self):
        super(ProjectValidationTestCase, self).setUp()

        self.project_name = 'My Project'

        create = resource_schema.project_create
        update = resource_schema.project_update
        self.create_project_validator = validators.SchemaValidator(create)
        self.update_project_validator = validators.SchemaValidator(update)

    def test_validate_project_request(self):
        """Test that we validate a project with `name` in request."""
        request_to_validate = {'name': self.project_name}
        self.create_project_validator.validate(request_to_validate)

    def test_validate_project_request_without_name_fails(self):
        """Validate project request fails without name."""
        request_to_validate = {'enabled': True}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_project_validator.validate,
                          request_to_validate)

    def test_validate_project_request_with_enabled(self):
        """Validate `enabled` as boolean-like values for projects."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.project_name,
                                   'enabled': valid_enabled}
            self.create_project_validator.validate(request_to_validate)

    def test_validate_project_request_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.project_name,
                                   'enabled': invalid_enabled}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_project_validator.validate,
                              request_to_validate)

    def test_validate_project_request_with_valid_description(self):
        """Test that we validate `description` in create project requests."""
        request_to_validate = {'name': self.project_name,
                               'description': 'My Project'}
        self.create_project_validator.validate(request_to_validate)

    def test_validate_project_request_with_invalid_description_fails(self):
        """Exception is raised when `description` as a non-string value."""
        request_to_validate = {'name': self.project_name,
                               'description': False}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_project_validator.validate,
                          request_to_validate)

    def test_validate_project_request_with_name_too_long(self):
        """Exception is raised when `name` is too long."""
        long_project_name = 'a' * 65
        request_to_validate = {'name': long_project_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_project_validator.validate,
                          request_to_validate)

    def test_validate_project_create_fails_with_invalid_name(self):
        """Exception when validating a create request with invalid `name`."""
        for invalid_name in _INVALID_NAMES + ['a' * 65]:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_project_validator.validate,
                              request_to_validate)

    def test_validate_project_create_with_tags(self):
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', 'bar']}
        self.create_project_validator.validate(request_to_validate)

    def test_validate_project_create_with_tags_invalid_char(self):
        invalid_chars = [',', '/', ',foo', 'foo/bar']
        for char in invalid_chars:
            tag = uuid.uuid4().hex + char
            request_to_validate = {'name': uuid.uuid4().hex,
                                   'tags': ['foo', tag]}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_project_validator.validate,
                              request_to_validate)

    def test_validate_project_create_with_tag_name_too_long(self):
        invalid_name = 'a' * 256
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', invalid_name]}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_project_validator.validate,
                          request_to_validate)

    def test_validate_project_create_with_too_many_tags(self):
        tags = [uuid.uuid4().hex for _ in range(81)]
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': tags}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_project_validator.validate,
                          request_to_validate)

    def test_validate_project_request_with_valid_parent_id(self):
        """Test that we validate `parent_id` in create project requests."""
        # parent_id is nullable
        request_to_validate = {'name': self.project_name,
                               'parent_id': None}
        self.create_project_validator.validate(request_to_validate)
        request_to_validate = {'name': self.project_name,
                               'parent_id': uuid.uuid4().hex}
        self.create_project_validator.validate(request_to_validate)

    def test_validate_project_request_with_invalid_parent_id_fails(self):
        """Exception is raised when `parent_id` as a non-id value."""
        request_to_validate = {'name': self.project_name,
                               'parent_id': False}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_project_validator.validate,
                          request_to_validate)
        request_to_validate = {'name': self.project_name,
                               'parent_id': 'fake project'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_project_validator.validate,
                          request_to_validate)

    def test_validate_project_update_request(self):
        """Test that we validate a project update request."""
        request_to_validate = {'domain_id': uuid.uuid4().hex}
        self.update_project_validator.validate(request_to_validate)

    def test_validate_project_update_request_with_no_parameters_fails(self):
        """Exception is raised when updating project without parameters."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_project_validator.validate,
                          request_to_validate)

    def test_validate_project_update_request_with_name_too_long_fails(self):
        """Exception raised when updating a project with `name` too long."""
        long_project_name = 'a' * 65
        request_to_validate = {'name': long_project_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_project_validator.validate,
                          request_to_validate)

    def test_validate_project_update_fails_with_invalid_name(self):
        """Exception when validating an update request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_project_validator.validate,
                              request_to_validate)

    def test_validate_project_update_with_tags(self):
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', 'bar']}
        self.update_project_validator.validate(request_to_validate)

    def test_validate_project_update_with_tags_invalid_char(self):
        invalid_chars = [',', '/']
        for char in invalid_chars:
            tag = uuid.uuid4().hex + char
            request_to_validate = {'name': uuid.uuid4().hex,
                                   'tags': ['foo', tag]}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_project_validator.validate,
                              request_to_validate)

    def test_validate_project_update_with_tag_name_too_long(self):
        invalid_name = 'a' * 256
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', invalid_name]}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_project_validator.validate,
                          request_to_validate)

    def test_validate_project_update_with_too_many_tags(self):
        tags = [uuid.uuid4().hex for _ in range(81)]
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': tags}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_project_validator.validate,
                          request_to_validate)

    def test_validate_project_create_request_with_valid_domain_id(self):
        """Test that we validate `domain_id` in create project requests."""
        # domain_id is nullable
        for domain_id in [None, uuid.uuid4().hex]:
            request_to_validate = {'name': self.project_name,
                                   'domain_id': domain_id}
            self.create_project_validator.validate(request_to_validate)

    def test_validate_project_request_with_invalid_domain_id_fails(self):
        """Exception is raised when `domain_id` is a non-id value."""
        for domain_id in [False, 'fake_project']:
            request_to_validate = {'name': self.project_name,
                                   'domain_id': domain_id}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_project_validator.validate,
                              request_to_validate)


class DomainValidationTestCase(unit.BaseTestCase):
    """Test for V3 Domain API validation."""

    def setUp(self):
        super(DomainValidationTestCase, self).setUp()

        self.domain_name = 'My Domain'

        create = resource_schema.domain_create
        update = resource_schema.domain_update
        self.create_domain_validator = validators.SchemaValidator(create)
        self.update_domain_validator = validators.SchemaValidator(update)

    def test_validate_domain_request(self):
        """Make sure we successfully validate a create domain request."""
        request_to_validate = {'name': self.domain_name}
        self.create_domain_validator.validate(request_to_validate)

    def test_validate_domain_request_without_name_fails(self):
        """Make sure we raise an exception when `name` isn't included."""
        request_to_validate = {'enabled': True}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_request_with_enabled(self):
        """Validate `enabled` as boolean-like values for domains."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.domain_name,
                                   'enabled': valid_enabled}
            self.create_domain_validator.validate(request_to_validate)

    def test_validate_domain_request_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.domain_name,
                                   'enabled': invalid_enabled}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_domain_validator.validate,
                              request_to_validate)

    def test_validate_domain_request_with_valid_description(self):
        """Test that we validate `description` in create domain requests."""
        request_to_validate = {'name': self.domain_name,
                               'description': 'My Domain'}
        self.create_domain_validator.validate(request_to_validate)

    def test_validate_domain_request_with_invalid_description_fails(self):
        """Exception is raised when `description` is a non-string value."""
        request_to_validate = {'name': self.domain_name,
                               'description': False}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_request_with_name_too_long(self):
        """Exception is raised when `name` is too long."""
        long_domain_name = 'a' * 65
        request_to_validate = {'name': long_domain_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_create_fails_with_invalid_name(self):
        """Exception when validating a create request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_domain_validator.validate,
                              request_to_validate)

    def test_validate_domain_create_with_tags(self):
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', 'bar']}
        self.create_domain_validator.validate(request_to_validate)

    def test_validate_domain_create_with_tags_invalid_char(self):
        invalid_chars = [',', '/']
        for char in invalid_chars:
            tag = uuid.uuid4().hex + char
            request_to_validate = {'name': uuid.uuid4().hex,
                                   'tags': ['foo', tag]}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_domain_validator.validate,
                              request_to_validate)

    def test_validate_domain_create_with_tag_name_too_long(self):
        invalid_name = 'a' * 256
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', invalid_name]}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_create_with_too_many_tags(self):
        tags = [uuid.uuid4().hex for _ in range(81)]
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': tags}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_update_request(self):
        """Test that we validate a domain update request."""
        request_to_validate = {'domain_id': uuid.uuid4().hex}
        self.update_domain_validator.validate(request_to_validate)

    def test_validate_domain_update_request_with_no_parameters_fails(self):
        """Exception is raised when updating a domain without parameters."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_update_request_with_name_too_long_fails(self):
        """Exception raised when updating a domain with `name` too long."""
        long_domain_name = 'a' * 65
        request_to_validate = {'name': long_domain_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_update_fails_with_invalid_name(self):
        """Exception when validating an update request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_domain_validator.validate,
                              request_to_validate)

    def test_validate_domain_update_with_tags(self):
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', 'bar']}
        self.update_domain_validator.validate(request_to_validate)

    def test_validate_domain_update_with_tags_invalid_char(self):
        invalid_chars = [',', '/']
        for char in invalid_chars:
            tag = uuid.uuid4().hex + char
            request_to_validate = {'name': uuid.uuid4().hex,
                                   'tags': ['foo', tag]}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_domain_validator.validate,
                              request_to_validate)

    def test_validate_domain_update_with_tag_name_too_long(self):
        invalid_name = 'a' * 256
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': ['foo', invalid_name]}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_domain_validator.validate,
                          request_to_validate)

    def test_validate_domain_update_with_too_many_tags(self):
        tags = [uuid.uuid4().hex for _ in range(81)]
        request_to_validate = {'name': uuid.uuid4().hex,
                               'tags': tags}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_domain_validator.validate,
                          request_to_validate)


class RoleValidationTestCase(unit.BaseTestCase):
    """Test for V3 Role API validation."""

    def setUp(self):
        super(RoleValidationTestCase, self).setUp()

        self.role_name = 'My Role'

        create = assignment_schema.role_create
        update = assignment_schema.role_update
        self.create_role_validator = validators.SchemaValidator(create)
        self.update_role_validator = validators.SchemaValidator(update)

    def test_validate_role_request(self):
        """Test we can successfully validate a create role request."""
        request_to_validate = {'name': self.role_name}
        self.create_role_validator.validate(request_to_validate)

    def test_validate_role_create_without_name_raises_exception(self):
        """Test that we raise an exception when `name` isn't included."""
        request_to_validate = {'enabled': True}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_role_validator.validate,
                          request_to_validate)

    def test_validate_role_create_fails_with_invalid_name(self):
        """Exception when validating a create request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_role_validator.validate,
                              request_to_validate)

    def test_validate_role_create_request_with_name_too_long_fails(self):
        """Exception raised when creating a role with `name` too long."""
        long_role_name = 'a' * 256
        request_to_validate = {'name': long_role_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_role_validator.validate,
                          request_to_validate)

    def test_validate_role_request_with_valid_description(self):
        """Test we can validate`description` in create role request."""
        request_to_validate = {'name': self.role_name,
                               'description': 'My Role'}
        self.create_role_validator.validate(request_to_validate)

    def test_validate_role_request_fails_with_invalid_description(self):
        """Exception is raised when `description` as a non-string value."""
        request_to_validate = {'name': self.role_name,
                               'description': False}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_role_validator.validate,
                          request_to_validate)

    def test_validate_role_update_request(self):
        """Test that we validate a role update request."""
        request_to_validate = {'name': 'My New Role'}
        self.update_role_validator.validate(request_to_validate)

    def test_validate_role_update_fails_with_invalid_name(self):
        """Exception when validating an update request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_role_validator.validate,
                              request_to_validate)

    def test_validate_role_update_request_with_name_too_long_fails(self):
        """Exception raised when updating a role with `name` too long."""
        long_role_name = 'a' * 256
        request_to_validate = {'name': long_role_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_role_validator.validate,
                          request_to_validate)


class PolicyValidationTestCase(unit.BaseTestCase):
    """Test for V3 Policy API validation."""

    def setUp(self):
        super(PolicyValidationTestCase, self).setUp()

        create = policy_schema.policy_create
        update = policy_schema.policy_update
        self.create_policy_validator = validators.SchemaValidator(create)
        self.update_policy_validator = validators.SchemaValidator(update)

    def test_validate_policy_succeeds(self):
        """Test that we validate a create policy request."""
        request_to_validate = {'blob': 'some blob information',
                               'type': 'application/json'}
        self.create_policy_validator.validate(request_to_validate)

    def test_validate_policy_without_blob_fails(self):
        """Exception raised without `blob` in request."""
        request_to_validate = {'type': 'application/json'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_policy_validator.validate,
                          request_to_validate)

    def test_validate_policy_without_type_fails(self):
        """Exception raised without `type` in request."""
        request_to_validate = {'blob': 'some blob information'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_policy_validator.validate,
                          request_to_validate)

    def test_validate_policy_create_with_extra_parameters_succeeds(self):
        """Validate policy create with extra parameters."""
        request_to_validate = {'blob': 'some blob information',
                               'type': 'application/json',
                               'extra': 'some extra stuff'}
        self.create_policy_validator.validate(request_to_validate)

    def test_validate_policy_create_with_invalid_type_fails(self):
        """Exception raised when `blob` and `type` are boolean."""
        for prop in ['blob', 'type']:
            request_to_validate = {prop: False}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_policy_validator.validate,
                              request_to_validate)

    def test_validate_policy_update_without_parameters_fails(self):
        """Exception raised when updating policy without parameters."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_policy_validator.validate,
                          request_to_validate)

    def test_validate_policy_update_with_extra_parameters_succeeds(self):
        """Validate policy update request with extra parameters."""
        request_to_validate = {'blob': 'some blob information',
                               'type': 'application/json',
                               'extra': 'some extra stuff'}
        self.update_policy_validator.validate(request_to_validate)

    def test_validate_policy_update_succeeds(self):
        """Test that we validate a policy update request."""
        request_to_validate = {'blob': 'some blob information',
                               'type': 'application/json'}
        self.update_policy_validator.validate(request_to_validate)

    def test_validate_policy_update_with_invalid_type_fails(self):
        """Exception raised when invalid `type` on policy update."""
        for prop in ['blob', 'type']:
            request_to_validate = {prop: False}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_policy_validator.validate,
                              request_to_validate)


class CredentialValidationTestCase(unit.BaseTestCase):
    """Test for V3 Credential API validation."""

    def setUp(self):
        super(CredentialValidationTestCase, self).setUp()

        create = credential_schema.credential_create
        update = credential_schema.credential_update
        self.create_credential_validator = validators.SchemaValidator(create)
        self.update_credential_validator = validators.SchemaValidator(update)

    def test_validate_credential_succeeds(self):
        """Test that we validate a credential request."""
        request_to_validate = {'blob': 'some string',
                               'project_id': uuid.uuid4().hex,
                               'type': 'ec2',
                               'user_id': uuid.uuid4().hex}
        self.create_credential_validator.validate(request_to_validate)

    def test_validate_credential_without_blob_fails(self):
        """Exception raised without `blob` in create request."""
        request_to_validate = {'type': 'ec2',
                               'user_id': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_credential_validator.validate,
                          request_to_validate)

    def test_validate_credential_without_user_id_fails(self):
        """Exception raised without `user_id` in create request."""
        request_to_validate = {'blob': 'some credential blob',
                               'type': 'ec2'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_credential_validator.validate,
                          request_to_validate)

    def test_validate_credential_without_type_fails(self):
        """Exception raised without `type` in create request."""
        request_to_validate = {'blob': 'some credential blob',
                               'user_id': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_credential_validator.validate,
                          request_to_validate)

    def test_validate_credential_ec2_without_project_id_fails(self):
        """Validate `project_id` is required for ec2.

        Test that a SchemaValidationError is raised when type is ec2
        and no `project_id` is provided in create request.
        """
        request_to_validate = {'blob': 'some credential blob',
                               'type': 'ec2',
                               'user_id': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_credential_validator.validate,
                          request_to_validate)

    def test_validate_credential_with_project_id_succeeds(self):
        """Test that credential request works for all types."""
        cred_types = ['ec2', 'cert', uuid.uuid4().hex]

        for c_type in cred_types:
            request_to_validate = {'blob': 'some blob',
                                   'project_id': uuid.uuid4().hex,
                                   'type': c_type,
                                   'user_id': uuid.uuid4().hex}
            # Make sure an exception isn't raised
            self.create_credential_validator.validate(request_to_validate)

    def test_validate_credential_non_ec2_without_project_id_succeeds(self):
        """Validate `project_id` is not required for non-ec2.

        Test that create request without `project_id` succeeds for any
        non-ec2 credential.
        """
        cred_types = ['cert', uuid.uuid4().hex]

        for c_type in cred_types:
            request_to_validate = {'blob': 'some blob',
                                   'type': c_type,
                                   'user_id': uuid.uuid4().hex}
            # Make sure an exception isn't raised
            self.create_credential_validator.validate(request_to_validate)

    def test_validate_credential_with_extra_parameters_succeeds(self):
        """Validate create request with extra parameters."""
        request_to_validate = {'blob': 'some string',
                               'extra': False,
                               'project_id': uuid.uuid4().hex,
                               'type': 'ec2',
                               'user_id': uuid.uuid4().hex}
        self.create_credential_validator.validate(request_to_validate)

    def test_validate_credential_update_succeeds(self):
        """Test that a credential request is properly validated."""
        request_to_validate = {'blob': 'some string',
                               'project_id': uuid.uuid4().hex,
                               'type': 'ec2',
                               'user_id': uuid.uuid4().hex}
        self.update_credential_validator.validate(request_to_validate)

    def test_validate_credential_update_without_parameters_fails(self):
        """Exception is raised on update without parameters."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_credential_validator.validate,
                          request_to_validate)

    def test_validate_credential_update_with_extra_parameters_succeeds(self):
        """Validate credential update with extra parameters."""
        request_to_validate = {'blob': 'some string',
                               'extra': False,
                               'project_id': uuid.uuid4().hex,
                               'type': 'ec2',
                               'user_id': uuid.uuid4().hex}
        self.update_credential_validator.validate(request_to_validate)


class RegionValidationTestCase(unit.BaseTestCase):
    """Test for V3 Region API validation."""

    def setUp(self):
        super(RegionValidationTestCase, self).setUp()

        self.region_name = 'My Region'

        create = catalog_schema.region_create
        update = catalog_schema.region_update
        self.create_region_validator = validators.SchemaValidator(create)
        self.update_region_validator = validators.SchemaValidator(update)

    def test_validate_region_request(self):
        """Test that we validate a basic region request."""
        # Create_region doesn't take any parameters in the request so let's
        # make sure we cover that case.
        request_to_validate = {}
        self.create_region_validator.validate(request_to_validate)

    def test_validate_region_create_request_with_parameters(self):
        """Test that we validate a region request with parameters."""
        request_to_validate = {'id': 'us-east',
                               'description': 'US East Region',
                               'parent_region_id': 'US Region'}
        self.create_region_validator.validate(request_to_validate)

    def test_validate_region_create_with_uuid(self):
        """Test that we validate a region request with a UUID as the id."""
        request_to_validate = {'id': uuid.uuid4().hex,
                               'description': 'US East Region',
                               'parent_region_id': uuid.uuid4().hex}
        self.create_region_validator.validate(request_to_validate)

    def test_validate_region_create_fails_with_invalid_region_id(self):
        """Exception raised when passing invalid `id` in request."""
        request_to_validate = {'id': 1234,
                               'description': 'US East Region'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_region_validator.validate,
                          request_to_validate)

    def test_validate_region_create_succeeds_with_extra_parameters(self):
        """Validate create region request with extra values."""
        request_to_validate = {'other_attr': uuid.uuid4().hex}
        self.create_region_validator.validate(request_to_validate)

    def test_validate_region_create_succeeds_with_no_parameters(self):
        """Validate create region request with no parameters."""
        request_to_validate = {}
        self.create_region_validator.validate(request_to_validate)

    def test_validate_region_update_succeeds(self):
        """Test that we validate a region update request."""
        request_to_validate = {'id': 'us-west',
                               'description': 'US West Region',
                               'parent_region_id': 'us-region'}
        self.update_region_validator.validate(request_to_validate)

    def test_validate_region_update_succeeds_with_extra_parameters(self):
        """Validate extra attributes in the region update request."""
        request_to_validate = {'other_attr': uuid.uuid4().hex}
        self.update_region_validator.validate(request_to_validate)

    def test_validate_region_update_fails_with_no_parameters(self):
        """Exception raised when passing no parameters in a region update."""
        # An update request should consist of at least one value to update
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_region_validator.validate,
                          request_to_validate)


class ServiceValidationTestCase(unit.BaseTestCase):
    """Test for V3 Service API validation."""

    def setUp(self):
        super(ServiceValidationTestCase, self).setUp()

        create = catalog_schema.service_create
        update = catalog_schema.service_update
        self.create_service_validator = validators.SchemaValidator(create)
        self.update_service_validator = validators.SchemaValidator(update)

    def test_validate_service_create_succeeds(self):
        """Test that we validate a service create request."""
        request_to_validate = {'name': 'Nova',
                               'description': 'OpenStack Compute Service',
                               'enabled': True,
                               'type': 'compute'}
        self.create_service_validator.validate(request_to_validate)

    def test_validate_service_create_succeeds_with_required_parameters(self):
        """Validate a service create request with the required parameters."""
        # The only parameter type required for service creation is 'type'
        request_to_validate = {'type': 'compute'}
        self.create_service_validator.validate(request_to_validate)

    def test_validate_service_create_fails_without_type(self):
        """Exception raised when trying to create a service without `type`."""
        request_to_validate = {'name': 'Nova'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_service_validator.validate,
                          request_to_validate)

    def test_validate_service_create_succeeds_with_extra_parameters(self):
        """Test that extra parameters pass validation on create service."""
        request_to_validate = {'other_attr': uuid.uuid4().hex,
                               'type': uuid.uuid4().hex}
        self.create_service_validator.validate(request_to_validate)

    def test_validate_service_create_succeeds_with_valid_enabled(self):
        """Validate boolean values as enabled values on service create."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': valid_enabled,
                                   'type': uuid.uuid4().hex}
            self.create_service_validator.validate(request_to_validate)

    def test_validate_service_create_fails_with_invalid_enabled(self):
        """Exception raised when boolean-like parameters as `enabled`.

        On service create, make sure an exception is raised if `enabled` is
        not a boolean value.
        """
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': invalid_enabled,
                                   'type': uuid.uuid4().hex}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_service_validator.validate,
                              request_to_validate)

    def test_validate_service_create_fails_when_name_too_long(self):
        """Exception raised when `name` is greater than 255 characters."""
        long_name = 'a' * 256
        request_to_validate = {'type': 'compute',
                               'name': long_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_service_validator.validate,
                          request_to_validate)

    def test_validate_service_create_fails_when_name_too_short(self):
        """Exception is raised when `name` is too short."""
        request_to_validate = {'type': 'compute',
                               'name': ''}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_service_validator.validate,
                          request_to_validate)

    def test_validate_service_create_fails_when_type_too_long(self):
        """Exception is raised when `type` is too long."""
        long_type_name = 'a' * 256
        request_to_validate = {'type': long_type_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_service_validator.validate,
                          request_to_validate)

    def test_validate_service_create_fails_when_type_too_short(self):
        """Exception is raised when `type` is too short."""
        request_to_validate = {'type': ''}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_service_validator.validate,
                          request_to_validate)

    def test_validate_service_update_request_succeeds(self):
        """Test that we validate a service update request."""
        request_to_validate = {'name': 'Cinder',
                               'type': 'volume',
                               'description': 'OpenStack Block Storage',
                               'enabled': False}
        self.update_service_validator.validate(request_to_validate)

    def test_validate_service_update_fails_with_no_parameters(self):
        """Exception raised when updating a service without values."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_service_validator.validate,
                          request_to_validate)

    def test_validate_service_update_succeeds_with_extra_parameters(self):
        """Validate updating a service with extra parameters."""
        request_to_validate = {'other_attr': uuid.uuid4().hex}
        self.update_service_validator.validate(request_to_validate)

    def test_validate_service_update_succeeds_with_valid_enabled(self):
        """Validate boolean formats as `enabled` on service update."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': valid_enabled}
            self.update_service_validator.validate(request_to_validate)

    def test_validate_service_update_fails_with_invalid_enabled(self):
        """Exception raised when boolean-like values as `enabled`."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': invalid_enabled}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_service_validator.validate,
                              request_to_validate)

    def test_validate_service_update_fails_with_name_too_long(self):
        """Exception is raised when `name` is too long on update."""
        long_name = 'a' * 256
        request_to_validate = {'name': long_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_service_validator.validate,
                          request_to_validate)

    def test_validate_service_update_fails_with_name_too_short(self):
        """Exception is raised when `name` is too short on update."""
        request_to_validate = {'name': ''}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_service_validator.validate,
                          request_to_validate)

    def test_validate_service_update_fails_with_type_too_long(self):
        """Exception is raised when `type` is too long on update."""
        long_type_name = 'a' * 256
        request_to_validate = {'type': long_type_name}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_service_validator.validate,
                          request_to_validate)

    def test_validate_service_update_fails_with_type_too_short(self):
        """Exception is raised when `type` is too short on update."""
        request_to_validate = {'type': ''}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_service_validator.validate,
                          request_to_validate)


class EndpointValidationTestCase(unit.BaseTestCase):
    """Test for V3 Endpoint API validation."""

    def setUp(self):
        super(EndpointValidationTestCase, self).setUp()

        create = catalog_schema.endpoint_create
        update = catalog_schema.endpoint_update
        self.create_endpoint_validator = validators.SchemaValidator(create)
        self.update_endpoint_validator = validators.SchemaValidator(update)

    def test_validate_endpoint_request_succeeds(self):
        """Test that we validate an endpoint request."""
        request_to_validate = {'enabled': True,
                               'interface': 'admin',
                               'region_id': uuid.uuid4().hex,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}
        self.create_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_create_succeeds_with_required_parameters(self):
        """Validate an endpoint request with only the required parameters."""
        # According to the Identity V3 API endpoint creation requires
        # 'service_id', 'interface', and 'url'
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'interface': 'public',
                               'url': 'https://service.example.com:5000/'}
        self.create_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_create_succeeds_with_valid_enabled(self):
        """Validate an endpoint with boolean values.

        Validate boolean values as `enabled` in endpoint create requests.
        """
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': valid_enabled,
                                   'service_id': uuid.uuid4().hex,
                                   'interface': 'public',
                                   'url': 'https://service.example.com:5000/'}
            self.create_endpoint_validator.validate(request_to_validate)

    def test_validate_create_endpoint_fails_with_invalid_enabled(self):
        """Exception raised when boolean-like values as `enabled`."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': invalid_enabled,
                                   'service_id': uuid.uuid4().hex,
                                   'interface': 'public',
                                   'url': 'https://service.example.com:5000/'}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_endpoint_validator.validate,
                              request_to_validate)

    def test_validate_endpoint_create_succeeds_with_extra_parameters(self):
        """Test that extra parameters pass validation on create endpoint."""
        request_to_validate = {'other_attr': uuid.uuid4().hex,
                               'service_id': uuid.uuid4().hex,
                               'interface': 'public',
                               'url': 'https://service.example.com:5000/'}
        self.create_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_create_fails_without_service_id(self):
        """Exception raised when `service_id` isn't in endpoint request."""
        request_to_validate = {'interface': 'public',
                               'url': 'https://service.example.com:5000/'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_create_fails_without_interface(self):
        """Exception raised when `interface` isn't in endpoint request."""
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_create_fails_without_url(self):
        """Exception raised when `url` isn't in endpoint request."""
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'interface': 'public'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_create_succeeds_with_url(self):
        """Validate `url` attribute in endpoint create request."""
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'interface': 'public'}
        for url in _VALID_URLS:
            request_to_validate['url'] = url
            self.create_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_create_fails_with_invalid_url(self):
        """Exception raised when passing invalid `url` in request."""
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'interface': 'public'}
        for url in _INVALID_URLS:
            request_to_validate['url'] = url
            self.assertRaises(exception.SchemaValidationError,
                              self.create_endpoint_validator.validate,
                              request_to_validate)

    def test_validate_endpoint_create_fails_with_invalid_interface(self):
        """Exception raised with invalid `interface`."""
        request_to_validate = {'interface': uuid.uuid4().hex,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_create_fails_with_invalid_region_id(self):
        """Exception raised when passing invalid `region(_id)` in request."""
        request_to_validate = {'interface': 'admin',
                               'region_id': 1234,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}

        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_validator.validate,
                          request_to_validate)

        request_to_validate = {'interface': 'admin',
                               'region': 1234,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}

        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_update_fails_with_invalid_enabled(self):
        """Exception raised when `enabled` is boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': invalid_enabled}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_endpoint_validator.validate,
                              request_to_validate)

    def test_validate_endpoint_update_succeeds_with_valid_enabled(self):
        """Validate `enabled` as boolean values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': valid_enabled}
            self.update_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_update_fails_with_invalid_interface(self):
        """Exception raised when invalid `interface` on endpoint update."""
        request_to_validate = {'interface': uuid.uuid4().hex,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_endpoint_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_update_request_succeeds(self):
        """Test that we validate an endpoint update request."""
        request_to_validate = {'enabled': True,
                               'interface': 'admin',
                               'region_id': uuid.uuid4().hex,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}
        self.update_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_update_fails_with_no_parameters(self):
        """Exception raised when no parameters on endpoint update."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_endpoint_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_update_succeeds_with_extra_parameters(self):
        """Test that extra parameters pass validation on update endpoint."""
        request_to_validate = {'enabled': True,
                               'interface': 'admin',
                               'region_id': uuid.uuid4().hex,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/',
                               'other_attr': uuid.uuid4().hex}
        self.update_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_update_succeeds_with_url(self):
        """Validate `url` attribute in endpoint update request."""
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'interface': 'public'}
        for url in _VALID_URLS:
            request_to_validate['url'] = url
            self.update_endpoint_validator.validate(request_to_validate)

    def test_validate_endpoint_update_fails_with_invalid_url(self):
        """Exception raised when passing invalid `url` in request."""
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'interface': 'public'}
        for url in _INVALID_URLS:
            request_to_validate['url'] = url
            self.assertRaises(exception.SchemaValidationError,
                              self.update_endpoint_validator.validate,
                              request_to_validate)

    def test_validate_endpoint_update_fails_with_invalid_region_id(self):
        """Exception raised when passing invalid `region(_id)` in request."""
        request_to_validate = {'interface': 'admin',
                               'region_id': 1234,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}

        self.assertRaises(exception.SchemaValidationError,
                          self.update_endpoint_validator.validate,
                          request_to_validate)

        request_to_validate = {'interface': 'admin',
                               'region': 1234,
                               'service_id': uuid.uuid4().hex,
                               'url': 'https://service.example.com:5000/'}

        self.assertRaises(exception.SchemaValidationError,
                          self.update_endpoint_validator.validate,
                          request_to_validate)


class EndpointGroupValidationTestCase(unit.BaseTestCase):
    """Test for V3 Endpoint Group API validation."""

    def setUp(self):
        super(EndpointGroupValidationTestCase, self).setUp()

        create = catalog_schema.endpoint_group_create
        update = catalog_schema.endpoint_group_update
        self.create_endpoint_grp_validator = validators.SchemaValidator(create)
        self.update_endpoint_grp_validator = validators.SchemaValidator(update)

    def test_validate_endpoint_group_request_succeeds(self):
        """Test that we validate an endpoint group request."""
        request_to_validate = {'description': 'endpoint group description',
                               'filters': {'interface': 'admin'},
                               'name': 'endpoint_group_name'}
        self.create_endpoint_grp_validator.validate(request_to_validate)

    def test_validate_endpoint_group_create_succeeds_with_req_parameters(self):
        """Validate required endpoint group parameters.

        This test ensure that validation succeeds with only the required
        parameters passed for creating an endpoint group.
        """
        request_to_validate = {'filters': {'interface': 'admin'},
                               'name': 'endpoint_group_name'}
        self.create_endpoint_grp_validator.validate(request_to_validate)

    def test_validate_endpoint_group_create_succeeds_with_valid_filters(self):
        """Validate `filters` in endpoint group create requests."""
        request_to_validate = {'description': 'endpoint group description',
                               'name': 'endpoint_group_name'}
        for valid_filters in _VALID_FILTERS:
            request_to_validate['filters'] = valid_filters
            self.create_endpoint_grp_validator.validate(request_to_validate)

    def test_validate_create_endpoint_group_fails_with_invalid_filters(self):
        """Validate invalid `filters` value in endpoint group parameters.

        This test ensures that exception is raised when non-dict values is
        used as `filters` in endpoint group create request.
        """
        request_to_validate = {'description': 'endpoint group description',
                               'name': 'endpoint_group_name'}
        for invalid_filters in _INVALID_FILTERS:
            request_to_validate['filters'] = invalid_filters
            self.assertRaises(exception.SchemaValidationError,
                              self.create_endpoint_grp_validator.validate,
                              request_to_validate)

    def test_validate_endpoint_group_create_fails_without_name(self):
        """Exception raised when `name` isn't in endpoint group request."""
        request_to_validate = {'description': 'endpoint group description',
                               'filters': {'interface': 'admin'}}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_grp_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_group_create_fails_without_filters(self):
        """Exception raised when `filters` isn't in endpoint group request."""
        request_to_validate = {'description': 'endpoint group description',
                               'name': 'endpoint_group_name'}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_endpoint_grp_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_group_update_request_succeeds(self):
        """Test that we validate an endpoint group update request."""
        request_to_validate = {'description': 'endpoint group description',
                               'filters': {'interface': 'admin'},
                               'name': 'endpoint_group_name'}
        self.update_endpoint_grp_validator.validate(request_to_validate)

    def test_validate_endpoint_group_update_fails_with_no_parameters(self):
        """Exception raised when no parameters on endpoint group update."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_endpoint_grp_validator.validate,
                          request_to_validate)

    def test_validate_endpoint_group_update_succeeds_with_name(self):
        """Validate request with  only `name` in endpoint group update.

        This test ensures that passing only a `name` passes validation
        on update endpoint group request.
        """
        request_to_validate = {'name': 'endpoint_group_name'}
        self.update_endpoint_grp_validator.validate(request_to_validate)

    def test_validate_endpoint_group_update_succeeds_with_valid_filters(self):
        """Validate `filters` as dict values."""
        for valid_filters in _VALID_FILTERS:
            request_to_validate = {'filters': valid_filters}
            self.update_endpoint_grp_validator.validate(request_to_validate)

    def test_validate_endpoint_group_update_fails_with_invalid_filters(self):
        """Exception raised when passing invalid `filters` in request."""
        for invalid_filters in _INVALID_FILTERS:
            request_to_validate = {'filters': invalid_filters}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_endpoint_grp_validator.validate,
                              request_to_validate)


class TrustValidationTestCase(unit.BaseTestCase):
    """Test for V3 Trust API validation."""

    _valid_roles = [{'name': 'member'},
                    {'id': uuid.uuid4().hex},
                    {'id': str(uuid.uuid4())},
                    {'name': '_member_'}]
    _invalid_roles = [False, True, 123, None]

    def setUp(self):
        super(TrustValidationTestCase, self).setUp()

        create = trust_schema.trust_create
        self.create_trust_validator = validators.SchemaValidator(create)

    def test_validate_trust_succeeds(self):
        """Test that we can validate a trust request."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False}
        self.create_trust_validator.validate(request_to_validate)

    def test_validate_trust_with_all_parameters_succeeds(self):
        """Test that we can validate a trust request with all parameters."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False,
                               'project_id': uuid.uuid4().hex,
                               'roles': [{'id': uuid.uuid4().hex},
                                         {'id': uuid.uuid4().hex}],
                               'expires_at': 'some timestamp',
                               'remaining_uses': 2}
        self.create_trust_validator.validate(request_to_validate)

    def test_validate_trust_without_trustor_id_fails(self):
        """Validate trust request fails without `trustor_id`."""
        request_to_validate = {'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_trust_validator.validate,
                          request_to_validate)

    def test_validate_trust_without_trustee_id_fails(self):
        """Validate trust request fails without `trustee_id`."""
        request_to_validate = {'trusor_user_id': uuid.uuid4().hex,
                               'impersonation': False}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_trust_validator.validate,
                          request_to_validate)

    def test_validate_trust_without_impersonation_fails(self):
        """Validate trust request fails without `impersonation`."""
        request_to_validate = {'trustee_user_id': uuid.uuid4().hex,
                               'trustor_user_id': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_trust_validator.validate,
                          request_to_validate)

    def test_validate_trust_with_extra_parameters_succeeds(self):
        """Test that we can validate a trust request with extra parameters."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False,
                               'project_id': uuid.uuid4().hex,
                               'roles': [{'id': uuid.uuid4().hex},
                                         {'id': uuid.uuid4().hex}],
                               'expires_at': 'some timestamp',
                               'remaining_uses': 2,
                               'extra': 'something extra!'}
        self.create_trust_validator.validate(request_to_validate)

    def test_validate_trust_with_invalid_impersonation_fails(self):
        """Validate trust request with invalid `impersonation` fails."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': 2}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_trust_validator.validate,
                          request_to_validate)

    def test_validate_trust_with_null_remaining_uses_succeeds(self):
        """Validate trust request with null `remaining_uses`."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False,
                               'remaining_uses': None}
        self.create_trust_validator.validate(request_to_validate)

    def test_validate_trust_with_remaining_uses_succeeds(self):
        """Validate trust request with `remaining_uses` succeeds."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False,
                               'remaining_uses': 2}
        self.create_trust_validator.validate(request_to_validate)

    def test_validate_trust_with_period_in_user_id_string(self):
        """Validate trust request with a period in the user id string."""
        request_to_validate = {'trustor_user_id': 'john.smith',
                               'trustee_user_id': 'joe.developer',
                               'impersonation': False}
        self.create_trust_validator.validate(request_to_validate)

    def test_validate_trust_with_invalid_expires_at_fails(self):
        """Validate trust request with invalid `expires_at` fails."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False,
                               'expires_at': 3}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_trust_validator.validate,
                          request_to_validate)

    def test_validate_trust_with_role_types_succeeds(self):
        """Validate trust request with `roles` succeeds."""
        for role in self._valid_roles:
            request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                                   'trustee_user_id': uuid.uuid4().hex,
                                   'impersonation': False,
                                   'roles': [role]}
            self.create_trust_validator.validate(request_to_validate)

    def test_validate_trust_with_invalid_role_type_fails(self):
        """Validate trust request with invalid `roles` fails."""
        for role in self._invalid_roles:
            request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                                   'trustee_user_id': uuid.uuid4().hex,
                                   'impersonation': False,
                                   'roles': role}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_trust_validator.validate,
                              request_to_validate)

    def test_validate_trust_with_list_of_valid_roles_succeeds(self):
        """Validate trust request with a list of valid `roles`."""
        request_to_validate = {'trustor_user_id': uuid.uuid4().hex,
                               'trustee_user_id': uuid.uuid4().hex,
                               'impersonation': False,
                               'roles': self._valid_roles}
        self.create_trust_validator.validate(request_to_validate)


class ServiceProviderValidationTestCase(unit.BaseTestCase):
    """Test for V3 Service Provider API validation."""

    def setUp(self):
        super(ServiceProviderValidationTestCase, self).setUp()

        self.valid_auth_url = 'https://' + uuid.uuid4().hex + '.com'
        self.valid_sp_url = 'https://' + uuid.uuid4().hex + '.com'

        create = federation_schema.service_provider_create
        update = federation_schema.service_provider_update
        self.create_sp_validator = validators.SchemaValidator(create)
        self.update_sp_validator = validators.SchemaValidator(update)

    def test_validate_sp_request(self):
        """Test that we validate `auth_url` and `sp_url` in request."""
        request_to_validate = {
            'auth_url': self.valid_auth_url,
            'sp_url': self.valid_sp_url
        }
        self.create_sp_validator.validate(request_to_validate)

    def test_validate_sp_request_with_invalid_auth_url_fails(self):
        """Validate request fails with invalid `auth_url`."""
        request_to_validate = {
            'auth_url': uuid.uuid4().hex,
            'sp_url': self.valid_sp_url
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_request_with_invalid_sp_url_fails(self):
        """Validate request fails with invalid `sp_url`."""
        request_to_validate = {
            'auth_url': self.valid_auth_url,
            'sp_url': uuid.uuid4().hex,
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_request_without_auth_url_fails(self):
        """Validate request fails without `auth_url`."""
        request_to_validate = {
            'sp_url': self.valid_sp_url
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)
        request_to_validate = {
            'auth_url': None,
            'sp_url': self.valid_sp_url
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_request_without_sp_url_fails(self):
        """Validate request fails without `sp_url`."""
        request_to_validate = {
            'auth_url': self.valid_auth_url,
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)
        request_to_validate = {
            'auth_url': self.valid_auth_url,
            'sp_url': None,
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_request_with_enabled(self):
        """Validate `enabled` as boolean-like values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {
                'auth_url': self.valid_auth_url,
                'sp_url': self.valid_sp_url,
                'enabled': valid_enabled
            }
            self.create_sp_validator.validate(request_to_validate)

    def test_validate_sp_request_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {
                'auth_url': self.valid_auth_url,
                'sp_url': self.valid_sp_url,
                'enabled': invalid_enabled
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.create_sp_validator.validate,
                              request_to_validate)

    def test_validate_sp_request_with_valid_description(self):
        """Test that we validate `description` in create requests."""
        request_to_validate = {
            'auth_url': self.valid_auth_url,
            'sp_url': self.valid_sp_url,
            'description': 'My Service Provider'
        }
        self.create_sp_validator.validate(request_to_validate)

    def test_validate_sp_request_with_invalid_description_fails(self):
        """Exception is raised when `description` as a non-string value."""
        request_to_validate = {
            'auth_url': self.valid_auth_url,
            'sp_url': self.valid_sp_url,
            'description': False
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_request_with_extra_field_fails(self):
        """Exception raised when passing extra fields in the body."""
        # 'id' can't be passed in the body since it is passed in the URL
        request_to_validate = {
            'id': 'ACME',
            'auth_url': self.valid_auth_url,
            'sp_url': self.valid_sp_url,
            'description': 'My Service Provider'
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_update_request(self):
        """Test that we validate a update request."""
        request_to_validate = {'description': uuid.uuid4().hex}
        self.update_sp_validator.validate(request_to_validate)

    def test_validate_sp_update_request_with_no_parameters_fails(self):
        """Exception is raised when updating without parameters."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_update_request_with_invalid_auth_url_fails(self):
        """Exception raised when updating with invalid `auth_url`."""
        request_to_validate = {'auth_url': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_sp_validator.validate,
                          request_to_validate)
        request_to_validate = {'auth_url': None}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_sp_validator.validate,
                          request_to_validate)

    def test_validate_sp_update_request_with_invalid_sp_url_fails(self):
        """Exception raised when updating with invalid `sp_url`."""
        request_to_validate = {'sp_url': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_sp_validator.validate,
                          request_to_validate)
        request_to_validate = {'sp_url': None}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_sp_validator.validate,
                          request_to_validate)


class UserValidationTestCase(unit.BaseTestCase):
    """Test for V3 User API validation."""

    def setUp(self):
        super(UserValidationTestCase, self).setUp()

        self.user_name = uuid.uuid4().hex

        create = identity_schema.user_create
        update = identity_schema.user_update
        self.create_user_validator = validators.SchemaValidator(create)
        self.update_user_validator = validators.SchemaValidator(update)

    def test_validate_user_create_request_succeeds(self):
        """Test that validating a user create request succeeds."""
        request_to_validate = {'name': self.user_name}
        self.create_user_validator.validate(request_to_validate)

    def test_validate_user_create_with_all_valid_parameters_succeeds(self):
        """Test that validating a user create request succeeds."""
        request_to_validate = unit.new_user_ref(domain_id=uuid.uuid4().hex,
                                                name=self.user_name)
        self.create_user_validator.validate(request_to_validate)

    def test_validate_user_create_fails_without_name(self):
        """Exception raised when validating a user without name."""
        request_to_validate = {'email': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_user_validator.validate,
                          request_to_validate)

    def test_validate_user_create_succeeds_with_valid_enabled_formats(self):
        """Validate acceptable enabled formats in create user requests."""
        for enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.user_name,
                                   'enabled': enabled}
            self.create_user_validator.validate(request_to_validate)

    def test_validate_user_create_fails_with_invalid_enabled_formats(self):
        """Exception raised when enabled is not an acceptable format."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'name': self.user_name,
                                   'enabled': invalid_enabled}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_user_validator.validate,
                              request_to_validate)

    def test_validate_user_create_succeeds_with_extra_attributes(self):
        """Validate extra parameters on user create requests."""
        request_to_validate = {'name': self.user_name,
                               'other_attr': uuid.uuid4().hex}
        self.create_user_validator.validate(request_to_validate)

    def test_validate_user_create_succeeds_with_password_of_zero_length(self):
        """Validate empty password on user create requests."""
        request_to_validate = {'name': self.user_name,
                               'password': ''}
        self.create_user_validator.validate(request_to_validate)

    def test_validate_user_create_succeeds_with_null_password(self):
        """Validate that password is nullable on create user."""
        request_to_validate = {'name': self.user_name,
                               'password': None}
        self.create_user_validator.validate(request_to_validate)

    def test_validate_user_create_fails_with_invalid_password_type(self):
        """Exception raised when user password is of the wrong type."""
        request_to_validate = {'name': self.user_name,
                               'password': True}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_user_validator.validate,
                          request_to_validate)

    def test_validate_user_create_succeeds_with_null_description(self):
        """Validate that description can be nullable on create user."""
        request_to_validate = {'name': self.user_name,
                               'description': None}
        self.create_user_validator.validate(request_to_validate)

    def test_validate_user_create_fails_with_invalid_name(self):
        """Exception when validating a create request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_user_validator.validate,
                              request_to_validate)

    def test_validate_user_update_succeeds(self):
        """Validate an update user request."""
        request_to_validate = {'email': uuid.uuid4().hex}
        self.update_user_validator.validate(request_to_validate)

    def test_validate_user_update_fails_with_no_parameters(self):
        """Exception raised when updating nothing."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_user_validator.validate,
                          request_to_validate)

    def test_validate_user_update_succeeds_with_extra_parameters(self):
        """Validate user update requests with extra parameters."""
        request_to_validate = {'other_attr': uuid.uuid4().hex}
        self.update_user_validator.validate(request_to_validate)

    def test_validate_user_update_fails_with_invalid_name(self):
        """Exception when validating an update request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_user_validator.validate,
                              request_to_validate)

    def test_user_create_succeeds_with_empty_options(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {}
        }
        self.create_user_validator.validate(request_to_validate)

    def test_user_create_options_fails_invalid_option(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {
                'whatever': True
            }
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_user_validator.validate,
                          request_to_validate)

    def test_user_create_with_options_change_password_required(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {
                ro.IGNORE_CHANGE_PASSWORD_OPT.option_name: True
            }
        }
        self.create_user_validator.validate(request_to_validate)

    def test_user_create_options_change_password_required_wrong_type(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {
                ro.IGNORE_CHANGE_PASSWORD_OPT.option_name: 'whatever'
            }
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_user_validator.validate,
                          request_to_validate)

    def test_user_create_options_change_password_required_none(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {
                ro.IGNORE_CHANGE_PASSWORD_OPT.option_name: None
            }
        }
        self.create_user_validator.validate(request_to_validate)

    def test_user_update_with_options_change_password_required(self):
        request_to_validate = {
            'options': {
                ro.IGNORE_CHANGE_PASSWORD_OPT.option_name: False
            }
        }
        self.update_user_validator.validate(request_to_validate)

    def test_user_create_with_options_lockout_password(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {
                ro.IGNORE_LOCKOUT_ATTEMPT_OPT.option_name: True
            }
        }
        self.create_user_validator.validate(request_to_validate)

    def test_user_update_with_options_lockout_password(self):
        request_to_validate = {
            'options': {
                ro.IGNORE_LOCKOUT_ATTEMPT_OPT.option_name: False
            }
        }
        self.update_user_validator.validate(request_to_validate)

    def test_user_update_with_two_options(self):
        request_to_validate = {
            'options': {
                ro.IGNORE_CHANGE_PASSWORD_OPT.option_name: True,
                ro.IGNORE_LOCKOUT_ATTEMPT_OPT.option_name: True
            }
        }
        self.update_user_validator.validate(request_to_validate)

    def test_user_create_with_two_options(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {
                ro.IGNORE_CHANGE_PASSWORD_OPT.option_name: False,
                ro.IGNORE_LOCKOUT_ATTEMPT_OPT.option_name: True
            }
        }
        self.create_user_validator.validate(request_to_validate)

    def test_user_create_with_mfa_rules(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {
                ro.MFA_RULES_OPT.option_name: [
                    [uuid.uuid4().hex, uuid.uuid4().hex],
                    [uuid.uuid4().hex],
                ]
            }
        }
        self.create_user_validator.validate(request_to_validate)

    def test_user_update_with_mfa_rules(self):
        request_to_validate = {
            'options': {
                ro.MFA_RULES_OPT.option_name: [
                    [uuid.uuid4().hex, uuid.uuid4().hex],
                    [uuid.uuid4().hex],
                ]
            }
        }
        self.update_user_validator.validate(request_to_validate)

    def test_user_create_with_mfa_rules_enabled(self):
        request_to_validate = {
            'name': self.user_name,
            'options': {ro.MFA_ENABLED_OPT.option_name: True}
        }
        self.create_user_validator.validate(request_to_validate)

    def test_user_update_mfa_rules_enabled(self):
        request_to_validate = {
            'options': {ro.MFA_ENABLED_OPT.option_name: False}
        }
        self.update_user_validator.validate(request_to_validate)

    def test_user_option_validation_with_invalid_mfa_rules_fails(self):
        # Test both json schema validation and the validator method in
        # keystone.identity.backends.resource_options
        test_cases = [
            # Main Element Not an Array
            (True, TypeError),
            # Sub-Element Not an Array
            ([True, False], TypeError),
            # Sub-element Element not string
            ([[True], [True, False]], TypeError),
            # Duplicate sub-array
            ([['duplicate_array'] for x in range(0, 2)], ValueError),
            # Empty Sub element
            ([[uuid.uuid4().hex], []], ValueError),
            # Duplicate strings in sub-element
            ([['duplicate' for x in range(0, 2)]], ValueError),
        ]
        for ruleset, exception_class in test_cases:
            request_to_validate = {
                'options': {
                    ro.MFA_RULES_OPT.option_name: ruleset
                }
            }
            # JSON Schema Validation
            self.assertRaises(exception.SchemaValidationError,
                              self.update_user_validator.validate,
                              request_to_validate)
            # Data Store Validation
            self.assertRaises(
                exception_class,
                ro._mfa_rules_validator_list_of_lists_of_strings_no_duplicates,
                ruleset)


class GroupValidationTestCase(unit.BaseTestCase):
    """Test for V3 Group API validation."""

    def setUp(self):
        super(GroupValidationTestCase, self).setUp()

        self.group_name = uuid.uuid4().hex

        create = identity_schema.group_create
        update = identity_schema.group_update
        self.create_group_validator = validators.SchemaValidator(create)
        self.update_group_validator = validators.SchemaValidator(update)

    def test_validate_group_create_succeeds(self):
        """Validate create group requests."""
        request_to_validate = {'name': self.group_name}
        self.create_group_validator.validate(request_to_validate)

    def test_validate_group_create_succeeds_with_all_parameters(self):
        """Validate create group requests with all parameters."""
        request_to_validate = {'name': self.group_name,
                               'description': uuid.uuid4().hex,
                               'domain_id': uuid.uuid4().hex}
        self.create_group_validator.validate(request_to_validate)

    def test_validate_group_create_fails_without_group_name(self):
        """Exception raised when group name is not provided in request."""
        request_to_validate = {'description': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_group_validator.validate,
                          request_to_validate)

    def test_validate_group_create_succeeds_with_extra_parameters(self):
        """Validate extra attributes on group create requests."""
        request_to_validate = {'name': self.group_name,
                               'other_attr': uuid.uuid4().hex}
        self.create_group_validator.validate(request_to_validate)

    def test_validate_group_create_fails_with_invalid_name(self):
        """Exception when validating a create request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_group_validator.validate,
                              request_to_validate)

    def test_validate_group_update_succeeds(self):
        """Validate group update requests."""
        request_to_validate = {'description': uuid.uuid4().hex}
        self.update_group_validator.validate(request_to_validate)

    def test_validate_group_update_fails_with_no_parameters(self):
        """Exception raised when no parameters passed in on update."""
        request_to_validate = {}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_group_validator.validate,
                          request_to_validate)

    def test_validate_group_update_succeeds_with_extra_parameters(self):
        """Validate group update requests with extra parameters."""
        request_to_validate = {'other_attr': uuid.uuid4().hex}
        self.update_group_validator.validate(request_to_validate)

    def test_validate_group_update_fails_with_invalid_name(self):
        """Exception when validating an update request with invalid `name`."""
        for invalid_name in _INVALID_NAMES:
            request_to_validate = {'name': invalid_name}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_group_validator.validate,
                              request_to_validate)


class ChangePasswordValidationTestCase(unit.BaseTestCase):
    """Test for Change Password API validation."""

    def setUp(self):
        super(ChangePasswordValidationTestCase, self).setUp()

        self.original_password = uuid.uuid4().hex
        self.password = uuid.uuid4().hex

        change = identity_schema.password_change
        self.change_password_validator = validators.SchemaValidator(change)

    def test_validate_password_change_request_succeeds(self):
        """Test that validating a password change request succeeds."""
        request_to_validate = {'original_password': self.original_password,
                               'password': self.password}
        self.change_password_validator.validate(request_to_validate)

    def test_validate_password_change_fails_without_all_fields(self):
        """Test that validating a password change fails without all values."""
        request_to_validate = {'original_password': self.original_password}
        self.assertRaises(exception.SchemaValidationError,
                          self.change_password_validator.validate,
                          request_to_validate)
        request_to_validate = {'password': self.password}
        self.assertRaises(exception.SchemaValidationError,
                          self.change_password_validator.validate,
                          request_to_validate)

    def test_validate_password_change_fails_with_invalid_values(self):
        """Test that validating a password change fails with bad values."""
        request_to_validate = {'original_password': None,
                               'password': None}
        self.assertRaises(exception.SchemaValidationError,
                          self.change_password_validator.validate,
                          request_to_validate)
        request_to_validate = {'original_password': 42,
                               'password': True}
        self.assertRaises(exception.SchemaValidationError,
                          self.change_password_validator.validate,
                          request_to_validate)


class IdentityProviderValidationTestCase(unit.BaseTestCase):
    """Test for V3 Identity Provider API validation."""

    def setUp(self):
        super(IdentityProviderValidationTestCase, self).setUp()

        create = federation_schema.identity_provider_create
        update = federation_schema.identity_provider_update
        self.create_idp_validator = validators.SchemaValidator(create)
        self.update_idp_validator = validators.SchemaValidator(update)

    def test_validate_idp_request_succeeds(self):
        """Test that we validate an identity provider request."""
        request_to_validate = {'description': 'identity provider description',
                               'enabled': True,
                               'remote_ids': [uuid.uuid4().hex,
                                              uuid.uuid4().hex]}
        self.create_idp_validator.validate(request_to_validate)
        self.update_idp_validator.validate(request_to_validate)

    def test_validate_idp_request_fails_with_invalid_params(self):
        """Exception raised when unknown parameter is found."""
        request_to_validate = {'bogus': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_idp_validator.validate,
                          request_to_validate)

        self.assertRaises(exception.SchemaValidationError,
                          self.update_idp_validator.validate,
                          request_to_validate)

    def test_validate_idp_request_with_enabled(self):
        """Validate `enabled` as boolean-like values."""
        for valid_enabled in _VALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': valid_enabled}
            self.create_idp_validator.validate(request_to_validate)
            self.update_idp_validator.validate(request_to_validate)

    def test_validate_idp_request_with_invalid_enabled_fails(self):
        """Exception is raised when `enabled` isn't a boolean-like value."""
        for invalid_enabled in _INVALID_ENABLED_FORMATS:
            request_to_validate = {'enabled': invalid_enabled}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_idp_validator.validate,
                              request_to_validate)

            self.assertRaises(exception.SchemaValidationError,
                              self.update_idp_validator.validate,
                              request_to_validate)

    def test_validate_idp_request_no_parameters(self):
        """Test that schema validation with empty request body."""
        request_to_validate = {}
        self.create_idp_validator.validate(request_to_validate)

        # Exception raised when no property on IdP update.
        self.assertRaises(exception.SchemaValidationError,
                          self.update_idp_validator.validate,
                          request_to_validate)

    def test_validate_idp_request_with_invalid_description_fails(self):
        """Exception is raised when `description` as a non-string value."""
        request_to_validate = {'description': False}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_idp_validator.validate,
                          request_to_validate)

        self.assertRaises(exception.SchemaValidationError,
                          self.update_idp_validator.validate,
                          request_to_validate)

    def test_validate_idp_request_with_invalid_remote_id_fails(self):
        """Exception is raised when `remote_ids` is not a array."""
        request_to_validate = {"remote_ids": uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_idp_validator.validate,
                          request_to_validate)

        self.assertRaises(exception.SchemaValidationError,
                          self.update_idp_validator.validate,
                          request_to_validate)

    def test_validate_idp_request_with_duplicated_remote_id(self):
        """Exception is raised when the duplicated `remote_ids` is found."""
        idp_id = uuid.uuid4().hex
        request_to_validate = {"remote_ids": [idp_id, idp_id]}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_idp_validator.validate,
                          request_to_validate)

        self.assertRaises(exception.SchemaValidationError,
                          self.update_idp_validator.validate,
                          request_to_validate)

    def test_validate_idp_request_remote_id_nullable(self):
        """Test that `remote_ids` could be explicitly set to None."""
        request_to_validate = {'remote_ids': None}
        self.create_idp_validator.validate(request_to_validate)
        self.update_idp_validator.validate(request_to_validate)


class FederationProtocolValidationTestCase(unit.BaseTestCase):
    """Test for V3 Federation Protocol API validation."""

    def setUp(self):
        super(FederationProtocolValidationTestCase, self).setUp()

        create = federation_schema.protocol_create
        update = federation_schema.protocol_update
        self.create_protocol_validator = validators.SchemaValidator(create)
        self.update_protocol_validator = validators.SchemaValidator(update)

    def test_validate_protocol_request_succeeds(self):
        """Test that we validate a protocol request successfully."""
        request_to_validate = {'mapping_id': uuid.uuid4().hex}
        self.create_protocol_validator.validate(request_to_validate)

    def test_validate_protocol_request_succeeds_with_nonuuid_mapping_id(self):
        """Test that we allow underscore in mapping_id value."""
        request_to_validate = {'mapping_id': 'my_mapping_id'}
        self.create_protocol_validator.validate(request_to_validate)

    def test_validate_protocol_request_fails_with_invalid_params(self):
        """Exception raised when unknown parameter is found."""
        request_to_validate = {'bogus': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_protocol_validator.validate,
                          request_to_validate)

    def test_validate_protocol_request_no_parameters(self):
        """Test that schema validation with empty request body."""
        request_to_validate = {}
        # 'mapping_id' is required.
        self.assertRaises(exception.SchemaValidationError,
                          self.create_protocol_validator.validate,
                          request_to_validate)

    def test_validate_protocol_request_fails_with_invalid_mapping_id(self):
        """Exception raised when mapping_id is not string."""
        request_to_validate = {'mapping_id': 12334}
        self.assertRaises(exception.SchemaValidationError,
                          self.create_protocol_validator.validate,
                          request_to_validate)

    def test_validate_protocol_request_succeeds_on_update(self):
        """Test that we validate a protocol update request successfully."""
        request_to_validate = {'mapping_id': uuid.uuid4().hex}
        self.update_protocol_validator.validate(request_to_validate)

    def test_validate_update_protocol_request_succeeds_with_nonuuid_id(self):
        """Test that we allow underscore in mapping_id value when updating."""
        request_to_validate = {'mapping_id': 'my_mapping_id'}
        self.update_protocol_validator.validate(request_to_validate)

    def test_validate_update_protocol_request_fails_with_invalid_params(self):
        """Exception raised when unknown parameter in protocol update."""
        request_to_validate = {'bogus': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_protocol_validator.validate,
                          request_to_validate)

    def test_validate_update_protocol_with_no_parameters_fails(self):
        """Test that updating a protocol requires at least one attribute."""
        request_to_validate = {}
        # 'mapping_id' is required.
        self.assertRaises(exception.SchemaValidationError,
                          self.update_protocol_validator.validate,
                          request_to_validate)

    def test_validate_update_protocol_request_fails_with_invalid_id(self):
        """Test that updating a protocol with a non-string mapping_id fail."""
        for bad_mapping_id in [12345, True]:
            request_to_validate = {'mapping_id': bad_mapping_id}
            self.assertRaises(exception.SchemaValidationError,
                              self.update_protocol_validator.validate,
                              request_to_validate)


class OAuth1ValidationTestCase(unit.BaseTestCase):
    """Test for V3 Identity OAuth1 API validation."""

    def setUp(self):
        super(OAuth1ValidationTestCase, self).setUp()

        create = oauth1_schema.consumer_create
        update = oauth1_schema.consumer_update
        authorize = oauth1_schema.request_token_authorize
        self.create_consumer_validator = validators.SchemaValidator(create)
        self.update_consumer_validator = validators.SchemaValidator(update)
        self.authorize_request_token_validator = validators.SchemaValidator(
            authorize)

    def test_validate_consumer_request_succeeds(self):
        """Test that we validate a consumer request successfully."""
        request_to_validate = {'description': uuid.uuid4().hex,
                               'name': uuid.uuid4().hex}
        self.create_consumer_validator.validate(request_to_validate)
        self.update_consumer_validator.validate(request_to_validate)

    def test_validate_consumer_request_with_no_parameters(self):
        """Test that schema validation with empty request body."""
        request_to_validate = {}
        self.create_consumer_validator.validate(request_to_validate)
        # At least one property should be given.
        self.assertRaises(exception.SchemaValidationError,
                          self.update_consumer_validator.validate,
                          request_to_validate)

    def test_validate_consumer_request_with_invalid_description_fails(self):
        """Exception is raised when `description` as a non-string value."""
        for invalid_desc in _INVALID_DESC_FORMATS:
            request_to_validate = {'description': invalid_desc}
            self.assertRaises(exception.SchemaValidationError,
                              self.create_consumer_validator.validate,
                              request_to_validate)

            self.assertRaises(exception.SchemaValidationError,
                              self.update_consumer_validator.validate,
                              request_to_validate)

    def test_validate_update_consumer_request_fails_with_secret(self):
        """Exception raised when secret is given."""
        request_to_validate = {'secret': uuid.uuid4().hex}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_consumer_validator.validate,
                          request_to_validate)

    def test_validate_consumer_request_with_none_desc(self):
        """Test that schema validation with None desc."""
        request_to_validate = {'description': None}
        self.create_consumer_validator.validate(request_to_validate)
        self.update_consumer_validator.validate(request_to_validate)

    def test_validate_authorize_request_token(self):
        request_to_validate = [
            {
                "id": "711aa6371a6343a9a43e8a310fbe4a6f"
            },
            {
                "name": "test_role"
            }
        ]

        self.authorize_request_token_validator.validate(request_to_validate)

    def test_validate_authorize_request_token_with_additional_properties(self):
        request_to_validate = [
            {
                "id": "711aa6371a6343a9a43e8a310fbe4a6f",
                "fake_key": "fake_value"
            }
        ]

        self.assertRaises(exception.SchemaValidationError,
                          self.authorize_request_token_validator.validate,
                          request_to_validate)

    def test_validate_authorize_request_token_with_id_and_name(self):
        request_to_validate = [
            {
                "id": "711aa6371a6343a9a43e8a310fbe4a6f",
                "name": "admin"
            }
        ]

        self.assertRaises(exception.SchemaValidationError,
                          self.authorize_request_token_validator.validate,
                          request_to_validate)

    def test_validate_authorize_request_token_with_non_id_or_name(self):
        request_to_validate = [
            {
                "fake_key": "fake_value"
            }
        ]

        self.assertRaises(exception.SchemaValidationError,
                          self.authorize_request_token_validator.validate,
                          request_to_validate)


class PasswordValidationTestCase(unit.TestCase):
    def setUp(self):
        super(PasswordValidationTestCase, self).setUp()
        # passwords requires: 1 letter, 1 digit, 7 chars
        self.config_fixture.config(group='security_compliance',
                                   password_regex=(
                                       r'^(?=.*\d)(?=.*[a-zA-Z]).{7,}$'))

    def test_password_validate_with_valid_strong_password(self):
        password = 'mypassword2'
        validators.validate_password(password)

    def test_password_validate_with_invalid_strong_password(self):
        # negative test: None
        password = None
        self.assertRaises(exception.PasswordValidationError,
                          validators.validate_password,
                          password)
        # negative test: numeric
        password = 1234
        self.assertRaises(exception.PasswordValidationError,
                          validators.validate_password,
                          password)
        # negative test: boolean
        password = True
        self.assertRaises(exception.PasswordValidationError,
                          validators.validate_password,
                          password)

    def test_password_validate_with_invalid_password_regex(self):
        # invalid regular expression, missing beginning '['
        self.config_fixture.config(group='security_compliance',
                                   password_regex=r'\S]+')
        password = 'mypassword2'
        self.assertRaises(exception.PasswordValidationError,
                          validators.validate_password,
                          password)
        # fix regular expression and validate
        self.config_fixture.config(group='security_compliance',
                                   password_regex=r'[\S]+')
        validators.validate_password(password)


class LimitValidationTestCase(unit.BaseTestCase):
    """Test for V3 Limits API validation."""

    def setUp(self):
        super(LimitValidationTestCase, self).setUp()

        create_registered_limits = limit_schema.registered_limit_create
        update_registered_limits = limit_schema.registered_limit_update
        create_limits = limit_schema.limit_create
        update_limits = limit_schema.limit_update

        self.create_registered_limits_validator = validators.SchemaValidator(
            create_registered_limits)
        self.update_registered_limits_validator = validators.SchemaValidator(
            update_registered_limits)
        self.create_limits_validator = validators.SchemaValidator(
            create_limits)
        self.update_limits_validator = validators.SchemaValidator(
            update_limits)

    def test_validate_registered_limit_create_request_succeeds(self):
        request_to_validate = [{'service_id': uuid.uuid4().hex,
                                'region_id': 'RegionOne',
                                'resource_name': 'volume',
                                'default_limit': 10,
                                'description': 'test description'}]
        self.create_registered_limits_validator.validate(request_to_validate)

    def test_validate_registered_limit_create_request_without_optional(self):
        request_to_validate = [{'service_id': uuid.uuid4().hex,
                                'resource_name': 'volume',
                                'default_limit': 10}]
        self.create_registered_limits_validator.validate(request_to_validate)

    def test_validate_registered_limit_update_request_without_region(self):
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'resource_name': 'volume',
                               'default_limit': 10}
        self.update_registered_limits_validator.validate(request_to_validate)

    def test_validate_registered_limit_request_with_no_parameters(self):
        request_to_validate = []
        # At least one property should be given.
        self.assertRaises(exception.SchemaValidationError,
                          self.create_registered_limits_validator.validate,
                          request_to_validate)

    def test_validate_registered_limit_create_request_with_invalid_input(self):
        _INVALID_FORMATS = [{'service_id': 'fake_id'},
                            {'region_id': 123},
                            {'resource_name': 123},
                            {'resource_name': ''},
                            {'resource_name': 'a' * 256},
                            {'default_limit': 'not_int'},
                            {'default_limit': -10},
                            {'default_limit': 10000000000000000},
                            {'description': 123},
                            {'description': True}]
        for invalid_desc in _INVALID_FORMATS:
            request_to_validate = [{'service_id': uuid.uuid4().hex,
                                    'region_id': 'RegionOne',
                                    'resource_name': 'volume',
                                    'default_limit': 10,
                                    'description': 'test description'}]
            request_to_validate[0].update(invalid_desc)

            self.assertRaises(exception.SchemaValidationError,
                              self.create_registered_limits_validator.validate,
                              request_to_validate)

    def test_validate_registered_limit_update_request_with_invalid_input(self):
        _INVALID_FORMATS = [{'service_id': 'fake_id'},
                            {'region_id': 123},
                            {'resource_name': 123},
                            {'resource_name': ''},
                            {'resource_name': 'a' * 256},
                            {'default_limit': 'not_int'},
                            {'default_limit': -10},
                            {'default_limit': 10000000000000000},
                            {'description': 123}]
        for invalid_desc in _INVALID_FORMATS:
            request_to_validate = {'service_id': uuid.uuid4().hex,
                                   'region_id': 'RegionOne',
                                   'resource_name': 'volume',
                                   'default_limit': 10,
                                   'description': 'test description'}
            request_to_validate.update(invalid_desc)

            self.assertRaises(exception.SchemaValidationError,
                              self.update_registered_limits_validator.validate,
                              request_to_validate)

    def test_validate_registered_limit_create_request_with_addition(self):
        request_to_validate = [{'service_id': uuid.uuid4().hex,
                                'region_id': 'RegionOne',
                                'resource_name': 'volume',
                                'default_limit': 10,
                                'more_key': 'more_value'}]
        self.assertRaises(exception.SchemaValidationError,
                          self.create_registered_limits_validator.validate,
                          request_to_validate)

    def test_validate_registered_limit_update_request_with_addition(self):
        request_to_validate = {'service_id': uuid.uuid4().hex,
                               'region_id': 'RegionOne',
                               'resource_name': 'volume',
                               'default_limit': 10,
                               'more_key': 'more_value'}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_registered_limits_validator.validate,
                          request_to_validate)

    def test_validate_registered_limit_create_request_without_required(self):
        for key in ['service_id', 'resource_name', 'default_limit']:
            request_to_validate = [{'service_id': uuid.uuid4().hex,
                                    'region_id': 'RegionOne',
                                    'resource_name': 'volume',
                                    'default_limit': 10}]
            request_to_validate[0].pop(key)
            self.assertRaises(exception.SchemaValidationError,
                              self.create_registered_limits_validator.validate,
                              request_to_validate)

    def test_validate_project_limit_create_request_succeeds(self):
        request_to_validate = [{'project_id': uuid.uuid4().hex,
                                'service_id': uuid.uuid4().hex,
                                'region_id': 'RegionOne',
                                'resource_name': 'volume',
                                'resource_limit': 10,
                                'description': 'test description'}]
        self.create_limits_validator.validate(request_to_validate)

    def test_validate_domain_limit_create_request_succeeds(self):
        request_to_validate = [{'domain_id': uuid.uuid4().hex,
                                'service_id': uuid.uuid4().hex,
                                'region_id': 'RegionOne',
                                'resource_name': 'volume',
                                'resource_limit': 10,
                                'description': 'test description'}]
        self.create_limits_validator.validate(request_to_validate)

    def test_validate_limit_create_request_without_optional(self):
        request_to_validate = [{'project_id': uuid.uuid4().hex,
                                'service_id': uuid.uuid4().hex,
                                'resource_name': 'volume',
                                'resource_limit': 10}]
        self.create_limits_validator.validate(request_to_validate)

    def test_validate_limit_update_request_succeeds(self):
        request_to_validate = {'resource_limit': 10,
                               'description': 'test description'}
        self.update_limits_validator.validate(request_to_validate)

    def test_validate_limit_update_request_without_optional(self):
        request_to_validate = {'resource_limit': 10}
        self.update_limits_validator.validate(request_to_validate)

    def test_validate_limit_request_with_no_parameters(self):
        request_to_validate = []
        # At least one property should be given.
        self.assertRaises(exception.SchemaValidationError,
                          self.create_limits_validator.validate,
                          request_to_validate)

    def test_validate_limit_create_request_with_invalid_input(self):
        _INVALID_FORMATS = [{'project_id': 'fake_id'},
                            {'service_id': 'fake_id'},
                            {'region_id': 123},
                            {'resource_name': 123},
                            {'resource_name': ''},
                            {'resource_name': 'a' * 256},
                            {'resource_limit': -10},
                            {'resource_limit': 10000000000000000},
                            {'resource_limit': 'not_int'},
                            {'description': 123}]
        for invalid_attribute in _INVALID_FORMATS:
            request_to_validate = [{'project_id': uuid.uuid4().hex,
                                    'service_id': uuid.uuid4().hex,
                                    'region_id': 'RegionOne',
                                    'resource_name': 'volume',
                                    'resource_limit': 10,
                                    'description': 'test description'}]
            request_to_validate[0].update(invalid_attribute)

            self.assertRaises(exception.SchemaValidationError,
                              self.create_limits_validator.validate,
                              request_to_validate)

    def test_validate_limit_create_request_with_invalid_domain(self):
        request_to_validate = [{'domain_id': 'fake_id',
                                'service_id': uuid.uuid4().hex,
                                'region_id': 'RegionOne',
                                'resource_name': 'volume',
                                'resource_limit': 10,
                                'description': 'test description'}]
        self.assertRaises(exception.SchemaValidationError,
                          self.create_limits_validator.validate,
                          request_to_validate)

    def test_validate_limit_update_request_with_invalid_input(self):
        _INVALID_FORMATS = [{'resource_name': 123},
                            {'resource_limit': 'not_int'},
                            {'resource_name': ''},
                            {'resource_name': 'a' * 256},
                            {'resource_limit': -10},
                            {'resource_limit': 10000000000000000},
                            {'description': 123}]
        for invalid_desc in _INVALID_FORMATS:
            request_to_validate = [{'project_id': uuid.uuid4().hex,
                                    'service_id': uuid.uuid4().hex,
                                    'region_id': 'RegionOne',
                                    'resource_name': 'volume',
                                    'resource_limit': 10,
                                    'description': 'test description'}]
            request_to_validate[0].update(invalid_desc)

            self.assertRaises(exception.SchemaValidationError,
                              self.update_limits_validator.validate,
                              request_to_validate)

    def test_validate_limit_create_request_with_addition_input_fails(self):
        request_to_validate = [{'service_id': uuid.uuid4().hex,
                                'region_id': 'RegionOne',
                                'resource_name': 'volume',
                                'resource_limit': 10,
                                'more_key': 'more_value'}]
        self.assertRaises(exception.SchemaValidationError,
                          self.create_limits_validator.validate,
                          request_to_validate)

    def test_validate_limit_update_request_with_addition_input_fails(self):
        request_to_validate = {'id': uuid.uuid4().hex,
                               'resource_limit': 10,
                               'more_key': 'more_value'}
        self.assertRaises(exception.SchemaValidationError,
                          self.update_limits_validator.validate,
                          request_to_validate)

    def test_validate_project_limit_create_request_without_required_fails(
            self):
        for key in ['project_id', 'service_id', 'resource_name',
                    'resource_limit']:
            request_to_validate = [{'project_id': uuid.uuid4().hex,
                                    'service_id': uuid.uuid4().hex,
                                    'region_id': 'RegionOne',
                                    'resource_name': 'volume',
                                    'resource_limit': 10}]
            request_to_validate[0].pop(key)
            self.assertRaises(exception.SchemaValidationError,
                              self.create_limits_validator.validate,
                              request_to_validate)

    def test_validate_domain_limit_create_request_without_required_fails(self):
        for key in ['domain_id', 'service_id', 'resource_name',
                    'resource_limit']:
            request_to_validate = [{'domain_id': uuid.uuid4().hex,
                                    'service_id': uuid.uuid4().hex,
                                    'region_id': 'RegionOne',
                                    'resource_name': 'volume',
                                    'resource_limit': 10}]
            request_to_validate[0].pop(key)
            self.assertRaises(exception.SchemaValidationError,
                              self.create_limits_validator.validate,
                              request_to_validate)

    def test_validate_limit_create_request_with_both_project_and_domain(self):
        request_to_validate = [{'project_id': uuid.uuid4().hex,
                                'domain_id': uuid.uuid4().hex,
                                'service_id': uuid.uuid4().hex,
                                'region_id': 'RegionOne',
                                'resource_name': 'volume',
                                'resource_limit': 10,
                                'description': 'test description'}]
        self.assertRaises(exception.SchemaValidationError,
                          self.create_limits_validator.validate,
                          request_to_validate)


class ApplicationCredentialValidatorTestCase(unit.TestCase):
    _valid_roles = [{'name': 'member'},
                    {'id': uuid.uuid4().hex},
                    {'id': str(uuid.uuid4())},
                    {'name': '_member_'}]
    _invalid_roles = [True, 123, None, {'badkey': 'badval'}]

    def setUp(self):
        super(ApplicationCredentialValidatorTestCase, self).setUp()

        create = app_cred_schema.application_credential_create
        self.create_app_cred_validator = validators.SchemaValidator(create)

    def test_validate_app_cred_request(self):
        request_to_validate = {
            'name': 'myappcred',
            'description': 'My App Cred',
            'roles': [{'name': 'member'}],
            'expires_at': 'tomorrow'
        }
        self.create_app_cred_validator.validate(request_to_validate)

    def test_validate_app_cred_request_without_name_fails(self):
        request_to_validate = {
            'description': 'My App Cred',
            'roles': [{'name': 'member'}],
            'expires_at': 'tomorrow'
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_app_cred_validator.validate,
                          request_to_validate)

    def test_validate_app_cred_with_invalid_expires_at_fails(self):
        request_to_validate = {
            'name': 'myappcred',
            'description': 'My App Cred',
            'roles': [{'name': 'member'}],
            'expires_at': 3
        }
        self.assertRaises(exception.SchemaValidationError,
                          self.create_app_cred_validator.validate,
                          request_to_validate)

    def test_validate_app_cred_with_null_expires_at_succeeds(self):
        request_to_validate = {
            'name': 'myappcred',
            'description': 'My App Cred',
            'roles': [{'name': 'member'}],
        }
        self.create_app_cred_validator.validate(request_to_validate)

    def test_validate_app_cred_with_unrestricted_flag_succeeds(self):
        request_to_validate = {
            'name': 'myappcred',
            'description': 'My App Cred',
            'roles': [{'name': 'member'}],
            'unrestricted': True
        }
        self.create_app_cred_validator.validate(request_to_validate)

    def test_validate_app_cred_with_secret_succeeds(self):
        request_to_validate = {
            'name': 'myappcred',
            'description': 'My App Cred',
            'roles': [{'name': 'member'}],
            'secret': 'secretsecretsecretsecret'
        }
        self.create_app_cred_validator.validate(request_to_validate)

    def test_validate_app_cred_invalid_roles_fails(self):
        for role in self._invalid_roles:
            request_to_validate = {
                'name': 'myappcred',
                'description': 'My App Cred',
                'roles': [role]
            }
            self.assertRaises(exception.SchemaValidationError,
                              self.create_app_cred_validator.validate,
                              request_to_validate)
