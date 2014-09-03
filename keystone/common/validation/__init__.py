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
"""Request body validating middleware for OpenStack Identity resources."""

import functools

from keystone.common.validation import validators


def validated(request_body_schema, resource_to_validate):
    """Register a schema to validate a resource reference.

    Registered schema will be used for validating a request body just before
    API method execution.

    :param request_body_schema: a schema to validate the resource reference
    :param resource_to_validate: the reference to validate

    """
    schema_validator = validators.SchemaValidator(request_body_schema)

    def add_validator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if resource_to_validate in kwargs:
                schema_validator.validate(kwargs[resource_to_validate])
            return func(*args, **kwargs)
        return wrapper
    return add_validator


def nullable(property_schema):
    """Clone a property schema into one that is nullable.

    :param dict property_schema: schema to clone into a nullable schema
    :returns: a new dict schema
    """
    # TODO(dstanek): deal with the case where type is already a list; we don't
    #                do that yet so I'm not wasting time on it
    new_schema = property_schema.copy()
    new_schema['type'] = [property_schema['type'], 'null']
    return new_schema


def add_array_type(property_schema):
    """Convert the parameter schema to be of type list.

    :param dict property_schema: schema to add array type to
    :returns: a new dict schema
    """
    new_schema = property_schema.copy()
    new_schema['type'] = [property_schema['type'], 'array']
    return new_schema
