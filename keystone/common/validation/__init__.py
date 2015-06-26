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
import inspect

from keystone.common.validation import validators
from keystone import exception
from keystone.i18n import _


def validated(request_body_schema, resource_to_validate):
    """Register a schema to validate a resource reference.

    Registered schema will be used for validating a request body just before
    API method execution.

    :param request_body_schema: a schema to validate the resource reference
    :param resource_to_validate: the reference to validate
    :raises keystone.exception.ValidationError: if `resource_to_validate` is
            not passed by or passed with an empty value (see wrapper method
            below).
    :raises TypeError: at decoration time when the expected resource to
                       validate isn't found in the decorated method's
                       signature

    """
    schema_validator = validators.SchemaValidator(request_body_schema)

    def add_validator(func):
        argspec = inspect.getargspec(func)
        try:
            arg_index = argspec.args.index(resource_to_validate)
        except ValueError:
            raise TypeError(_('validated expected to find %(param_name)r in '
                              'function signature for %(func_name)r.') %
                            {'param_name': resource_to_validate,
                             'func_name': func.__name__})

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if kwargs.get(resource_to_validate):
                schema_validator.validate(kwargs[resource_to_validate])
            else:
                try:
                    resource = args[arg_index]
                    # If resource to be validated is empty, no need to do
                    # validation since the message given by jsonschema doesn't
                    # help in this case.
                    if resource:
                        schema_validator.validate(resource)
                    else:
                        raise exception.ValidationError(
                            attribute=resource_to_validate,
                            target='request body')
                # We cannot find the resource neither from kwargs nor args.
                except IndexError:
                    raise exception.ValidationError(
                        attribute=resource_to_validate,
                        target='request body')
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
