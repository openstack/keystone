# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""API request/response validating middleware."""

import functools
import typing as ty

import flask
from oslo_serialization import jsonutils

from keystone.api.validation import validators


def validated(cls):
    cls._validated = True
    return cls


def _schema_validator(
    schema: ty.Dict[str, ty.Any],
    target: ty.Dict[str, ty.Any],
    args: ty.Any,
    kwargs: ty.Any,
    is_body: bool = True,
):
    """A helper method to execute JSON Schema Validation.

    This method checks the request version whether matches the specified
    ``max_version`` and ``min_version``. If the version range matches the
    request, we validate ``schema`` against ``target``. A failure will result
    in ``ValidationError`` being raised.

    :param schema: The JSON Schema schema used to validate the target.
    :param target: The target to be validated by the schema.
    :param args: Positional arguments which passed into original method.
    :param kwargs: Keyword arguments which passed into original method.
    :param is_body: Whether ``target`` is a HTTP request body or not.
    :returns: None.
    :raises: ``ValidationError`` if validation fails.
    """
    schema_validator = validators._SchemaValidator(schema, is_body=is_body)
    schema_validator.validate(target)


def request_body_schema(schema: ty.Optional[ty.Dict[str, ty.Any]] = None):
    """Register a schema to validate request body.

    ``schema`` will be used for validating the request body just before the API
    method is executed.

    :param schema: The JSON Schema schema used to validate the target. If
        empty value is passed no validation will be performed.
    :param min_version: A string indicating the minimum API version ``schema``
        applies against.
    :param max_version: A string indicating the maximum API version ``schema``
        applies against.
    """

    def add_validator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if schema is not None:
                _schema_validator(
                    schema,
                    flask.request.get_json(silent=True, force=True) or {},
                    args,
                    kwargs,
                    is_body=True,
                )
            return func(*args, **kwargs)

        wrapper._request_body_schema = schema

        return wrapper

    return add_validator


def request_query_schema(schema: ty.Optional[ty.Dict[str, ty.Any]] = None):
    """Register a schema to validate request query string parameters.

    ``schema`` will be used for validating request query strings just before
    the API method is executed.

    :param schema: The JSON Schema schema used to validate the target. If
        empty value is passed no validation will be performed.
    """

    def add_validator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if schema is not None:
                # NOTE: The request object is always the second argument.
                # However, numerous unittests pass in the request object
                # via kwargs instead so we handle that as well.
                # TODO(stephenfin): Fix unit tests so we don't have to do this
                if "req" in kwargs:
                    req = kwargs["req"]
                else:
                    req = flask.request.args

                _schema_validator(schema, req, args, kwargs, is_body=True)
            return func(*args, **kwargs)

        wrapper._request_query_schema = schema

        return wrapper

    return add_validator


def response_body_schema(schema: ty.Optional[ty.Dict[str, ty.Any]] = None):
    """Register a schema to validate response body.

    ``schema`` will be used for validating the response body just after the API
    method is executed.

    :param schema: The JSON Schema schema used to validate the target. If
        empty value is passed no validation will be performed.
    :param min_version: A string indicating the minimum API version ``schema``
        applies against.
    :param max_version: A string indicating the maximum API version ``schema``
        applies against.
    """

    def add_validator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            response = func(*args, **kwargs)

            if schema is not None:
                # In Flask it is not uncommon that the method return a tuple of
                # body and the status code. In the runtime Keystone only return
                # a body, but some of the used testtools do return a tuple.
                if isinstance(response, tuple):
                    _body = response[0]
                else:
                    _body = response

                # NOTE(stephenfin): If our response is an object, we need to
                # serializer and deserialize to convert e.g. date-time
                # to strings
                _body = jsonutils.dump_as_bytes(_body)

                if _body == b"":
                    body = None
                else:
                    body = jsonutils.loads(_body)

                _schema_validator(schema, body, args, kwargs, is_body=True)
            return response

        wrapper._response_body_schema = schema

        return wrapper

    return add_validator
