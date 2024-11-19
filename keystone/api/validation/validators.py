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

"""Internal implementation of request/response validating middleware."""

import re

import jsonschema
from jsonschema import exceptions as jsonschema_exc
from oslo_utils import timeutils
from oslo_utils import uuidutils
import webob.exc

from keystone.common import utils
from keystone import exception
from keystone.i18n import _


def _soft_validate_additional_properties(
    validator, additional_properties_value, param_value, schema
):
    """Validator function.

    If there are not any properties on the param_value that are not specified
    in the schema, this will return without any effect. If there are any such
    extra properties, they will be handled as follows:

    - if the validator passed to the method is not of type "object", this
      method will return without any effect.
    - if the 'additional_properties_value' parameter is True, this method will
      return without any effect.
    - if the schema has an additionalProperties value of True, the extra
      properties on the param_value will not be touched.
    - if the schema has an additionalProperties value of False and there
      aren't patternProperties specified, the extra properties will be stripped
      from the param_value.
    - if the schema has an additionalProperties value of False and there
      are patternProperties specified, the extra properties will not be
      touched and raise validation error if pattern doesn't match.
    """
    if not (
        validator.is_type(param_value, "object") or additional_properties_value
    ):
        return

    properties = schema.get("properties", {})
    patterns = "|".join(schema.get("patternProperties", {}))
    extra_properties = set()
    for prop in param_value:
        if prop not in properties:
            if patterns:
                if not re.search(patterns, prop):
                    extra_properties.add(prop)
            else:
                extra_properties.add(prop)

    if not extra_properties:
        return

    if patterns:
        error = "Additional properties are not allowed (%s %s unexpected)"
        if len(extra_properties) == 1:
            verb = "was"
        else:
            verb = "were"
        yield jsonschema_exc.ValidationError(
            error
            % (", ".join(repr(extra) for extra in extra_properties), verb)
        )
    else:
        for prop in extra_properties:
            del param_value[prop]


def _validate_string_length(
    value,
    entity_name,
    mandatory=False,
    min_length=0,
    max_length=None,
    remove_whitespaces=False,
):
    """Check the length of specified string.

    :param value: the value of the string
    :param entity_name: the name of the string
    :mandatory: string is mandatory or not
    :param min_length: the min_length of the string
    :param max_length: the max_length of the string
    :param remove_whitespaces: True if trimming whitespaces is needed else
        False
    """
    if not mandatory and not value:
        return True

    if mandatory and not value:
        msg = _("The '%s' can not be None.") % entity_name
        raise webob.exc.HTTPBadRequest(explanation=msg)

    if remove_whitespaces:
        value = value.strip()

    utils.check_string_length(
        value, entity_name, min_length=min_length, max_length=max_length
    )


_FORMAT_CHECKER = jsonschema.FormatChecker()


@_FORMAT_CHECKER.checks("date-time")
def _validate_datetime_format(instance: object) -> bool:
    # format checks constrain to the relevant primitive type
    # https://github.com/OAI/OpenAPI-Specification/issues/3148
    if not isinstance(instance, str):
        return True
    try:
        timeutils.parse_isotime(instance)
    except ValueError:
        return False
    else:
        return True


@_FORMAT_CHECKER.checks("uuid")
def _validate_uuid_format(instance: object) -> bool:
    # format checks constrain to the relevant primitive type
    # https://github.com/OAI/OpenAPI-Specification/issues/3148
    if not isinstance(instance, str):
        return True

    return uuidutils.is_uuid_like(instance)


class _SchemaValidator:
    """A validator class.

    This class is changed from Draft202012Validator to validate minimum/maximum
    value of a string number(e.g. '10').

    In addition, FormatCheckers are added for checking data formats which are
    common in the Manila API.
    """

    validator = None
    validator_org = jsonschema.Draft202012Validator

    def __init__(
        self, schema, relax_additional_properties=False, is_body=True
    ):
        self.is_body = is_body
        validators = {
            "minimum": self._validate_minimum,
            "maximum": self._validate_maximum,
        }
        if relax_additional_properties:
            validators["additionalProperties"] = (
                _soft_validate_additional_properties
            )

        validator_cls = jsonschema.validators.extend(
            self.validator_org, validators
        )
        self.validator = validator_cls(schema, format_checker=_FORMAT_CHECKER)

    def validate(self, *args, **kwargs):
        try:
            self.validator.validate(*args, **kwargs)
        except jsonschema.ValidationError as ex:
            if len(ex.path) > 0:
                if self.is_body:
                    # NOTE: For consistency across OpenStack services, this
                    # error message has been written in a similar format as
                    # WSME errors.
                    detail = _(
                        "Invalid input for field/attribute %(path)s. "
                        "Value: %(value)s. %(message)s"
                    ) % {
                        "path": ex.path.pop(),
                        "value": ex.instance,
                        "message": ex.message,
                    }
                else:
                    # NOTE: We use 'ex.path.popleft()' instead of
                    # 'ex.path.pop()'. This is due to the structure of query
                    # parameters which is a dict with key as name and value is
                    # list. As such, the first item in the 'ex.path' is the key
                    # and second item is the index of list in the value. We
                    # need the key as the parameter name in the error message
                    # so we pop the first value out of 'ex.path'.
                    detail = _(
                        "Invalid input for query parameters %(path)s. "
                        "Value: %(value)s. %(message)s"
                    ) % {
                        "path": ex.path.popleft(),
                        "value": ex.instance,
                        "message": ex.message,
                    }
            else:
                detail = ex.message
            raise exception.SchemaValidationError(detail=detail)
        except TypeError as ex:
            # NOTE: If passing non string value to patternProperties parameter,
            # TypeError happens. Here is for catching the TypeError.
            detail = str(ex)
            raise exception.SchemaValidationError(detail=detail)

    def _number_from_str(self, param_value):
        try:
            value = int(param_value)
        except (ValueError, TypeError):
            try:
                value = float(param_value)
            except (ValueError, TypeError):
                return None
        return value

    def _validate_minimum(self, validator, minimum, param_value, schema):
        param_value = self._number_from_str(param_value)
        if param_value is None:
            return
        return self.validator_org.VALIDATORS["minimum"](
            validator, minimum, param_value, schema
        )

    def _validate_maximum(self, validator, maximum, param_value, schema):
        param_value = self._number_from_str(param_value)
        if param_value is None:
            return
        return self.validator_org.VALIDATORS["maximum"](
            validator, maximum, param_value, schema
        )
