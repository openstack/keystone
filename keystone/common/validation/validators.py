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
"""Internal implementation of request body validating middleware."""

import re

import jsonschema
from oslo_config import cfg
from oslo_log import log

from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
LOG = log.getLogger(__name__)


# TODO(rderose): extend schema validation and add this check there
def validate_password(password):
    pattern = CONF.security_compliance.password_regex
    if pattern:
        if not isinstance(password, str):
            detail = _("Password must be a string type")
            raise exception.PasswordValidationError(detail=detail)
        try:
            if not re.match(pattern, password):
                pattern_desc = (
                    CONF.security_compliance.password_regex_description)
                raise exception.PasswordRequirementsValidationError(
                    detail=pattern_desc)
        except re.error:
            msg = ("Unable to validate password due to invalid regular "
                   "expression - password_regex: %s")
            LOG.error(msg, pattern)
            detail = _("Unable to validate password due to invalid "
                       "configuration")
            raise exception.PasswordValidationError(detail=detail)


class SchemaValidator(object):
    """Resource reference validator class."""

    validator_org = jsonschema.Draft4Validator

    def __init__(self, schema):
        # NOTE(lbragstad): If at some point in the future we want to extend
        # our validators to include something specific we need to check for,
        # we can do it here. Nova's V3 API validators extend the validator to
        # include `self._validate_minimum` and `self._validate_maximum`. This
        # would be handy if we needed to check for something the jsonschema
        # didn't by default. See the Nova V3 validator for details on how this
        # is done.
        validators = {}
        validator_cls = jsonschema.validators.extend(self.validator_org,
                                                     validators)
        fc = jsonschema.FormatChecker()
        self.validator = validator_cls(schema, format_checker=fc)

    def validate(self, *args, **kwargs):
        try:
            self.validator.validate(*args, **kwargs)
        except jsonschema.ValidationError as ex:
            # NOTE: For whole OpenStack message consistency, this error
            # message has been written in a format consistent with WSME.
            if ex.path:
                # NOTE(lbragstad): Here we could think about using iter_errors
                # as a method of providing invalid parameters back to the
                # user.
                # TODO(lbragstad): If the value of a field is confidential or
                # too long, then we should build the masking in here so that
                # we don't expose sensitive user information in the event it
                # fails validation.
                path = '/'.join(map(str, ex.path))
                detail = _("Invalid input for field '%(path)s': "
                           "%(message)s") % {'path': path,
                                             'message': str(ex)}
            else:
                detail = str(ex)
            raise exception.SchemaValidationError(detail=detail)
