# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import resource_options
from keystone.common.validation import parameter_types
from keystone.i18n import _


def _mfa_rules_validator_list_of_lists_of_strings_no_duplicates(value):
    # NOTE(notmorgan): This should possibly validate that the auth-types
    # are enabled? For now it simply validates the following:
    #
    # Must be a list of lists, each sub list must be a list of strings
    # e.g. [['str1', 'str2'], ['str3', 'str4']]
    # No sub-list may be empty. Duplication of sub-lists and duplication of
    # string elements are not permitted.
    msg = _('Invalid data type, must be a list of lists comprised of strings. '
            'Sub-lists may not be duplicated. Strings in sub-lists may not be '
            'duplicated.')
    if not isinstance(value, list):
        # Value is not a List, TypeError
        raise TypeError(msg)
    sublists = []
    for sublist in value:
        # Sublist element tracker is reset for each sublist.
        string_set = set()
        if not isinstance(sublist, list):
            # Sublist is not a List, TypeError
            raise TypeError(msg)
        if not sublist:
            # Sublist is Empty, ValueError
            raise ValueError(msg)
        if sublist in sublists:
            # Sublist is duplicated, ValueError
            raise ValueError(msg)
        # Add the sublist to the tracker
        sublists.append(sublist)
        for element in sublist:
            if not isinstance(element, str):
                # Element of sublist is not a string, TypeError
                raise TypeError(msg)
            if element in string_set:
                # Element of sublist is duplicated, ValueError
                raise ValueError(msg)
            # add element to the sublist element tracker
            string_set.add(element)


USER_OPTIONS_REGISTRY = resource_options.ResourceOptionRegistry('USER')
IGNORE_CHANGE_PASSWORD_OPT = (
    resource_options.ResourceOption(
        option_id='1000',
        option_name='ignore_change_password_upon_first_use',
        validator=resource_options.boolean_validator,
        json_schema_validation=parameter_types.boolean))
IGNORE_PASSWORD_EXPIRY_OPT = (
    resource_options.ResourceOption(
        option_id='1001',
        option_name='ignore_password_expiry',
        validator=resource_options.boolean_validator,
        json_schema_validation=parameter_types.boolean))
IGNORE_LOCKOUT_ATTEMPT_OPT = (
    resource_options.ResourceOption(
        option_id='1002',
        option_name='ignore_lockout_failure_attempts',
        validator=resource_options.boolean_validator,
        json_schema_validation=parameter_types.boolean))
LOCK_PASSWORD_OPT = (
    resource_options.ResourceOption(
        option_id='1003',
        option_name='lock_password',
        validator=resource_options.boolean_validator,
        json_schema_validation=parameter_types.boolean))
IGNORE_USER_INACTIVITY_OPT = (
    resource_options.ResourceOption(
        option_id='1004',
        option_name='ignore_user_inactivity',
        validator=resource_options.boolean_validator,
        json_schema_validation=parameter_types.boolean))
MFA_RULES_OPT = (
    resource_options.ResourceOption(
        option_id='MFAR',
        option_name='multi_factor_auth_rules',
        validator=_mfa_rules_validator_list_of_lists_of_strings_no_duplicates,
        json_schema_validation={
            # List
            'type': 'array',
            'items': {
                # Of Lists
                'type': 'array',
                'items': {
                    # Of Strings, each string must be unique, minimum 1
                    # element
                    'type': 'string',
                },
                'minItems': 1,
                'uniqueItems': True
            },
            'uniqueItems': True
        }))
MFA_ENABLED_OPT = (
    resource_options.ResourceOption(
        option_id='MFAE',
        option_name='multi_factor_auth_enabled',
        validator=resource_options.boolean_validator,
        json_schema_validation=parameter_types.boolean))


# NOTE(notmorgan): wrap this in a function for testing purposes.
# This is called on import by design.
def register_user_options():
    for opt in [
        IGNORE_CHANGE_PASSWORD_OPT,
        IGNORE_PASSWORD_EXPIRY_OPT,
        IGNORE_LOCKOUT_ATTEMPT_OPT,
        LOCK_PASSWORD_OPT,
        IGNORE_USER_INACTIVITY_OPT,
        MFA_RULES_OPT,
        MFA_ENABLED_OPT,
    ]:
        USER_OPTIONS_REGISTRY.register_option(opt)


register_user_options()
