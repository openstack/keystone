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

import re

import keystone.conf


CONF = keystone.conf.CONF


def symptom_minimum_password_age_greater_than_expires_days():
    """Minimum password age should be less than the password expires days.

    If the minimum password age is greater than or equal to the password
    expires days, then users would not be able to change their passwords before
    they expire.

    Ensure `[security_compliance] minimum_password_age` is less than the
    `[security_compliance] password_expires_days`.
    """
    min_age = CONF.security_compliance.minimum_password_age
    expires = CONF.security_compliance.password_expires_days
    return (min_age >= expires) if (min_age > 0 and expires > 0) else False


def symptom_invalid_password_regular_expression():
    """Invalid password regular expression.

    The password regular expression is invalid and users will not be able to
    make password changes until this has been corrected.

    Ensure `[security_compliance] password_regex` is a valid regular
    expression.
    """
    try:
        if CONF.security_compliance.password_regex:
            re.match(CONF.security_compliance.password_regex, 'password')
        return False
    except re.error:
        return True


def symptom_password_regular_expression_description_not_set():
    """Password regular expression description is not set.

    The password regular expression is set, but the description is not. Thus,
    if a user fails the password regular expression, they will not receive a
    message to explain why their requested password was insufficient.

    Ensure `[security_compliance] password_regex_description` is set with a
    description of your password regular expression in a language for humans.
    """
    return (CONF.security_compliance.password_regex and not
            CONF.security_compliance.password_regex_description)
