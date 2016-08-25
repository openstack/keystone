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

import keystone.conf


CONF = keystone.conf.CONF


def symptom_minimum_password_age_should_be_less_than_password_expires_days():
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
