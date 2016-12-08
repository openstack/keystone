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

from keystone.cmd.doctor import caching
from keystone.cmd.doctor import credential
from keystone.cmd.doctor import database
from keystone.cmd.doctor import debug
from keystone.cmd.doctor import federation
from keystone.cmd.doctor import ldap
from keystone.cmd.doctor import security_compliance
from keystone.cmd.doctor import tokens
from keystone.cmd.doctor import tokens_fernet
import keystone.conf
from keystone.i18n import _


CONF = keystone.conf.CONF

SYMPTOM_PREFIX = 'symptom_'
SYMPTOM_MODULES = [
    caching,
    credential,
    database,
    debug,
    federation,
    ldap,
    security_compliance,
    tokens,
    tokens_fernet]


def diagnose():
    """Report diagnosis for any symptoms we find.

    Returns true when any symptoms are found, false otherwise.
    """
    symptoms_found = False

    for symptom in gather_symptoms():
        if CONF.debug:
            # Some symptoms may take a long time to check, so let's keep
            # curious users posted on our progress as we go.
            print(
                'Checking for %s...' %
                symptom.__name__[len(SYMPTOM_PREFIX):].replace('_', ' '))

        # All symptoms are just callables that return true when they match the
        # condition that they're looking for. When that happens, we need to
        # inform the user by providing some helpful documentation.
        if symptom():
            # We use this to keep track of our exit condition
            symptoms_found = True

            # Ignore 'H701: empty localization string' because we're definitely
            # passing a string here. Also, we include a line break here to
            # visually separate the symptom's description from any other
            # checks -- it provides a better user experience.
            print(_('\nWARNING: %s') % _(symptom.__doc__))  # noqa: See comment above.

    return symptoms_found


def gather_symptoms():
    """Gather all of the objects in this module that are named symptom_*."""
    symptoms = []
    for module in SYMPTOM_MODULES:
        for name in dir(module):
            if name.startswith(SYMPTOM_PREFIX):
                symptoms.append(getattr(module, name))
    return symptoms
