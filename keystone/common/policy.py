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

from oslo_policy import policy as common_policy

from keystone.common import policies
import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


_ENFORCER = None


def reset():
    global _ENFORCER
    _ENFORCER = None


def init():
    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = common_policy.Enforcer(CONF)
        register_rules(_ENFORCER)


def get_enforcer():
    # Here we pass an empty list of arguments because there aren't any
    # arguments that oslo.config or oslo.policy shouldn't already understand
    # from the CONF object. This makes things easier here because we don't have
    # to parse arguments passed in from the command line and remove unexpected
    # arguments before building a Config object.
    CONF([], project='keystone')
    init()
    return _ENFORCER


def enforce(credentials, action, target, do_raise=True):
    """Verify that the action is valid on the target in this context.

    :param credentials: user credentials
    :param action: string representing the action to be checked, which should
                   be colon separated for clarity.
    :param target: dictionary representing the object of the action for object
                   creation this should be a dictionary representing the
                   location of the object e.g. {'project_id':
                   object.project_id}
    :raises keystone.exception.Forbidden: If verification fails.

    Actions should be colon separated for clarity. For example:

    * identity:list_users

    """
    init()

    # Add the exception arguments if asked to do a raise
    extra = {}
    if do_raise:
        extra.update(exc=exception.ForbiddenAction, action=action,
                     do_raise=do_raise)

    try:
        return _ENFORCER.enforce(action, target, credentials, **extra)
    except common_policy.InvalidScope:
        raise exception.ForbiddenAction(action=action)


def register_rules(enforcer):
    enforcer.register_defaults(policies.list_rules())
