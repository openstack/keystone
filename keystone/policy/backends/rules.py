# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 OpenStack, LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Policy engine for keystone"""

import os.path

from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging
from keystone.openstack.common import policy as common_policy
from keystone import policy


CONF = config.CONF
LOG = logging.getLogger(__name__)


_ENFORCER = None
_POLICY_PATH = None
_POLICY_CACHE = {}


def reset():
    global _POLICY_PATH
    global _POLICY_CACHE
    global _ENFORCER
    _POLICY_PATH = None
    _POLICY_CACHE = {}
    _ENFORCER = None


def init():
    global _POLICY_PATH
    global _POLICY_CACHE
    global _ENFORCER
    if not _POLICY_PATH:
        _POLICY_PATH = CONF.policy_file
        if not os.path.exists(_POLICY_PATH):
            _POLICY_PATH = CONF.find_file(_POLICY_PATH)
    if not _ENFORCER:
        _ENFORCER = common_policy.Enforcer(policy_file=_POLICY_PATH)
    utils.read_cached_file(_POLICY_PATH,
                           _POLICY_CACHE,
                           reload_func=_set_rules)


def _set_rules(data):
    global _ENFORCER
    default_rule = CONF.policy_default_rule
    _ENFORCER.set_rules(common_policy.Rules.load_json(
        data, default_rule))


def enforce(credentials, action, target, do_raise=True):
    """Verifies that the action is valid on the target in this context.

       :param credentials: user credentials
       :param action: string representing the action to be checked, which
                      should be colon separated for clarity.
       :param target: dictionary representing the object of the action
                      for object creation this should be a dictionary
                      representing the location of the object e.g.
                      {'project_id': object.project_id}
       :raises: `exception.Forbidden` if verification fails.

       Actions should be colon separated for clarity. For example:

        * identity:list_users

    """
    init()

    # Add the exception arguments if asked to do a raise
    extra = {}
    if do_raise:
        extra.update(exc=exception.ForbiddenAction, action=action,
                     do_raise=do_raise)

    return _ENFORCER.enforce(action, target, credentials, **extra)


class Policy(policy.Driver):
    def enforce(self, credentials, action, target):
        LOG.debug(_('enforce %(action)s: %(credentials)s'), {
            'action': action,
            'credentials': credentials})
        enforce(credentials, action, target)
