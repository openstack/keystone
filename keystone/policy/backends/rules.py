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

from oslo_config import cfg
from oslo_log import log
from oslo_policy import policy as common_policy

from keystone import exception
from keystone import policy


CONF = cfg.CONF
LOG = log.getLogger(__name__)


_ENFORCER = None


def reset():
    global _ENFORCER
    _ENFORCER = None


def init():
    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = common_policy.Enforcer(CONF)


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


class Policy(policy.PolicyDriverV8):
    def enforce(self, credentials, action, target):
        LOG.debug('enforce %(action)s: %(credentials)s', {
            'action': action,
            'credentials': credentials})
        enforce(credentials, action, target)

    def create_policy(self, policy_id, policy):
        raise exception.NotImplemented()

    def list_policies(self):
        raise exception.NotImplemented()

    def get_policy(self, policy_id):
        raise exception.NotImplemented()

    def update_policy(self, policy_id, policy):
        raise exception.NotImplemented()

    def delete_policy(self, policy_id):
        raise exception.NotImplemented()
