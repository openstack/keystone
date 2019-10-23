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

# NOTE(morgan): This entire module is to provide compatibility for the old
# @protected style decorator enforcement. All new enforcement should directly
# reference the Enforcer object itself.
from keystone.common.rbac_enforcer import enforcer
from keystone import conf


CONF = conf.CONF


# NOTE(morgan): Shared-state enforcer object
_ENFORCER = enforcer.RBACEnforcer()


def reset():
    _ENFORCER._reset()


def get_enforcer():
    """Entrypoint that must return the raw oslo.policy enforcer obj.

    This is utilized by the command-line policy tools.

    :returns: :class:`oslo_policy.policy.Enforcer`
    """
    CONF(project='keystone')
    return _ENFORCER._enforcer


enforce = _ENFORCER._enforce
