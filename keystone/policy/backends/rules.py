# Copyright (c) 2011 OpenStack Foundation
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

"""Policy engine for keystone."""

from oslo_log import log

from keystone.common.rbac_enforcer import policy
from keystone import exception
from keystone.policy.backends import base


LOG = log.getLogger(__name__)


class Policy(base.PolicyDriverBase):
    def enforce(self, credentials, action, target):
        msg = 'enforce %(action)s: %(credentials)s'
        LOG.debug(msg, {
            'action': action,
            'credentials': credentials})
        policy.enforce(credentials, action, target)

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
