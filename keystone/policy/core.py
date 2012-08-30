# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
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

"""Main entry point into the Policy service."""


from keystone.common import manager
from keystone.common import controller
from keystone import config
from keystone import exception


CONF = config.CONF


class Manager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.policy.driver)

    def get_policy(self, context, policy_id):
        try:
            return self.driver.get_policy(policy_id)
        except exception.NotFound:
            raise exception.PolicyNotFound(policy_id=policy_id)

    def update_policy(self, context, policy_id, policy):
        if 'id' in policy and policy_id != policy['id']:
            raise exception.ValidationError('Cannot change policy ID')
        try:
            return self.driver.update_policy(policy_id, policy)
        except exception.NotFound:
            raise exception.PolicyNotFound(policy_id=policy_id)

    def delete_policy(self, context, policy_id):
        try:
            return self.driver.delete_policy(policy_id)
        except exception.NotFound:
            raise exception.PolicyNotFound(policy_id=policy_id)


class Driver(object):
    def enforce(context, credentials, action, target):
        """Verify that a user is authorized to perform action.

        For more information on a full implementation of this see:
        `keystone.common.policy.enforce`.
        """
        raise exception.NotImplemented()

    def create_policy(self, policy_id, policy):
        """Store a policy blob.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_policies(self):
        """List all policies."""
        raise exception.NotImplemented()

    def get_policy(self, policy_id):
        """Retrieve a specific policy blob.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()

    def update_policy(self, policy_id, policy):
        """Update a policy blob.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()

    def delete_policy(self, policy_id):
        """Remove a policy blob.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()


class PolicyControllerV3(controller.V3Controller):
    @controller.protected
    def create_policy(self, context, policy):
        ref = self._assign_unique_id(self._normalize_dict(policy))
        self._require_attribute(ref, 'blob')
        self._require_attribute(ref, 'type')

        ref = self.policy_api.create_policy(context, ref['id'], ref)
        return {'policy': ref}

    @controller.protected
    def list_policies(self, context):
        refs = self.policy_api.list_policies(context)
        refs = self._filter_by_attribute(context, refs, 'type')
        return {'policies': self._paginate(context, refs)}

    @controller.protected
    def get_policy(self, context, policy_id):
        ref = self.policy_api.get_policy(context, policy_id)
        return {'policy': ref}

    @controller.protected
    def update_policy(self, context, policy_id, policy):
        ref = self.policy_api.update_policy(context, policy_id, policy)
        return {'policy': ref}

    @controller.protected
    def delete_policy(self, context, policy_id):
        return self.policy_api.delete_policy(context, policy_id)
