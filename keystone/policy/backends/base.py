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

import abc

import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


class PolicyDriverBase(object, metaclass=abc.ABCMeta):

    def _get_list_limit(self):
        return CONF.policy.list_limit or CONF.list_limit

    @abc.abstractmethod
    def enforce(self, context, credentials, action, target):
        """Verify that a user is authorized to perform action.

        For more information on a full implementation of this see:
        `keystone.policy.backends.rules.Policy.enforce`
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_policy(self, policy_id, policy):
        """Store a policy blob.

        :raises keystone.exception.Conflict: If a duplicate policy exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_policies(self):
        """List all policies."""
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_policy(self, policy_id):
        """Retrieve a specific policy blob.

        :raises keystone.exception.PolicyNotFound: If the policy doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_policy(self, policy_id, policy):
        """Update a policy blob.

        :raises keystone.exception.PolicyNotFound: If the policy doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_policy(self, policy_id):
        """Remove a policy blob.

        :raises keystone.exception.PolicyNotFound: If the policy doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover
