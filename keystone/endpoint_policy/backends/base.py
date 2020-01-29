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

from keystone import exception


class EndpointPolicyDriverBase(object, metaclass=abc.ABCMeta):
    """Interface description for an Endpoint Policy driver."""

    @abc.abstractmethod
    def create_policy_association(self, policy_id, endpoint_id=None,
                                  service_id=None, region_id=None):
        """Create a policy association.

        :param policy_id: identity of policy that is being associated
        :type policy_id: string
        :param endpoint_id: identity of endpoint to associate
        :type endpoint_id: string
        :param service_id: identity of the service to associate
        :type service_id: string
        :param region_id: identity of the region to associate
        :type region_id: string
        :returns: None

        There are three types of association permitted:

        - Endpoint (in which case service and region must be None)
        - Service and region (in which endpoint must be None)
        - Service (in which case endpoint and region must be None)

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_policy_association(self, policy_id, endpoint_id=None,
                                 service_id=None, region_id=None):
        """Check existence of a policy association.

        :param policy_id: identity of policy that is being associated
        :type policy_id: string
        :param endpoint_id: identity of endpoint to associate
        :type endpoint_id: string
        :param service_id: identity of the service to associate
        :type service_id: string
        :param region_id: identity of the region to associate
        :type region_id: string
        :raises keystone.exception.PolicyAssociationNotFound: If there is no
            match for the specified association.
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_policy_association(self, policy_id, endpoint_id=None,
                                  service_id=None, region_id=None):
        """Delete a policy association.

        :param policy_id: identity of policy that is being associated
        :type policy_id: string
        :param endpoint_id: identity of endpoint to associate
        :type endpoint_id: string
        :param service_id: identity of the service to associate
        :type service_id: string
        :param region_id: identity of the region to associate
        :type region_id: string
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_policy_association(self, endpoint_id=None,
                               service_id=None, region_id=None):
        """Get the policy for an explicit association.

        This method is not exposed as a public API, but is used by
        get_policy_for_endpoint().

        :param endpoint_id: identity of endpoint
        :type endpoint_id: string
        :param service_id: identity of the service
        :type service_id: string
        :param region_id: identity of the region
        :type region_id: string
        :raises keystone.exception.PolicyAssociationNotFound: If there is no
            match for the specified association.
        :returns: dict containing policy_id (value is a tuple containing only
                  the policy_id)

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_associations_for_policy(self, policy_id):
        """List the associations for a policy.

        This method is not exposed as a public API, but is used by
        list_endpoints_for_policy().

        :param policy_id: identity of policy
        :type policy_id: string
        :returns: List of association dicts

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_association_by_endpoint(self, endpoint_id):
        """Remove all the policy associations with the specific endpoint.

        :param endpoint_id: identity of endpoint to check
        :type endpoint_id: string
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_association_by_service(self, service_id):
        """Remove all the policy associations with the specific service.

        :param service_id: identity of endpoint to check
        :type service_id: string
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_association_by_region(self, region_id):
        """Remove all the policy associations with the specific region.

        :param region_id: identity of endpoint to check
        :type region_id: string
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_association_by_policy(self, policy_id):
        """Remove all the policy associations with the specific policy.

        :param policy_id: identity of endpoint to check
        :type policy_id: string
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover
