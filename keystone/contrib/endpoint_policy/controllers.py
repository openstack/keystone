# Copyright 2014 IBM Corp.
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

from keystone.common import controller
from keystone.common import dependency
from keystone import notifications


@dependency.requires('policy_api', 'catalog_api', 'endpoint_policy_api')
class EndpointPolicyV3Controller(controller.V3Controller):
    collection_name = 'endpoints'
    member_name = 'endpoint'

    def __init__(self):
        super(EndpointPolicyV3Controller, self).__init__()
        notifications.register_event_callback(
            'deleted', 'endpoint', self._on_endpoint_delete)
        notifications.register_event_callback(
            'deleted', 'service', self._on_service_delete)
        notifications.register_event_callback(
            'deleted', 'region', self._on_region_delete)
        notifications.register_event_callback(
            'deleted', 'policy', self._on_policy_delete)

    def _on_endpoint_delete(self, service, resource_type, operation, payload):
        self.endpoint_policy_api.delete_association_by_endpoint(
            payload['resource_info'])

    def _on_service_delete(self, service, resource_type, operation, payload):
        self.endpoint_policy_api.delete_association_by_service(
            payload['resource_info'])

    def _on_region_delete(self, service, resource_type, operation, payload):
        self.endpoint_policy_api.delete_association_by_region(
            payload['resource_info'])

    def _on_policy_delete(self, service, resource_type, operation, payload):
        self.endpoint_policy_api.delete_association_by_policy(
            payload['resource_info'])

    @controller.protected()
    def create_policy_association_for_endpoint(self, context,
                                               policy_id, endpoint_id):
        """Create an association between a policy and an endpoint."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_endpoint(endpoint_id)
        self.endpoint_policy_api.create_policy_association(
            policy_id, endpoint_id=endpoint_id)

    @controller.protected()
    def check_policy_association_for_endpoint(self, context,
                                              policy_id, endpoint_id):
        """Check an association between a policy and an endpoint."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_endpoint(endpoint_id)
        self.endpoint_policy_api.check_policy_association(
            policy_id, endpoint_id=endpoint_id)

    @controller.protected()
    def delete_policy_association_for_endpoint(self, context,
                                               policy_id, endpoint_id):
        """Delete an association between a policy and an endpoint."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_endpoint(endpoint_id)
        self.endpoint_policy_api.delete_policy_association(
            policy_id, endpoint_id=endpoint_id)

    @controller.protected()
    def create_policy_association_for_service(self, context,
                                              policy_id, service_id):
        """Create an association between a policy and a service."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_service(service_id)
        self.endpoint_policy_api.create_policy_association(
            policy_id, service_id=service_id)

    @controller.protected()
    def check_policy_association_for_service(self, context,
                                             policy_id, service_id):
        """Check an association between a policy and a service."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_service(service_id)
        self.endpoint_policy_api.check_policy_association(
            policy_id, service_id=service_id)

    @controller.protected()
    def delete_policy_association_for_service(self, context,
                                              policy_id, service_id):
        """Delete an association between a policy and a service."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_service(service_id)
        self.endpoint_policy_api.delete_policy_association(
            policy_id, service_id=service_id)

    @controller.protected()
    def create_policy_association_for_region_and_service(
            self, context, policy_id, service_id, region_id):
        """Create an association between a policy and region+service."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_service(service_id)
        self.catalog_api.get_region(region_id)
        self.endpoint_policy_api.create_policy_association(
            policy_id, service_id=service_id, region_id=region_id)

    @controller.protected()
    def check_policy_association_for_region_and_service(
            self, context, policy_id, service_id, region_id):
        """Check an association between a policy and region+service."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_service(service_id)
        self.catalog_api.get_region(region_id)
        self.endpoint_policy_api.check_policy_association(
            policy_id, service_id=service_id, region_id=region_id)

    @controller.protected()
    def delete_policy_association_for_region_and_service(
            self, context, policy_id, service_id, region_id):
        """Delete an association between a policy and region+service."""
        self.policy_api.get_policy(policy_id)
        self.catalog_api.get_service(service_id)
        self.catalog_api.get_region(region_id)
        self.endpoint_policy_api.delete_policy_association(
            policy_id, service_id=service_id, region_id=region_id)

    @controller.protected()
    def get_policy_for_endpoint(self, context, endpoint_id):
        """Get the effective policy for an endpoint."""
        self.catalog_api.get_endpoint(endpoint_id)
        ref = self.endpoint_policy_api.get_policy_for_endpoint(endpoint_id)
        # NOTE(henry-nash): since the collection and member for this class is
        # set to endpoints, we have to handle wrapping this policy entity
        # ourselves.
        self._add_self_referential_link(context, ref)
        return {'policy': ref}

    # NOTE(henry-nash): As in the catalog controller, we must ensure that the
    # legacy_endpoint_id does not escape.

    @classmethod
    def filter_endpoint(cls, ref):
        if 'legacy_endpoint_id' in ref:
            ref.pop('legacy_endpoint_id')
        return ref

    @classmethod
    def wrap_member(cls, context, ref):
        ref = cls.filter_endpoint(ref)
        return super(EndpointPolicyV3Controller, cls).wrap_member(context, ref)

    @controller.protected()
    def list_endpoints_for_policy(self, context, policy_id):
        """List endpoints with the effective association to a policy."""
        self.policy_api.get_policy(policy_id)
        refs = self.endpoint_policy_api.list_endpoints_for_policy(policy_id)
        return EndpointPolicyV3Controller.wrap_collection(context, refs)
