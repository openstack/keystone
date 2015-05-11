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

import uuid

from six.moves import range
from testtools import matchers

from keystone import exception


class PolicyAssociationTests(object):

    def _assert_correct_policy(self, endpoint, policy):
        ref = (
            self.endpoint_policy_api.get_policy_for_endpoint(endpoint['id']))
        self.assertEqual(policy['id'], ref['id'])

    def _assert_correct_endpoints(self, policy, endpoint_list):
        endpoint_id_list = [ep['id'] for ep in endpoint_list]
        endpoints = (
            self.endpoint_policy_api.list_endpoints_for_policy(policy['id']))
        self.assertThat(endpoints, matchers.HasLength(len(endpoint_list)))
        for endpoint in endpoints:
            self.assertIn(endpoint['id'], endpoint_id_list)

    def load_sample_data(self):
        """Create sample data to test policy associations.

        The following data is created:

        - 3 regions, in a hierarchy, 0 -> 1 -> 2 (where 0 is top)
        - 3 services
        - 6 endpoints, 2 in each region, with a mixture of services:
          0 - region 0, Service 0
          1 - region 0, Service 1
          2 - region 1, Service 1
          3 - region 1, Service 2
          4 - region 2, Service 2
          5 - region 2, Service 0

        """

        def new_endpoint(region_id, service_id):
            endpoint = {'id': uuid.uuid4().hex, 'interface': 'test',
                        'region_id': region_id, 'service_id': service_id,
                        'url': '/url'}
            self.endpoint.append(self.catalog_api.create_endpoint(
                endpoint['id'], endpoint))

        self.policy = []
        self.endpoint = []
        self.service = []
        self.region = []
        for i in range(3):
            policy = {'id': uuid.uuid4().hex, 'type': uuid.uuid4().hex,
                      'blob': {'data': uuid.uuid4().hex}}
            self.policy.append(self.policy_api.create_policy(policy['id'],
                                                             policy))
            service = {'id': uuid.uuid4().hex, 'type': uuid.uuid4().hex}
            self.service.append(self.catalog_api.create_service(service['id'],
                                                                service))
            region = {'id': uuid.uuid4().hex, 'description': uuid.uuid4().hex}
            # Link the 3 regions together as a hierarchy, [0] at the top
            if i != 0:
                region['parent_region_id'] = self.region[i - 1]['id']
            self.region.append(self.catalog_api.create_region(region))

        new_endpoint(self.region[0]['id'], self.service[0]['id'])
        new_endpoint(self.region[0]['id'], self.service[1]['id'])
        new_endpoint(self.region[1]['id'], self.service[1]['id'])
        new_endpoint(self.region[1]['id'], self.service[2]['id'])
        new_endpoint(self.region[2]['id'], self.service[2]['id'])
        new_endpoint(self.region[2]['id'], self.service[0]['id'])

    def test_policy_to_endpoint_association_crud(self):
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], endpoint_id=self.endpoint[0]['id'])
        self.endpoint_policy_api.check_policy_association(
            self.policy[0]['id'], endpoint_id=self.endpoint[0]['id'])
        self.endpoint_policy_api.delete_policy_association(
            self.policy[0]['id'], endpoint_id=self.endpoint[0]['id'])
        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[0]['id'],
                          endpoint_id=self.endpoint[0]['id'])

    def test_overwriting_policy_to_endpoint_association(self):
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], endpoint_id=self.endpoint[0]['id'])
        self.endpoint_policy_api.create_policy_association(
            self.policy[1]['id'], endpoint_id=self.endpoint[0]['id'])
        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[0]['id'],
                          endpoint_id=self.endpoint[0]['id'])
        self.endpoint_policy_api.check_policy_association(
            self.policy[1]['id'], endpoint_id=self.endpoint[0]['id'])

    def test_invalid_policy_to_endpoint_association(self):
        self.assertRaises(exception.InvalidPolicyAssociation,
                          self.endpoint_policy_api.create_policy_association,
                          self.policy[0]['id'])
        self.assertRaises(exception.InvalidPolicyAssociation,
                          self.endpoint_policy_api.create_policy_association,
                          self.policy[0]['id'],
                          endpoint_id=self.endpoint[0]['id'],
                          region_id=self.region[0]['id'])
        self.assertRaises(exception.InvalidPolicyAssociation,
                          self.endpoint_policy_api.create_policy_association,
                          self.policy[0]['id'],
                          endpoint_id=self.endpoint[0]['id'],
                          service_id=self.service[0]['id'])
        self.assertRaises(exception.InvalidPolicyAssociation,
                          self.endpoint_policy_api.create_policy_association,
                          self.policy[0]['id'],
                          region_id=self.region[0]['id'])

    def test_policy_to_explicit_endpoint_association(self):
        # Associate policy 0 with endpoint 0
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], endpoint_id=self.endpoint[0]['id'])
        self._assert_correct_policy(self.endpoint[0], self.policy[0])
        self._assert_correct_endpoints(self.policy[0], [self.endpoint[0]])
        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.get_policy_for_endpoint,
                          uuid.uuid4().hex)

    def test_policy_to_service_association(self):
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], service_id=self.service[0]['id'])
        self.endpoint_policy_api.create_policy_association(
            self.policy[1]['id'], service_id=self.service[1]['id'])

        # Endpoints 0 and 5 are part of service 0
        self._assert_correct_policy(self.endpoint[0], self.policy[0])
        self._assert_correct_policy(self.endpoint[5], self.policy[0])
        self._assert_correct_endpoints(
            self.policy[0], [self.endpoint[0], self.endpoint[5]])

        # Endpoints 1 and 2 are part of service 1
        self._assert_correct_policy(self.endpoint[1], self.policy[1])
        self._assert_correct_policy(self.endpoint[2], self.policy[1])
        self._assert_correct_endpoints(
            self.policy[1], [self.endpoint[1], self.endpoint[2]])

    def test_policy_to_region_and_service_association(self):
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], service_id=self.service[0]['id'],
            region_id=self.region[0]['id'])
        self.endpoint_policy_api.create_policy_association(
            self.policy[1]['id'], service_id=self.service[1]['id'],
            region_id=self.region[1]['id'])
        self.endpoint_policy_api.create_policy_association(
            self.policy[2]['id'], service_id=self.service[2]['id'],
            region_id=self.region[2]['id'])

        # Endpoint 0 is in region 0 with service 0, so should get policy 0
        self._assert_correct_policy(self.endpoint[0], self.policy[0])
        # Endpoint 5 is in Region 2 with service 0, so should also get
        # policy 0 by searching up the tree to Region 0
        self._assert_correct_policy(self.endpoint[5], self.policy[0])

        # Looking the other way round, policy 2 should only be in use by
        # endpoint 4, since that's the only endpoint in region 2 with the
        # correct service
        self._assert_correct_endpoints(
            self.policy[2], [self.endpoint[4]])
        # Policy 1 should only be in use by endpoint 2, since that's the only
        # endpoint in region 1 (and region 2 below it) with the correct service
        self._assert_correct_endpoints(
            self.policy[1], [self.endpoint[2]])
        # Policy 0 should be in use by endpoint 0, as well as 5 (since 5 is
        # of the correct service and in region 2 below it)
        self._assert_correct_endpoints(
            self.policy[0], [self.endpoint[0], self.endpoint[5]])

    def test_delete_association_by_entity(self):
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], endpoint_id=self.endpoint[0]['id'])
        self.endpoint_policy_api.delete_association_by_endpoint(
            self.endpoint[0]['id'])
        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[0]['id'],
                          endpoint_id=self.endpoint[0]['id'])
        # Make sure deleting it again is silent - since this method is used
        # in response to notifications by the controller.
        self.endpoint_policy_api.delete_association_by_endpoint(
            self.endpoint[0]['id'])

        # Now try with service - ensure both combined region & service
        # associations and explicit service ones are removed
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], service_id=self.service[0]['id'],
            region_id=self.region[0]['id'])
        self.endpoint_policy_api.create_policy_association(
            self.policy[1]['id'], service_id=self.service[0]['id'],
            region_id=self.region[1]['id'])
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], service_id=self.service[0]['id'])

        self.endpoint_policy_api.delete_association_by_service(
            self.service[0]['id'])

        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[0]['id'],
                          service_id=self.service[0]['id'],
                          region_id=self.region[0]['id'])
        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[1]['id'],
                          service_id=self.service[0]['id'],
                          region_id=self.region[1]['id'])
        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[0]['id'],
                          service_id=self.service[0]['id'])

        # Finally, check delete by region
        self.endpoint_policy_api.create_policy_association(
            self.policy[0]['id'], service_id=self.service[0]['id'],
            region_id=self.region[0]['id'])

        self.endpoint_policy_api.delete_association_by_region(
            self.region[0]['id'])

        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[0]['id'],
                          service_id=self.service[0]['id'],
                          region_id=self.region[0]['id'])
        self.assertRaises(exception.NotFound,
                          self.endpoint_policy_api.check_policy_association,
                          self.policy[0]['id'],
                          service_id=self.service[0]['id'])
