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

from keystone import exception


class DriverTestCase(object):
    """Test cases to validate the endpoint policy driver behavior."""

    @property
    def driver(self):
        raise exception.NotImplemented()

    def create_association(self, **kwargs):
        association = {'policy_id': uuid.uuid4().hex,
                       'endpoint_id': None,
                       'service_id': None,
                       'region_id': None}
        association.update(kwargs)
        self.driver.create_policy_association(**association)
        return association

    def test_create_policy_association(self):
        association = self.create_association(endpoint_id=uuid.uuid4().hex)
        self.driver.check_policy_association(**association)

        association = self.create_association(service_id=uuid.uuid4().hex,
                                              region_id=uuid.uuid4().hex)
        self.driver.check_policy_association(**association)

        association = self.create_association(service_id=uuid.uuid4().hex)
        self.driver.check_policy_association(**association)

    def test_recreate_policy_association(self):
        # Creating a policy association to a target that already has a policy
        # associated to it will cause the original policy to be overridden
        original_association = self.create_association(
            service_id=uuid.uuid4().hex)
        override_association = original_association.copy()
        override_association['policy_id'] = uuid.uuid4().hex

        self.driver.create_policy_association(**override_association)

        self.driver.check_policy_association(**override_association)
        self.assertRaises(exception.PolicyAssociationNotFound,
                          self.driver.check_policy_association,
                          **original_association)

    def test_check_policy_association(self):
        association = self.create_association(service_id=uuid.uuid4().hex,
                                              region_id=uuid.uuid4().hex)
        self.driver.check_policy_association(**association)

        # An association is uniquely identified by its target. Omitting any
        # attribute (region_id in this case) will result in a different check
        association.pop('region_id')

        self.assertRaises(exception.PolicyAssociationNotFound,
                          self.driver.check_policy_association,
                          **association)

    def test_delete_policy_association(self):
        association = self.create_association(endpoint_id=uuid.uuid4().hex)
        self.driver.delete_policy_association(**association)

        self.assertRaises(exception.PolicyAssociationNotFound,
                          self.driver.check_policy_association,
                          **association)

    def test_get_policy_association(self):
        association = self.create_association(service_id=uuid.uuid4().hex)

        # Extract the policy_id from the association and query it by the target
        policy_id = association.pop('policy_id')

        association_ref = self.driver.get_policy_association(**association)
        self.assertEqual({'policy_id': (policy_id,)}, association_ref)

    def test_list_associations_for_policy(self):
        policy_id = uuid.uuid4().hex
        first = self.create_association(endpoint_id=uuid.uuid4().hex,
                                        policy_id=policy_id)
        second = self.create_association(service_id=uuid.uuid4().hex,
                                         policy_id=policy_id)

        associations = self.driver.list_associations_for_policy(policy_id)
        self.assertCountEqual([first, second], associations)

    def test_delete_association_by_endpoint(self):
        endpoint_id = uuid.uuid4().hex
        associations = [self.create_association(endpoint_id=endpoint_id),
                        self.create_association(endpoint_id=endpoint_id)]

        self.driver.delete_association_by_endpoint(endpoint_id)

        for association in associations:
            self.assertRaises(exception.PolicyAssociationNotFound,
                              self.driver.check_policy_association,
                              **association)

    def test_delete_association_by_service(self):
        service_id = uuid.uuid4().hex
        associations = [self.create_association(service_id=service_id),
                        self.create_association(service_id=service_id)]

        self.driver.delete_association_by_service(service_id)

        for association in associations:
            self.assertRaises(exception.PolicyAssociationNotFound,
                              self.driver.check_policy_association,
                              **association)

    def test_delete_association_by_region(self):
        region_id = uuid.uuid4().hex
        first = self.create_association(service_id=uuid.uuid4().hex,
                                        region_id=region_id)
        second = self.create_association(service_id=uuid.uuid4().hex,
                                         region_id=region_id)

        self.driver.delete_association_by_region(region_id)

        for association in [first, second]:
            self.assertRaises(exception.PolicyAssociationNotFound,
                              self.driver.check_policy_association,
                              **association)

    def test_delete_association_by_policy(self):
        policy_id = uuid.uuid4().hex
        first = self.create_association(endpoint_id=uuid.uuid4().hex,
                                        policy_id=policy_id)
        second = self.create_association(service_id=uuid.uuid4().hex,
                                         policy_id=policy_id)

        self.driver.delete_association_by_policy(policy_id)

        for association in [first, second]:
            self.assertRaises(exception.PolicyAssociationNotFound,
                              self.driver.check_policy_association,
                              **association)
