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

import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import mapping_fixtures
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF


class DuplicateTestCase(test_v3.RestfulTestCase):
    def test_domain_duplicate_conflict_gives_name(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        domain['id'] = uuid.uuid4().hex
        try:
            self.resource_api.create_domain(domain['id'], domain)
        except exception.Conflict as e:
            self.assertIn("%s" % domain['name'], repr(e))
        else:
            self.fail("Creating duplicate domain did not raise a conflict")

    def test_project_duplicate_conflict_gives_name(self):
        project = unit.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project['id'], project)
        project['id'] = uuid.uuid4().hex
        try:
            self.resource_api.create_project(project['id'], project)
        except exception.Conflict as e:
            self.assertIn("%s" % project['name'], repr(e))
        else:
            self.fail("Creating duplicate project did not raise a conflict")

    def test_user_duplicate_conflict_gives_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user['id'] = uuid.uuid4().hex
        try:
            self.identity_api.create_user(user)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s" % user['name'],
                          repr(e))
        else:
            self.fail("Create duplicate user did not raise a conflict")

    def test_role_duplicate_conflict_gives_name(self):
        role = unit.new_role_ref()
        self.role_api.create_role(role['id'], role)
        role['id'] = uuid.uuid4().hex
        try:
            self.role_api.create_role(role['id'], role)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s" % role['name'],
                          repr(e))
        else:
            self.fail("Create duplicate role did not raise a conflict")

    def test_group_duplicate_conflict_gives_name(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)
        try:
            self.identity_api.create_group(group)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s"
                          % group['name'], repr(e))
        else:
            self.fail("Create duplicate group did not raise a conflict")

    def test_policy_duplicate_conflict_gives_name(self):
        policy_ref = unit.new_policy_ref()
        self.policy_api.create_policy(policy_ref['id'], policy_ref)
        try:
            self.policy_api.create_policy(policy_ref['id'], policy_ref)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s"
                          % policy_ref['name'], repr(e))
        else:
            self.fail("Create duplicate policy did not raise a conflict")

    def test_credential_duplicate_conflict_gives_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        credential = unit.new_credential_ref(user_id=user['id'])
        self.credential_api.create_credential(credential['id'], credential)
        try:
            self.credential_api.create_credential(credential['id'], credential)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % credential['id'], repr(e))
        else:
            self.fail("Create duplicate credential did not raise a conflict")

    def test_trust_duplicate_conflict_gives_name(self):
        trustor = unit.new_user_ref(domain_id=self.domain_id)
        trustor = self.identity_api.create_user(trustor)
        trustee = unit.new_user_ref(domain_id=self.domain_id)
        trustee = self.identity_api.create_user(trustee)
        role_ref = unit.new_role_ref()
        self.role_api.create_role(role_ref['id'], role_ref)
        trust_ref = unit.new_trust_ref(trustor['id'], trustee['id'])
        self.trust_api.create_trust(trust_ref['id'], trust_ref, [role_ref])
        try:
            self.trust_api.create_trust(trust_ref['id'], trust_ref, [role_ref])
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % trust_ref['id'], repr(e))
        else:
            self.fail("Create duplicate trust did not raise a conflict")

    def test_mapping_duplicate_conflict_gives_name(self):
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = uuid.uuid4().hex
        self.federation_api.create_mapping(self.mapping['id'],
                                           self.mapping)
        try:
            self.federation_api.create_mapping(self.mapping['id'],
                                               self.mapping)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % self.mapping['id'], repr(e))
        else:
            self.fail("Create duplicate mapping did not raise a conflict")

    def test_region_duplicate_conflict_gives_name(self):
        region_ref = unit.new_region_ref()
        self.catalog_api.create_region(region_ref)
        try:
            self.catalog_api.create_region(region_ref)
        except exception.Conflict as e:
            self.assertIn("Duplicate ID, %s" % region_ref['id'], repr(e))
        else:
            self.fail("Create duplicate region did not raise a conflict")

    def test_federation_protocol_duplicate_conflict_gives_name(self):
        self.idp = {
            'id': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        self.federation_api.create_idp(self.idp['id'], self.idp)
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = uuid.uuid4().hex
        self.federation_api.create_mapping(self.mapping['id'],
                                           self.mapping)
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id']
        }
        protocol_ret = self.federation_api.create_protocol(self.idp['id'],
                                                           protocol['id'],
                                                           protocol)
        try:
            self.federation_api.create_protocol(self.idp['id'],
                                                protocol['id'],
                                                protocol)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % protocol_ret['id'], repr(e))
        else:
            self.fail("Create duplicate region did not raise a conflict")

    def test_sp_duplicate_conflict_gives_name(self):
        sp = {
            'auth_url': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex,
            'sp_url': uuid.uuid4().hex,
            'relay_state_prefix': CONF.saml.relay_state_prefix,
        }
        service_ref = self.federation_api.create_sp('SP1', sp)
        try:
            self.federation_api.create_sp('SP1', sp)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % service_ref['id'], repr(e))
        else:
            self.fail("Create duplicate region did not raise a conflict")
