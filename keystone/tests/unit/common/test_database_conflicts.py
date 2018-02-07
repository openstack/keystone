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

from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import mapping_fixtures
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class DuplicateTestCase(test_v3.RestfulTestCase):
    # TODO(lbragstad): This class relies heavily on the usage of try/excepts
    # within the tests. We could achieve the same functionality with better
    # readability using a context manager from `assertRaises()`. The reason why
    # we aren't is because we are using the testtools library, which
    # reimplemented the functionality of `assertRaises` but didn't include
    # support for using it to generate a context manager. If that ever changes,
    # or if we move away from testtools, we should fix this to be more
    # test-like and not rely on try/except/else patterns in tests.

    def test_domain_duplicate_conflict_gives_name(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        domain['id'] = uuid.uuid4().hex
        try:
            PROVIDERS.resource_api.create_domain(domain['id'], domain)
        except exception.Conflict as e:
            self.assertIn("%s" % domain['name'], repr(e))
        else:
            self.fail("Creating duplicate domain did not raise a conflict")

    def test_project_duplicate_conflict_gives_name(self):
        project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)
        project['id'] = uuid.uuid4().hex
        try:
            PROVIDERS.resource_api.create_project(project['id'], project)
        except exception.Conflict as e:
            self.assertIn("%s" % project['name'], repr(e))
        else:
            self.fail("Creating duplicate project did not raise a conflict")

    def test_user_duplicate_conflict_gives_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        user['id'] = uuid.uuid4().hex
        try:
            PROVIDERS.identity_api.create_user(user)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s" % user['name'],
                          repr(e))
        else:
            self.fail("Create duplicate user did not raise a conflict")

    def test_role_duplicate_conflict_gives_name(self):
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        role['id'] = uuid.uuid4().hex
        try:
            PROVIDERS.role_api.create_role(role['id'], role)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s" % role['name'],
                          repr(e))
        else:
            self.fail("Create duplicate role did not raise a conflict")

    def test_group_duplicate_conflict_gives_name(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        try:
            PROVIDERS.identity_api.create_group(group)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s"
                          % group['name'], repr(e))
        else:
            self.fail("Create duplicate group did not raise a conflict")

    def test_policy_duplicate_conflict_gives_name(self):
        policy_ref = unit.new_policy_ref()
        PROVIDERS.policy_api.create_policy(policy_ref['id'], policy_ref)
        try:
            PROVIDERS.policy_api.create_policy(policy_ref['id'], policy_ref)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s"
                          % policy_ref['name'], repr(e))
        else:
            self.fail("Create duplicate policy did not raise a conflict")

    def test_credential_duplicate_conflict_gives_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        credential = unit.new_credential_ref(user_id=user['id'])
        PROVIDERS.credential_api.create_credential(
            credential['id'], credential
        )
        try:
            PROVIDERS.credential_api.create_credential(
                credential['id'], credential
            )
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % credential['id'], repr(e))
        else:
            self.fail("Create duplicate credential did not raise a conflict")

    def test_trust_duplicate_conflict_gives_name(self):
        trustor = unit.new_user_ref(domain_id=self.domain_id)
        trustor = PROVIDERS.identity_api.create_user(trustor)
        trustee = unit.new_user_ref(domain_id=self.domain_id)
        trustee = PROVIDERS.identity_api.create_user(trustee)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        trust_ref = unit.new_trust_ref(trustor['id'], trustee['id'])
        PROVIDERS.trust_api.create_trust(
            trust_ref['id'], trust_ref, [role_ref]
        )
        try:
            PROVIDERS.trust_api.create_trust(
                trust_ref['id'], trust_ref, [role_ref]
            )
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % trust_ref['id'], repr(e))
        else:
            self.fail("Create duplicate trust did not raise a conflict")

    def test_mapping_duplicate_conflict_gives_name(self):
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = uuid.uuid4().hex
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        try:
            PROVIDERS.federation_api.create_mapping(
                self.mapping['id'], self.mapping
            )
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % self.mapping['id'], repr(e))
        else:
            self.fail("Create duplicate mapping did not raise a conflict")

    def test_mapping_duplicate_conflict_with_id_in_id(self):
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = 'mapping_with_id_in_the_id'
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        try:
            PROVIDERS.federation_api.create_mapping(
                self.mapping['id'], self.mapping
            )
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % self.mapping['id'], repr(e))
        # Any other exception will cause the test to fail

    def test_region_duplicate_conflict_gives_name(self):
        region_ref = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(region_ref)
        try:
            PROVIDERS.catalog_api.create_region(region_ref)
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
        PROVIDERS.federation_api.create_idp(self.idp['id'], self.idp)
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = uuid.uuid4().hex
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id']
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        try:
            PROVIDERS.federation_api.create_protocol(
                self.idp['id'], protocol['id'], protocol
            )
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % protocol_ret['id'], repr(e))
        else:
            self.fail("Create duplicate federation_protocol did not raise "
                      "a conflict")

    def test_federation_protocol_duplicate_conflict_with_id_in_id(self):
        self.idp = {
            'id': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        PROVIDERS.federation_api.create_idp(self.idp['id'], self.idp)
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = uuid.uuid4().hex
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        protocol = {
            'id': 'federation_protocol_with_id_in_the_id',
            'mapping_id': self.mapping['id']
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        try:
            PROVIDERS.federation_api.create_protocol(
                self.idp['id'], protocol['id'], protocol
            )
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % protocol_ret['id'], repr(e))
        # Any other exception will fail the test

    def test_federation_protocol_duplicate_conflict_with_id_in_idp_id(self):
        self.idp = {
            'id': 'myidp',
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        PROVIDERS.federation_api.create_idp(self.idp['id'], self.idp)
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = uuid.uuid4().hex
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id']
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        try:
            PROVIDERS.federation_api.create_protocol(
                self.idp['id'], protocol['id'], protocol
            )
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % protocol_ret['id'], repr(e))
        # Any other exception will fail the test

    def test_sp_duplicate_conflict_gives_name(self):
        sp = {
            'auth_url': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex,
            'sp_url': uuid.uuid4().hex,
            'relay_state_prefix': CONF.saml.relay_state_prefix,
        }
        service_ref = PROVIDERS.federation_api.create_sp('SP1', sp)
        try:
            PROVIDERS.federation_api.create_sp('SP1', sp)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with ID %s"
                          % service_ref['id'], repr(e))
        else:
            self.fail("Create duplicate sp did not raise a conflict")
