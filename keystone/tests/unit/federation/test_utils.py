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
import copy
import uuid

from keystone.exception import ValidationError
from keystone.federation import utils
from keystone.tests import unit


class TestFederationUtils(unit.TestCase):
    def setUp(self):
        super().setUp()
        self.mapping_id_mock = uuid.uuid4().hex
        self.domain_id_mock = uuid.uuid4().hex
        self.domain_mock = {'id': self.domain_id_mock}
        self.attribute_mapping_schema_1_0 = {
            "id": self.mapping_id_mock,
            "schema_version": '1.0',
            "rules": [
                {
                    "remote": [
                        {"type": "OIDC-preferred_username"},
                        {"type": "OIDC-email"},
                        {"type": "OIDC-openstack-user-domain"},
                        {"type": "OIDC-openstack-default-project"},
                        {
                            "type": "OIDC-openstack-user-status",
                            "any_one_of": ["local"],
                        },
                    ],
                    "local": [
                        {
                            "domain": {"name": "{2}"},
                            "user": {
                                "domain": {"name": "{2}"},
                                "type": "local",
                                "name": "{0}",
                                "email": "{1}",
                            },
                            "projects": [
                                {"name": "{3}", "roles": [{"name": "member"}]}
                            ],
                        }
                    ],
                }
            ],
        }
        self.attribute_mapping_schema_2_0 = copy.deepcopy(
            self.attribute_mapping_schema_1_0
        )
        self.attribute_mapping_schema_2_0['schema_version'] = '2.0'
        self.attribute_mapping_schema_2_0['rules'][0]['local'][0]["projects"][
            0
        ]['domain'] = {"name": "{some_place_holder}"}
        self.rule_processor = utils.RuleProcessor(
            self.mapping_id_mock, self.attribute_mapping_schema_1_0
        )
        self.rule_processor_schema_2_0 = (
            utils.RuleProcessorToHonorDomainOption(
                self.mapping_id_mock, self.attribute_mapping_schema_2_0
            )
        )

    def test_validate_mapping_structure_schema1_0(self):
        utils.validate_mapping_structure(self.attribute_mapping_schema_1_0)

    def test_validate_mapping_structure_schema2_0(self):
        utils.validate_mapping_structure(self.attribute_mapping_schema_2_0)

    def test_normalize_user_no_type_set(self):
        user = {}
        self.rule_processor.normalize_user(user, self.domain_mock)
        self.assertEqual(utils.UserType.EPHEMERAL, user['type'])

    def test_normalize_user_unexpected_type(self):
        user = {'type': "weird-type"}
        self.assertRaises(
            ValidationError,
            self.rule_processor.normalize_user,
            user,
            self.domain_mock,
        )

    def test_normalize_user_type_local(self):
        user = {'type': utils.UserType.LOCAL}
        self.rule_processor.normalize_user(user, self.domain_mock)
        self.assertEqual(utils.UserType.LOCAL, user['type'])

    def test_normalize_user_type_ephemeral(self):
        user = {'type': utils.UserType.EPHEMERAL}
        self.rule_processor.normalize_user(user, self.domain_mock)
        self.assertEqual(utils.UserType.EPHEMERAL, user['type'])

    def test_extract_groups(self):
        group1 = {'name': "group1", 'domain': self.domain_id_mock}
        group_by_domain = {self.domain_id_mock: [group1]}

        result = utils.RuleProcessor(
            self.mapping_id_mock, self.attribute_mapping_schema_1_0
        ).extract_groups(group_by_domain)

        self.assertEqual([group1], list(result))

    def test_process_group_by_name_domain_with_name_only(self):
        domain = {'name': "domain1"}
        group1 = {'name': "group1", 'domain': domain}
        group_by_domain = {}
        result = self.rule_processor.process_group_by_name(
            group1, group_by_domain
        )
        self.assertEqual([group1], list(result))
        self.assertEqual([domain["name"]], list(group_by_domain.keys()))

    def test_process_group_by_name_domain_with_id_only(self):
        group1 = {'name': "group1", 'domain': self.domain_mock}
        group_by_domain = {}
        result = self.rule_processor.process_group_by_name(
            group1, group_by_domain
        )
        self.assertEqual([group1], list(result))
        self.assertEqual([self.domain_id_mock], list(group_by_domain.keys()))

    def test_process_group_by_name_domain_with_id_and_name(self):
        self.domain_mock['name'] = "domain1"
        group1 = {'name': "group1", 'domain': self.domain_mock}
        group_by_domain = {}
        result = self.rule_processor.process_group_by_name(
            group1, group_by_domain
        )
        self.assertEqual([group1], list(result))
        self.assertEqual(["domain1"], list(group_by_domain.keys()))

    def test_process_group_by_name_groups_same_domain(self):
        group1 = {'name': "group1", 'domain': self.domain_mock}
        group2 = {'name': "group2", 'domain': self.domain_mock}
        group_by_domain = {self.domain_id_mock: [group1]}
        result = self.rule_processor.process_group_by_name(
            group2, group_by_domain
        )
        self.assertEqual([group1, group2], list(result))
        self.assertEqual([self.domain_id_mock], list(group_by_domain.keys()))

    def test_process_group_by_name_groups_different_domain(self):
        domain = {'name': "domain1"}
        group1 = {'name': "group1", 'domain': domain}
        group2 = {'name': "group2", 'domain': self.domain_mock}
        group_by_domain = {"domain1": [group1]}
        result = self.rule_processor.process_group_by_name(
            group2, group_by_domain
        )
        self.assertEqual([group1, group2], list(result))
        self.assertEqual(
            ["domain1", self.domain_id_mock], list(group_by_domain.keys())
        )

    def test_rule_processor_extract_projects_schema1_0_no_projects(self):
        result = self.rule_processor.extract_projects({})
        self.assertEqual([], result)

    def test_rule_processor_extract_projects_schema1_0(self):
        projects_list = [{'name': "project1", 'domain': self.domain_mock}]
        identity_values = {'projects': projects_list}
        result = self.rule_processor.extract_projects(identity_values)
        self.assertEqual(projects_list, result)

    def test_rule_processor_extract_projects_schema2_0_no_projects(self):
        result = self.rule_processor_schema_2_0.extract_projects({})
        self.assertEqual([], result)

    def test_rule_processor_extract_projects_schema2_0_domain_in_project(self):
        projects_list = [{'name': "project1", 'domain': self.domain_mock}]
        identity_values = {'projects': projects_list}
        result = self.rule_processor_schema_2_0.extract_projects(
            identity_values
        )
        self.assertEqual(projects_list, result)

    def test_rule_processor_extract_projects_schema2_0_no_domain(self):
        projects_list = [{'name': "project1"}]
        identity_values = {'projects': projects_list}
        result = self.rule_processor_schema_2_0.extract_projects(
            identity_values
        )
        self.assertEqual(projects_list, result)

    def test_rule_processor_extract_projects_schema2_0_no_domain_project(self):
        project = {'name': "project1"}
        identity_values = {
            'projects': [project.copy()],
            'domain': self.domain_mock,
        }
        result = self.rule_processor_schema_2_0.extract_projects(
            identity_values
        )
        expected_project = project.copy()
        expected_project['domain'] = self.domain_mock
        self.assertEqual([expected_project], result)

    def test_normalize_user_no_type_set_schema_2_0(self):
        user = {}
        self.rule_processor_schema_2_0.normalize_user(user, self.domain_mock)
        self.assertEqual(utils.UserType.EPHEMERAL, user['type'])

    def test_normalize_user_unexpected_type_schema_2_0(self):
        user = {'type': "weird-type"}
        self.assertRaises(
            ValidationError,
            self.rule_processor_schema_2_0.normalize_user,
            user,
            self.domain_mock,
        )

    def test_normalize_user_type_local_schema_2_0(self):
        user = {'type': utils.UserType.LOCAL}
        self.rule_processor_schema_2_0.normalize_user(user, self.domain_mock)
        self.assertEqual(utils.UserType.LOCAL, user['type'])

    def test_normalize_user_type_ephemeral_schema_2_0(self):
        user = {'type': utils.UserType.EPHEMERAL}
        self.rule_processor_schema_2_0.normalize_user(user, self.domain_mock)
        self.assertEqual(utils.UserType.EPHEMERAL, user['type'])

    def test_normalize_user_no_domain_schema_2_0(self):
        user = {}
        self.rule_processor_schema_2_0.normalize_user(user, self.domain_mock)
        self.assertEqual(utils.UserType.EPHEMERAL, user['type'])
        self.assertEqual(self.domain_mock, user.get("domain"))

    def test_create_attribute_mapping_rules_processor_default(self):
        result = utils.create_attribute_mapping_rules_processor(
            self.attribute_mapping_schema_1_0
        )
        self.assertIsInstance(result, utils.RuleProcessor)

    def test_create_attribute_mapping_rules_processor_schema1_0(self):
        result = utils.create_attribute_mapping_rules_processor(
            self.attribute_mapping_schema_1_0
        )
        self.assertIsInstance(result, utils.RuleProcessor)

    def test_create_attribute_mapping_rules_processor_schema2_0(self):
        result = utils.create_attribute_mapping_rules_processor(
            self.attribute_mapping_schema_2_0
        )
        self.assertIsInstance(result, utils.RuleProcessorToHonorDomainOption)
