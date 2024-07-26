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
from unittest import mock
import uuid

from keystone.assignment.core import Manager as AssignmentApi
from keystone.auth.plugins import mapped
from keystone.exception import ProjectNotFound
from keystone.resource.core import Manager as ResourceApi
from keystone.tests import unit


class TestMappedPlugin(unit.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setUp(self):
        super().setUp()
        self.resource_api_mock = mock.Mock(spec=ResourceApi)
        self.assignment_api_mock = mock.Mock(spec=AssignmentApi)
        self.domain_uuid_mock = uuid.uuid4().hex
        self.domain_mock = {'id': self.domain_uuid_mock}
        self.idp_domain_uuid_mock = uuid.uuid4().hex
        self.member_role_id = uuid.uuid4().hex
        self.member_role_name = "member"
        self.existing_roles = {
            self.member_role_name: {'id': self.member_role_id}
        }
        self.shadow_project_mock = {
            'name': "test-project",
            'roles': [{'name': self.member_role_name}],
        }
        self.shadow_project_in_domain_mock = {
            'name': "test-project-in-domain",
            'domain': self.domain_mock,
            'roles': [{'name': self.member_role_name}],
        }
        self.shadow_projects_mock = [
            self.shadow_project_mock,
            self.shadow_project_in_domain_mock,
        ]
        self.user_mock = {'id': uuid.uuid4().hex, 'name': "test-user"}

    def test_configure_project_domain_no_project_domain(self):
        mapped.configure_project_domain(
            self.shadow_project_mock,
            self.idp_domain_uuid_mock,
            self.resource_api_mock,
        )
        self.assertIn("domain", self.shadow_project_mock)
        self.assertEqual(
            self.idp_domain_uuid_mock, self.shadow_project_mock['domain']['id']
        )

    def test_configure_project_domain_with_domain_id(self):
        self.shadow_project_mock['domain'] = self.domain_mock
        mapped.configure_project_domain(
            self.shadow_project_mock,
            self.idp_domain_uuid_mock,
            self.resource_api_mock,
        )
        self.assertIn("domain", self.shadow_project_mock)
        self.assertEqual(
            self.domain_uuid_mock, self.shadow_project_mock['domain']['id']
        )

    def test_configure_project_domain_with_domain_name(self):
        domain_name = "test-domain"
        self.shadow_project_mock['domain'] = {'name': domain_name}
        self.resource_api_mock.get_domain_by_name.return_value = (
            self.domain_mock
        )
        mapped.configure_project_domain(
            self.shadow_project_mock,
            self.idp_domain_uuid_mock,
            self.resource_api_mock,
        )
        self.assertIn("domain", self.shadow_project_mock)
        self.assertEqual(
            self.domain_uuid_mock, self.shadow_project_mock['domain']['id']
        )
        self.resource_api_mock.get_domain_by_name.assert_called_with(
            domain_name
        )

    def test_handle_projects_from_mapping_project_exists(self):
        project_mock_1 = self.create_project_mock_for_shadow_project(
            self.shadow_project_mock
        )
        project_mock_2 = self.create_project_mock_for_shadow_project(
            self.shadow_project_in_domain_mock
        )
        self.resource_api_mock.get_project_by_name.side_effect = [
            project_mock_1,
            project_mock_2,
        ]
        mapped.handle_projects_from_mapping(
            self.shadow_projects_mock,
            self.idp_domain_uuid_mock,
            self.existing_roles,
            self.user_mock,
            self.assignment_api_mock,
            self.resource_api_mock,
        )
        self.resource_api_mock.get_project_by_name.assert_has_calls(
            [
                mock.call(
                    self.shadow_project_in_domain_mock['name'],
                    self.shadow_project_in_domain_mock['domain']['id'],
                ),
                mock.call(
                    self.shadow_project_mock['name'], self.idp_domain_uuid_mock
                ),
            ],
            any_order=True,
        )
        self.assignment_api_mock.create_grant.assert_has_calls(
            [
                mock.call(
                    self.member_role_id,
                    user_id=self.user_mock['id'],
                    project_id=project_mock_1['id'],
                ),
                mock.call(
                    self.member_role_id,
                    user_id=self.user_mock['id'],
                    project_id=project_mock_2['id'],
                ),
            ]
        )

    @mock.patch("uuid.UUID.hex", new_callable=mock.PropertyMock)
    def test_handle_projects_from_mapping_create_projects(self, uuid_mock):
        uuid_mock.return_value = "uuid"
        project_mock_1 = self.create_project_mock_for_shadow_project(
            self.shadow_project_mock
        )
        project_mock_2 = self.create_project_mock_for_shadow_project(
            self.shadow_project_in_domain_mock
        )
        self.resource_api_mock.get_project_by_name.side_effect = [
            ProjectNotFound(project_id=project_mock_1['name']),
            ProjectNotFound(project_id=project_mock_2['name']),
        ]
        self.resource_api_mock.create_project.side_effect = [
            project_mock_1,
            project_mock_2,
        ]
        mapped.handle_projects_from_mapping(
            self.shadow_projects_mock,
            self.idp_domain_uuid_mock,
            self.existing_roles,
            self.user_mock,
            self.assignment_api_mock,
            self.resource_api_mock,
        )
        self.resource_api_mock.get_project_by_name.assert_has_calls(
            [
                mock.call(
                    self.shadow_project_in_domain_mock['name'],
                    self.shadow_project_in_domain_mock['domain']['id'],
                ),
                mock.call(
                    self.shadow_project_mock['name'], self.idp_domain_uuid_mock
                ),
            ],
            any_order=True,
        )
        expected_project_ref1 = {
            'id': "uuid",
            'name': self.shadow_project_mock['name'],
            'domain_id': self.idp_domain_uuid_mock,
        }
        expected_project_ref2 = {
            'id': "uuid",
            'name': self.shadow_project_in_domain_mock['name'],
            'domain_id': self.shadow_project_in_domain_mock['domain']['id'],
        }
        self.resource_api_mock.create_project.assert_has_calls(
            [
                mock.call(expected_project_ref1['id'], expected_project_ref1),
                mock.call(expected_project_ref2['id'], expected_project_ref2),
            ]
        )
        self.assignment_api_mock.create_grant.assert_has_calls(
            [
                mock.call(
                    self.member_role_id,
                    user_id=self.user_mock['id'],
                    project_id=project_mock_1['id'],
                ),
                mock.call(
                    self.member_role_id,
                    user_id=self.user_mock['id'],
                    project_id=project_mock_2['id'],
                ),
            ]
        )

    def create_project_mock_for_shadow_project(self, shadow_project):
        project = shadow_project.copy()
        project['id'] = uuid.uuid4().hex
        return project
