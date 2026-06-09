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
from keystone.federation import constants as federation_constants
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

    def _make_federated_token_mock(self, expires_at):
        token = mock.Mock()
        token.audit_id = uuid.uuid4().hex
        token.user_id = uuid.uuid4().hex
        token.identity_provider_id = 'test-idp'
        token.protocol_id = 'mapped'
        token.federated_groups = [{'id': uuid.uuid4().hex}]
        token.expires_at = expires_at
        return token


class TestHandleScopedToken(unit.TestCase):
    """Tests for the handle_scoped_token security fix.

    Verify that rescoping a federated token preserves the original
    token's expires_at rather than falling back to a fresh TTL.
    Without the fix, an attacker can extend their session indefinitely
    by rescoping before expiry, bypassing IdP-level account revocation.
    """

    def setUp(self):
        super().setUp()
        self.federation_api = mock.Mock()
        self.identity_api = mock.Mock()
        mapping_ref = {'id': uuid.uuid4().hex}
        self.federation_api.get_mapping_from_idp_and_protocol.return_value = (
            mapping_ref
        )

    @mock.patch(
        'keystone.auth.plugins.mapped.notifications'
        '.send_saml_audit_notification',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_mapped_group_ids',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.assert_enabled_identity_provider',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_expiration', autospec=True
    )
    def test_handle_scoped_token_preserves_expires_at(
        self,
        mock_validate_exp,
        mock_assert_idp,
        mock_validate_groups,
        mock_notify,
    ):
        """Rescoped federated token must inherit original expiry (not fresh TTL).

        This is the security regression test for the authentication expiry
        bypass vulnerability: handle_scoped_token must include expires_at in
        the returned response_data so that issue_token() does not fall back to
        default_expire_time().
        """
        original_expiry = '2026-04-26T08:59:30.000000Z'
        token = self._make_federated_token_mock(original_expiry)

        result = mapped.handle_scoped_token(
            token, self.federation_api, self.identity_api
        )

        self.assertIn('expires_at', result)
        self.assertEqual(original_expiry, result['expires_at'])

    @mock.patch(
        'keystone.auth.plugins.mapped.notifications'
        '.send_saml_audit_notification',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_mapped_group_ids',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.assert_enabled_identity_provider',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_expiration', autospec=True
    )
    def test_handle_scoped_token_returns_federation_metadata(
        self,
        mock_validate_exp,
        mock_assert_idp,
        mock_validate_groups,
        mock_notify,
    ):
        """Rescoped federated token still returns all required federation data."""
        token = self._make_federated_token_mock('2026-04-26T08:59:30.000000Z')

        result = mapped.handle_scoped_token(
            token, self.federation_api, self.identity_api
        )

        self.assertEqual(token.user_id, result['user_id'])
        self.assertEqual(
            token.identity_provider_id,
            result[federation_constants.IDENTITY_PROVIDER],
        )
        self.assertEqual(
            token.protocol_id, result[federation_constants.PROTOCOL]
        )
        self.assertIsInstance(result['group_ids'], list)

    def _make_federated_token_mock(self, expires_at):
        token = mock.Mock()
        token.audit_id = uuid.uuid4().hex
        token.user_id = uuid.uuid4().hex
        token.identity_provider_id = 'test-idp'
        token.protocol_id = 'mapped'
        token.federated_groups = [{'id': uuid.uuid4().hex}]
        token.expires_at = expires_at
        return token
