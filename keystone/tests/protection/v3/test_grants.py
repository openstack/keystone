#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid

import http.client
from oslo_serialization import jsonutils

from keystone.common.policies import grant as gp
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _SystemUserGrantTests(object):

    def test_can_list_grants_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/projects/%s/users/%s/roles' % (project['id'], user['id']),
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_list_grants_for_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/domains/%s/users/%s/roles' % (domain['id'], user['id']),
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_list_grants_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/projects/%s/groups/%s/roles' % (
                    project['id'], group['id']),
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_list_grants_for_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/domains/%s/groups/%s/roles' % (domain['id'], group['id']),
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_check_grant_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_can_check_grant_for_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_can_check_grant_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_can_check_grant_for_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )


class _SystemMemberAndReaderGrantTests(object):

    def test_cannot_create_grant_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainUserTests(object):

    def test_can_list_grants_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/projects/%s/users/%s/roles' % (project['id'], user['id']),
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_list_grants_for_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=self.domain_id
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/domains/%s/users/%s/roles' % (self.domain_id, user['id']),
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_list_grants_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/projects/%s/groups/%s/roles' % (
                    project['id'], group['id']),
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_list_grants_for_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=self.domain_id
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/domains/%s/groups/%s/roles' % (
                    self.domain_id, group['id']
                ), headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))

    def test_can_check_grant_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=self.domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_can_check_grant_for_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=self.domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    self.domain_id, user['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_can_check_grant_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_can_check_grant_for_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=self.domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    self.domain_id, group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_cannot_list_grants_for_user_other_domain_on_project_own_domain(self):  # noqa: E501
        user_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/users/%s/roles' % (project['id'], user['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_list_grants_for_user_own_domain_on_project_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/users/%s/roles' % (project['id'], user['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_list_grants_for_user_own_domain_on_other_domain(self):
        user_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/users/%s/roles' % (domain_id, user['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_list_grants_for_user_other_domain_on_own_domain(self):
        user_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/users/%s/roles' % (domain_id, user['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_list_grants_for_group_other_domain_on_project_own_domain(self):  # noqa: E501
        group_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/groups/%s/roles' % (
                    project['id'], group['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_list_grants_for_group_own_domain_on_project_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/groups/%s/roles' % (
                    project['id'], group['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_list_grants_for_group_own_domain_on_other_domain(self):
        group_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/groups/%s/roles' % (
                    domain_id, group['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_list_grants_for_group_other_domain_on_own_domain(self):
        group_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/groups/%s/roles' % (
                    domain_id, group['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_user_other_domain_on_project_own_domain(self):  # noqa: E501
        user_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'],
                    self.bootstrapper.reader_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_user_own_domain_on_project_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'],
                    self.bootstrapper.reader_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_user_own_domain_on_project_own_domain_with_role_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        project_domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex, unit.new_role_ref(domain_id=role_domain_id))

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=project_domain_id)
        )

        # NOTE(cmurphy) the grant for a domain-specific role cannot be created
        # for a project in a different domain, so we don't try to create it,
        # but we still need to test that checking the role results in a 403 and
        # not a 404

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'],
                    role['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_user_own_domain_on_other_domain(self):
        user_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_user_other_domain_on_own_domain(self):
        user_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_user_own_domain_on_own_domain_with_role_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex,
            unit.new_role_ref(domain_id=role_domain_id))

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        # NOTE(cmurphy) the grant for a domain-specific role cannot be created
        # for a project in a different domain, so we don't try to create it,
        # but we still need to test that checking the role results in a 403 and
        # not a 404

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'],
                    role['id']
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_group_other_domain_on_project_own_domain(self):  # noqa: E501
        group_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'], group['id'],
                    self.bootstrapper.reader_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_group_own_domain_on_project_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=project_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'], group['id'],
                    self.bootstrapper.reader_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_group_own_domain_on_project_own_domain_with_role_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex,
            unit.new_role_ref(domain_id=role_domain_id))

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=project_domain_id)
        )

        # NOTE(cmurphy) the grant for a domain-specific role cannot be created
        # for a project in a different domain, so we don't try to create it,
        # but we still need to test that checking the role results in a 403 and
        # not a 404

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'], group['id'],
                    role['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_group_own_domain_on_other_domain(self):
        group_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'],
                    self.bootstrapper.reader_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_group_other_domain_on_own_domain(self):
        group_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'],
                    self.bootstrapper.reader_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_check_grant_for_group_own_domain_on_own_domain_with_role_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex, unit.new_role_ref(domain_id=role_domain_id))

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        # NOTE(cmurphy) the grant for a domain-specific role cannot be created
        # for a project in a different domain, so we don't try to create it,
        # but we still need to test that checking the role results in a 403 and
        # not a 404

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'],
                    role['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_other_domain_on_project_own_domain(self):  # noqa: E501
        user_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_own_domain_on_project_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_own_domain_on_project_own_domain_with_role_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        project_domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex, unit.new_role_ref(domain_id=role_domain_id))

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )
        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], role['id']
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_other_domain_on_own_domain(self):
        user_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_own_domain_on_other_domain(self):
        user_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_own_domain_on_own_domain_with_role_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex, unit.new_role_ref(domain_id=role_domain_id))

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'], role['id']
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_other_domain_on_project_own_domain(self):  # noqa: E501
        group_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_own_domain_on_project_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_own_domain_on_project_own_domain_with_role_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        project_domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex, unit.new_role_ref(domain_id=role_domain_id))

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    role['id']
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_other_domain_on_own_domain(self):
        group_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_own_domain_on_other_domain(self):
        group_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_own_domain_on_own_domain_with_role_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex, unit.new_role_ref(domain_id=role_domain_id))

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'], role['id']
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_other_domain_on_project_own_domain(self):  # noqa: E501
        user_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_own_domain_on_project_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_other_domain_on_own_domain(self):
        user_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_own_domain_on_other_domain(self):
        user_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_own_domain_on_own_domain_with_role_other_domain(self):  # noqa: E501
        user_domain_id = self.domain_id
        domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex, unit.new_role_ref(domain_id=role_domain_id))

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=user_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            role['id'], user_id=user['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain_id, user['id'], role['id']
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_other_domain_on_project_own_domain(self):  # noqa: E501
        group_domain_id = CONF.identity.default_domain_id
        project_domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_own_domain_on_project_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        project_domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=project_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_other_domain_on_own_domain(self):
        group_domain_id = CONF.identity.default_domain_id
        domain_id = self.domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_own_domain_on_other_domain(self):
        group_domain_id = self.domain_id
        domain_id = CONF.identity.default_domain_id

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_own_domain_on_own_domain_with_role_other_domain(self):  # noqa: E501
        group_domain_id = self.domain_id
        domain_id = self.domain_id
        role_domain_id = CONF.identity.default_domain_id

        role = PROVIDERS.role_api.create_role(
            uuid.uuid4().hex,
            unit.new_role_ref(domain_id=role_domain_id))

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=group_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            role['id'], group_id=group['id'],
            domain_id=domain_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain_id, group['id'], role['id']
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserGrantTests,
                        _SystemMemberAndReaderGrantTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            system_reader
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.reader_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=system_reader['password'],
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class SystemMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserGrantTests,
                        _SystemMemberAndReaderGrantTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            system_member
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.member_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=system_member['password'],
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class SystemAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _SystemUserGrantTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self.user_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_can_create_grant_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_create_grant_for_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_create_grant_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_create_grant_for_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_revoke_grant_from_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_revoke_grant_from_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_revoke_grant_from_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_revoke_grant_from_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )


class _DomainMemberAndReaderTests(object):

    def test_cannot_create_grant_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_create_grant_for_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_user_on_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    domain['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_revoke_grant_from_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class DomainReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _DomainUserTests,
                        _DomainMemberAndReaderTests):

    def setUp(self):
        super(DomainReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_user = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_user)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_user['password'],
            domain_id=self.domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _DomainUserTests,
                        _DomainMemberAndReaderTests):

    def setUp(self):
        super(DomainMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_user = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_user)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_user['password'],
            domain_id=self.domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _DomainUserTests):

    def setUp(self):
        super(DomainAdminTests, self).setUp()
        self.loadapp()
        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )
        self._override_policy()
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_admin = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=domain_admin['password'],
            domain_id=self.domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.grant have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will OR deprecated policies with new policies to
        # maintain compatibility and give operators a chance to update
        # permissions or update policies without breaking users. This will
        # cause these specific tests to fail since we're trying to correct this
        # broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:list_grants': gp.SYSTEM_READER_OR_DOMAIN_READER_LIST,
                'identity:check_grant': gp.SYSTEM_READER_OR_DOMAIN_READER,
                'identity:create_grant': gp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:revoke_grant': gp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN
            }
            f.write(jsonutils.dumps(overridden_policies))

    def test_can_create_grant_for_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_create_grant_for_user_own_domain_on_own_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/users/%s/roles/%s' % (
                    self.domain_id, user['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_create_grant_for_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_create_grant_for_group_own_domain_on_own_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    self.domain_id, group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_revoke_grant_from_user_on_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/users/%s/roles/%s' % (
                    project['id'], user['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_can_revoke_grant_from_group_on_project(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/groups/%s/roles/%s' % (
                    project['id'],
                    group['id'],
                    self.bootstrapper.reader_role_id
                ),
                headers=self.headers
            )

    def test_cannot_revoke_grant_from_group_on_domain(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, group_id=group['id'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s/groups/%s/roles/%s' % (
                    domain['id'], group['id'], self.bootstrapper.reader_role_id
                ),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )
