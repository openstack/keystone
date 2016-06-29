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

from testtools import matchers

from keystone.assignment import controllers as assignment_controllers
from keystone import exception
from keystone.resource import controllers as resource_controllers
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database


class TenantTestCase(unit.TestCase):
    """Test for the V2 Tenant controller.

    These tests exercise :class:`keystone.assignment.controllers.Tenant`.

    """

    def setUp(self):
        super(TenantTestCase, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.tenant_controller = resource_controllers.Tenant()
        self.assignment_tenant_controller = (
            assignment_controllers.TenantAssignment())
        self.assignment_role_controller = (
            assignment_controllers.RoleAssignmentV2())

    def test_get_project_users_no_user(self):
        """Test the user's existence for get_project_users.

        When a user that's not known to `identity` has a role on a project,
        then `get_project_users` just skips that user.

        """
        project_id = self.tenant_bar['id']

        orig_project_users = (
            self.assignment_tenant_controller.get_project_users(
                self.make_request(is_admin=True), project_id))

        # Assign a role to a user that doesn't exist to the `bar` project.

        user_id = uuid.uuid4().hex
        self.assignment_role_controller.add_role_to_user(
            self.make_request(is_admin=True), user_id,
            self.role_other['id'], project_id)

        new_project_users = (
            self.assignment_tenant_controller.get_project_users(
                self.make_request(is_admin=True), project_id))

        # The new user isn't included in the result, so no change.
        # asserting that the expected values appear in the list,
        # without asserting the order of the results
        self.assertEqual(sorted(orig_project_users), sorted(new_project_users))

    def test_list_projects_default_domain(self):
        """Test that list projects only returns those in the default domain."""
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project1['id'], project1)
        # Check the real total number of projects, we should have the:
        # - tenants in the default fixtures
        # - the project representing the default domain
        # - the project representing the domain we created above
        # - the project we created above
        refs = self.resource_api.list_projects()
        self.assertThat(
            refs, matchers.HasLength(len(default_fixtures.TENANTS) + 3))

        # Now list all projects using the v2 API - we should only get
        # back those in the default features, since only those are in the
        # default domain.
        refs = self.tenant_controller.get_all_projects(
            self.make_request(is_admin=True))
        self.assertEqual(len(default_fixtures.TENANTS), len(refs['tenants']))
        for tenant in default_fixtures.TENANTS:
            tenant_copy = tenant.copy()
            tenant_copy.pop('domain_id')
            tenant_copy.pop('parent_id')
            tenant_copy.pop('is_domain')
            self.assertIn(tenant_copy, refs['tenants'])

    def _create_is_domain_project(self):
        project = unit.new_project_ref(is_domain=True)
        project_ref = self.resource_api.create_project(project['id'], project)
        return self.tenant_controller.v3_to_v2_project(project_ref)

    def test_get_is_domain_project_not_found(self):
        """Test that get project does not return is_domain projects."""
        project = self._create_is_domain_project()

        request = self.make_request(is_admin=True,
                                    query_string='name=%s' % project['name'])

        self.assertRaises(
            exception.ProjectNotFound,
            self.tenant_controller.get_all_projects,
            request)

        request = self.make_request(is_admin=True,
                                    query_string='name=%s' % project['id'])

        self.assertRaises(
            exception.ProjectNotFound,
            self.tenant_controller.get_all_projects,
            request)

    def test_create_is_domain_project_fails(self):
        """Test that the creation of a project acting as a domain fails."""
        project = {'name': uuid.uuid4().hex, 'domain_id': 'default',
                   'is_domain': True}

        self.assertRaises(
            exception.ValidationError,
            self.tenant_controller.create_project,
            self.make_request(is_admin=True),
            project)

    def test_create_project_passing_is_domain_false_fails(self):
        """Test that passing is_domain=False is not allowed."""
        project = {'name': uuid.uuid4().hex, 'domain_id': 'default',
                   'is_domain': False}

        self.assertRaises(
            exception.ValidationError,
            self.tenant_controller.create_project,
            self.make_request(is_admin=True),
            project)

    def test_update_is_domain_project_not_found(self):
        """Test that update is_domain project is not allowed in v2."""
        project = self._create_is_domain_project()

        project['name'] = uuid.uuid4().hex
        self.assertRaises(
            exception.ProjectNotFound,
            self.tenant_controller.update_project,
            self.make_request(is_admin=True),
            project['id'],
            project)

    def test_delete_is_domain_project_not_found(self):
        """Test that delete is_domain project is not allowed in v2."""
        project = self._create_is_domain_project()

        self.assertRaises(
            exception.ProjectNotFound,
            self.tenant_controller.delete_project,
            self.make_request(is_admin=True),
            project['id'])

    def test_list_is_domain_project_not_found(self):
        """Test v2 get_all_projects having projects that act as a domain.

        In v2 no project with the is_domain flag enabled should be returned.
        """
        project1 = self._create_is_domain_project()
        project2 = self._create_is_domain_project()

        refs = self.tenant_controller.get_all_projects(
            self.make_request(is_admin=True))
        projects = refs.get('tenants')

        self.assertNotIn(project1, projects)
        self.assertNotIn(project2, projects)
