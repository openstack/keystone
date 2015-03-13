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

from keystone.assignment import controllers as assignment_controllers
from keystone.resource import controllers as resource_controllers
from keystone.tests import unit as tests
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database


_ADMIN_CONTEXT = {'is_admin': True, 'query_string': {}}


class TenantTestCase(tests.TestCase):
    """Tests for the V2 Tenant controller.

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
        """get_project_users when user doesn't exist.

        When a user that's not known to `identity` has a role on a project,
        then `get_project_users` just skips that user.

        """
        project_id = self.tenant_bar['id']

        orig_project_users = (
            self.assignment_tenant_controller.get_project_users(_ADMIN_CONTEXT,
                                                                project_id))

        # Assign a role to a user that doesn't exist to the `bar` project.

        user_id = uuid.uuid4().hex
        self.assignment_role_controller.add_role_to_user(
            _ADMIN_CONTEXT, user_id, self.role_other['id'], project_id)

        new_project_users = (
            self.assignment_tenant_controller.get_project_users(_ADMIN_CONTEXT,
                                                                project_id))

        # The new user isn't included in the result, so no change.
        # asserting that the expected values appear in the list,
        # without asserting the order of the results
        self.assertEqual(sorted(orig_project_users), sorted(new_project_users))

    def test_list_projects_default_domain(self):
        """Test that list projects only returns those in the default domain."""

        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        self.resource_api.create_domain(domain['id'], domain)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project1['id'], project1)
        # Check the real total number of projects, we should have the above
        # plus those in the default features
        refs = self.resource_api.list_projects()
        self.assertEqual(len(default_fixtures.TENANTS) + 1, len(refs))

        # Now list all projects using the v2 API - we should only get
        # back those in the default features, since only those are in the
        # default domain.
        refs = self.tenant_controller.get_all_projects(_ADMIN_CONTEXT)
        self.assertEqual(len(default_fixtures.TENANTS), len(refs['tenants']))
        for tenant in default_fixtures.TENANTS:
            tenant_copy = tenant.copy()
            tenant_copy.pop('domain_id')
            tenant_copy.pop('parent_id')
            self.assertIn(tenant_copy, refs['tenants'])
