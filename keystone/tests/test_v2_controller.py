# -*- coding: utf-8 -*-

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

from keystone.assignment import controllers
from keystone import exception
from keystone import tests
from keystone.tests import default_fixtures


_ADMIN_CONTEXT = {'is_admin': True}


class TenantTestCase(tests.TestCase):
    """Tests for the V2 Tenant controller.

    These tests exercise :class:`keystone.assignment.controllers.Tenant`.

    """

    def test_get_project_users_no_user(self):
        """get_project_users when user doesn't exist, raises UserNotFound.

        When a user that's not known to `identity` has a role on a project,
        then `get_project_users` raises
        :class:`keystone.exception.UserNotFound`.

        """

        self.load_backends()
        self.load_fixtures(default_fixtures)
        tenant_controller = controllers.Tenant()
        role_controller = controllers.Role()

        # Assign a role to a user that doesn't exist to the `bar` project.

        project_id = self.tenant_bar['id']

        user_id = uuid.uuid4().hex
        role_controller.add_role_to_user(
            _ADMIN_CONTEXT, user_id, self.role_other['id'], project_id)

        self.assertRaisesRegexp(exception.UserNotFound,
                                'Could not find user, %s' % user_id,
                                tenant_controller.get_project_users,
                                _ADMIN_CONTEXT, project_id)
