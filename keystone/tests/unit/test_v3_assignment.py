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

import datetime
import random
import uuid

import freezegun
import http.client
from testtools import matchers

from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.resource.backends import base as resource_base
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class SystemRoleAssignmentMixin(object):

    def _create_new_role(self):
        """Create a role available for use anywhere and return the ID."""
        ref = unit.new_role_ref()
        response = self.post('/roles', body={'role': ref})
        # We only really need the role ID, so omit the rest of the response and
        # return the ID of the role we just created.
        return response.json_body['role']['id']

    def _create_group(self):
        body = {
            'group': {
                'domain_id': self.domain_id,
                'name': uuid.uuid4().hex
            }
        }
        response = self.post('/groups/', body=body)
        return response.json_body['group']

    def _create_user(self):
        body = {
            'user': {
                'domain_id': self.domain_id,
                'name': uuid.uuid4().hex
            }
        }
        response = self.post('/users/', body=body)
        return response.json_body['user']


class AssignmentTestCase(test_v3.RestfulTestCase,
                         test_v3.AssignmentTestMixin,
                         SystemRoleAssignmentMixin):
    """Test roles and role assignments."""

    def setUp(self):
        super(AssignmentTestCase, self).setUp()

        self.group = unit.new_group_ref(domain_id=self.domain_id)
        self.group = PROVIDERS.identity_api.create_group(self.group)
        self.group_id = self.group['id']

    # Role CRUD tests

    def test_create_role(self):
        """Call ``POST /roles``."""
        ref = unit.new_role_ref()
        r = self.post(
            '/roles',
            body={'role': ref})
        return self.assertValidRoleResponse(r, ref)

    def test_create_role_bad_request(self):
        """Call ``POST /roles``."""
        self.post('/roles', body={'role': {}},
                  expected_status=http.client.BAD_REQUEST)

    def test_list_head_roles(self):
        """Call ``GET & HEAD /roles``."""
        resource_url = '/roles'
        r = self.get(resource_url)
        self.assertValidRoleListResponse(r, ref=self.role,
                                         resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

    def test_get_head_role(self):
        """Call ``GET & HEAD /roles/{role_id}``."""
        resource_url = '/roles/%(role_id)s' % {
            'role_id': self.role_id}
        r = self.get(resource_url)
        self.assertValidRoleResponse(r, self.role)
        self.head(resource_url, expected_status=http.client.OK)

    def test_update_role(self):
        """Call ``PATCH /roles/{role_id}``."""
        ref = unit.new_role_ref()
        del ref['id']
        r = self.patch('/roles/%(role_id)s' % {
            'role_id': self.role_id},
            body={'role': ref})
        self.assertValidRoleResponse(r, ref)

    def test_delete_role(self):
        """Call ``DELETE /roles/{role_id}``."""
        self.delete('/roles/%(role_id)s' % {
            'role_id': self.role_id})

    # Role Grants tests

    def test_crud_user_project_role_grants(self):
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        collection_url = (
            '/projects/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.project['id'],
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': role['id']}

        # There is a role assignment for self.user on self.project
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=self.role,
                                         expected_length=1)

        self.put(member_url)
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=role,
                                         resource_url=collection_url,
                                         expected_length=2)
        self.head(collection_url, expected_status=http.client.OK)

        self.delete(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=self.role, expected_length=1)
        self.assertIn(collection_url, r.result['links']['self'])
        self.head(collection_url, expected_status=http.client.OK)

    def test_crud_user_project_role_grants_no_user(self):
        """Grant role on a project to a user that doesn't exist.

        When grant a role on a project to a user that doesn't exist, the server
        returns Not Found for the user.

        """
        user_id = uuid.uuid4().hex

        collection_url = (
            '/projects/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.project['id'], 'user_id': user_id})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url, expected_status=http.client.NOT_FOUND)
        self.head(member_url, expected_status=http.client.NOT_FOUND)
        self.get(member_url, expected_status=http.client.NOT_FOUND)

    def test_crud_user_domain_role_grants(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            collection_url = (
                '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                    'domain_id': self.domain_id,
                    'user_id': self.user['id']})
            member_url = '%(collection_url)s/%(role_id)s' % {
                'collection_url': collection_url,
                'role_id': self.role_id}

            self.put(member_url)
            self.head(member_url)
            self.get(member_url, expected_status=http.client.NO_CONTENT)
            r = self.get(collection_url)
            self.assertValidRoleListResponse(r, ref=self.role,
                                             resource_url=collection_url)
            self.head(collection_url, expected_status=http.client.OK)

            self.delete(member_url)
            # NOTE(lbragstad): Make sure we wait a second before we ask for the
            # roles. This ensures the token we use isn't considered revoked
            # because it was issued within the same second as a revocation
            # event.
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            r = self.get(collection_url)
            self.assertValidRoleListResponse(r, expected_length=0,
                                             resource_url=collection_url)
            self.head(collection_url, expected_status=http.client.OK)

    def test_crud_user_domain_role_grants_no_user(self):
        """Grant role on a domain to a user that doesn't exist.

        When grant a role on a domain to a user that doesn't exist, the server
        returns 404 Not Found for the user.

        """
        user_id = uuid.uuid4().hex

        collection_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.domain_id, 'user_id': user_id})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url, expected_status=http.client.NOT_FOUND)
        self.head(member_url, expected_status=http.client.NOT_FOUND)
        self.get(member_url, expected_status=http.client.NOT_FOUND)

    def test_crud_group_project_role_grants(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            collection_url = (
                '/projects/%(project_id)s/groups/%(group_id)s/roles' % {
                    'project_id': self.project_id,
                    'group_id': self.group_id})
            member_url = '%(collection_url)s/%(role_id)s' % {
                'collection_url': collection_url,
                'role_id': self.role_id}

            self.put(member_url)
            self.head(member_url)
            self.get(member_url, expected_status=http.client.NO_CONTENT)
            r = self.get(collection_url)
            self.assertValidRoleListResponse(r, ref=self.role,
                                             resource_url=collection_url)
            self.head(collection_url, expected_status=http.client.OK)

            self.delete(member_url)
            # NOTE(lbragstad): Make sure we wait a second before we ask for the
            # roles. This ensures the token we use isn't considered revoked
            # because it was issued within the same second as a revocation
            # event.
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            r = self.get(collection_url)
            self.assertValidRoleListResponse(r, expected_length=0,
                                             resource_url=collection_url)
            self.head(collection_url, expected_status=http.client.OK)

    def test_crud_group_project_role_grants_no_group(self):
        """Grant role on a project to a group that doesn't exist.

        When grant a role on a project to a group that doesn't exist, the
        server returns 404 Not Found for the group.

        """
        group_id = uuid.uuid4().hex

        collection_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/roles' % {
                'project_id': self.project_id,
                'group_id': group_id})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url, expected_status=http.client.NOT_FOUND)
        self.head(member_url, expected_status=http.client.NOT_FOUND)
        self.get(member_url, expected_status=http.client.NOT_FOUND)

    def test_crud_group_domain_role_grants(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            collection_url = (
                '/domains/%(domain_id)s/groups/%(group_id)s/roles' % {
                    'domain_id': self.domain_id,
                    'group_id': self.group_id})
            member_url = '%(collection_url)s/%(role_id)s' % {
                'collection_url': collection_url,
                'role_id': self.role_id}

            self.put(member_url)
            self.head(member_url)
            self.get(member_url, expected_status=http.client.NO_CONTENT)
            r = self.get(collection_url)
            self.assertValidRoleListResponse(r, ref=self.role,
                                             resource_url=collection_url)
            self.head(collection_url, expected_status=http.client.OK)

            self.delete(member_url)
            # NOTE(lbragstad): Make sure we wait a second before we ask for the
            # roles. This ensures the token we use isn't considered revoked
            # because it was issued within the same second as a revocation
            # event.
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            r = self.get(collection_url)
            self.assertValidRoleListResponse(r, expected_length=0,
                                             resource_url=collection_url)
            self.head(collection_url, expected_status=http.client.OK)

    def test_crud_group_domain_role_grants_no_group(self):
        """Grant role on a domain to a group that doesn't exist.

        When grant a role on a domain to a group that doesn't exist, the server
        returns 404 Not Found for the group.

        """
        group_id = uuid.uuid4().hex

        collection_url = (
            '/domains/%(domain_id)s/groups/%(group_id)s/roles' % {
                'domain_id': self.domain_id,
                'group_id': group_id})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url, expected_status=http.client.NOT_FOUND)
        self.head(member_url, expected_status=http.client.NOT_FOUND)
        self.get(member_url, expected_status=http.client.NOT_FOUND)

    def _create_new_user_and_assign_role_on_project(self):
        """Create a new user and assign user a role on a project."""
        # Create a new user
        new_user = unit.new_user_ref(domain_id=self.domain_id)
        user_ref = PROVIDERS.identity_api.create_user(new_user)
        # Assign the user a role on the project
        collection_url = (
            '/projects/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.project_id,
                'user_id': user_ref['id']})
        member_url = ('%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id})
        self.put(member_url)
        # Check the user has the role assigned
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        return member_url, user_ref

    def test_delete_user_before_removing_role_assignment_succeeds(self):
        """Call ``DELETE`` on the user before the role assignment."""
        member_url, user = self._create_new_user_and_assign_role_on_project()
        # Delete the user from identity backend
        PROVIDERS.identity_api.driver.delete_user(user['id'])
        # Clean up the role assignment
        self.delete(member_url)
        # Make sure the role is gone
        self.head(member_url, expected_status=http.client.NOT_FOUND)

    def test_delete_group_before_removing_role_assignment_succeeds(self):
        # Disable the cache so that we perform a fresh check of the identity
        # backend when attempting to remove the role assignment.
        self.config_fixture.config(group='cache', enabled=False)

        # Create a new group
        group = unit.new_group_ref(domain_id=self.domain_id)
        group_ref = PROVIDERS.identity_api.create_group(group)

        # Assign the user a role on the project
        collection_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/roles' % {
                'project_id': self.project_id,
                'group_id': group_ref['id']})
        member_url = ('%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id})
        self.put(member_url)

        # Check the user has the role assigned
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)

        # Simulate removing the group via LDAP by directly removing it from the
        # identity backend.
        PROVIDERS.identity_api.driver.delete_group(group_ref['id'])

        # Ensure we can clean up the role assignment even though the group
        # doesn't exist
        self.delete(member_url)

    def test_delete_user_before_removing_system_assignments_succeeds(self):
        system_role = self._create_new_role()
        user = self._create_user()
        path = (
            '/system/users/%(user_id)s/roles/%(role_id)s' %
            {'user_id': user['id'], 'role_id': system_role}
        )
        self.put(path)

        response = self.get('/role_assignments')
        number_of_assignments = len(response.json_body['role_assignments'])

        path = '/users/%(user_id)s' % {'user_id': user['id']}
        self.delete(path)

        # The user with the system role assignment is a new user and only has
        # one role on the system. We should expect one less role assignment in
        # the list.
        response = self.get('/role_assignments')
        self.assertValidRoleAssignmentListResponse(
            response, expected_length=number_of_assignments - 1
        )

    def test_delete_user_and_check_role_assignment_fails(self):
        """Call ``DELETE`` on the user and check the role assignment."""
        member_url, user = self._create_new_user_and_assign_role_on_project()
        # Delete the user from identity backend
        PROVIDERS.identity_api.delete_user(user['id'])
        # We should get a 404 Not Found when looking for the user in the
        # identity backend because we're not performing a delete operation on
        # the role.
        self.head(member_url, expected_status=http.client.NOT_FOUND)

    def test_token_revoked_once_group_role_grant_revoked(self):
        """Test token invalid when direct & indirect role on user is revoked.

        When a role granted to a group is revoked for a given scope,
        and user direct role is revoked, then tokens created
        by user will be invalid.

        """
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            # creates grant from group on project.
            PROVIDERS.assignment_api.create_grant(
                role_id=self.role['id'], project_id=self.project['id'],
                group_id=self.group['id']
            )

            # adds user to the group.
            PROVIDERS.identity_api.add_user_to_group(
                user_id=self.user['id'], group_id=self.group['id']
            )

            # creates a token for the user
            auth_body = self.build_authentication_request(
                user_id=self.user['id'],
                password=self.user['password'],
                project_id=self.project['id'])
            token_resp = self.post('/auth/tokens', body=auth_body)
            token = token_resp.headers.get('x-subject-token')

            # validates the returned token; it should be valid.
            self.head('/auth/tokens',
                      headers={'x-subject-token': token},
                      expected_status=http.client.OK)

            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            # revokes the grant from group on project.
            PROVIDERS.assignment_api.delete_grant(
                role_id=self.role['id'], project_id=self.project['id'],
                group_id=self.group['id'])
            # revokes the direct role form user on project
            PROVIDERS.assignment_api.delete_grant(
                role_id=self.role['id'], project_id=self.project['id'],
                user_id=self.user['id']
            )

            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            # validates the same token again; it should not longer be valid.
            self.head('/auth/tokens', token=token,
                      expected_status=http.client.UNAUTHORIZED)

    def test_delete_group_before_removing_system_assignments_succeeds(self):
        system_role = self._create_new_role()
        group = self._create_group()
        path = (
            '/system/groups/%(group_id)s/roles/%(role_id)s' %
            {'group_id': group['id'], 'role_id': system_role}
        )
        self.put(path)

        response = self.get('/role_assignments')
        number_of_assignments = len(response.json_body['role_assignments'])

        path = '/groups/%(group_id)s' % {'group_id': group['id']}
        self.delete(path)

        # The group with the system role assignment is a new group and only has
        # one role on the system. We should expect one less role assignment in
        # the list.
        response = self.get('/role_assignments')
        self.assertValidRoleAssignmentListResponse(
            response, expected_length=number_of_assignments - 1
        )

    @unit.skip_if_cache_disabled('assignment')
    def test_delete_grant_from_user_and_project_invalidate_cache(self):
        # create a new project
        new_project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)

        collection_url = (
            '/projects/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': new_project['id'],
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        # create the user a grant on the new project
        self.put(member_url)

        # check the grant that was just created
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        resp = self.get(collection_url)
        self.assertValidRoleListResponse(resp, ref=self.role,
                                         resource_url=collection_url)

        # delete the grant
        self.delete(member_url)

        # get the collection and ensure there are no roles on the project
        resp = self.get(collection_url)
        self.assertListEqual(resp.json_body['roles'], [])

    @unit.skip_if_cache_disabled('assignment')
    def test_delete_grant_from_user_and_domain_invalidates_cache(self):
        # create a new domain
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)

        collection_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': new_domain['id'],
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        # create the user a grant on the new domain
        self.put(member_url)

        # check the grant that was just created
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        resp = self.get(collection_url)
        self.assertValidRoleListResponse(resp, ref=self.role,
                                         resource_url=collection_url)

        # delete the grant
        self.delete(member_url)

        # get the collection and ensure there are no roles on the domain
        resp = self.get(collection_url)
        self.assertListEqual(resp.json_body['roles'], [])

    @unit.skip_if_cache_disabled('assignment')
    def test_delete_grant_from_group_and_project_invalidates_cache(self):
        # create a new project
        new_project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)

        collection_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/roles' % {
                'project_id': new_project['id'],
                'group_id': self.group['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        # create the group a grant on the new project
        self.put(member_url)

        # check the grant that was just created
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        resp = self.get(collection_url)
        self.assertValidRoleListResponse(resp, ref=self.role,
                                         resource_url=collection_url)

        # delete the grant
        self.delete(member_url)

        # get the collection and ensure there are no roles on the project
        resp = self.get(collection_url)
        self.assertListEqual(resp.json_body['roles'], [])

    @unit.skip_if_cache_disabled('assignment')
    def test_delete_grant_from_group_and_domain_invalidates_cache(self):
        # create a new domain
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)

        collection_url = (
            '/domains/%(domain_id)s/groups/%(group_id)s/roles' % {
                'domain_id': new_domain['id'],
                'group_id': self.group['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        # create the group a grant on the new domain
        self.put(member_url)

        # check the grant that was just created
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        resp = self.get(collection_url)
        self.assertValidRoleListResponse(resp, ref=self.role,
                                         resource_url=collection_url)

        # delete the grant
        self.delete(member_url)

        # get the collection and ensure there are no roles on the domain
        resp = self.get(collection_url)
        self.assertListEqual(resp.json_body['roles'], [])

    # Role Assignments tests

    def test_get_head_role_assignments(self):
        """Call ``GET & HEAD /role_assignments``.

        The sample data set up already has a user, group and project
        that is part of self.domain. We use these plus a new user
        we create as our data set, making sure we ignore any
        role assignments that are already in existence.

        Since we don't yet support a first class entity for role
        assignments, we are only testing the LIST API.  To create
        and delete the role assignments we use the old grant APIs.

        Test Plan:

        - Create extra user for tests
        - Get a list of all existing role assignments
        - Add a new assignment for each of the four combinations, i.e.
          group+domain, user+domain, group+project, user+project, using
          the same role each time
        - Get a new list of all role assignments, checking these four new
          ones have been added
        - Then delete the four we added
        - Get a new list of all role assignments, checking the four have
          been removed

        """
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            # Since the default fixtures already assign some roles to the
            # user it creates, we also need a new user that will not have any
            # existing assignments
            user1 = unit.new_user_ref(domain_id=self.domain['id'])
            user1 = PROVIDERS.identity_api.create_user(user1)

            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)

            collection_url = '/role_assignments'
            r = self.get(collection_url)
            self.assertValidRoleAssignmentListResponse(
                r, resource_url=collection_url)
            self.head(collection_url, expected_status=http.client.OK)
            existing_assignments = len(r.result.get('role_assignments'))

            # Now add one of each of the four types of assignment, making sure
            # that we get them all back.
            gd_entity = self.build_role_assignment_entity(
                domain_id=self.domain_id,
                group_id=self.group_id,
                role_id=role['id'])
            self.put(gd_entity['links']['assignment'])
            r = self.get(collection_url)
            self.assertValidRoleAssignmentListResponse(
                r,
                expected_length=existing_assignments + 1,
                resource_url=collection_url)
            self.assertRoleAssignmentInListResponse(r, gd_entity)
            self.head(collection_url, expected_status=http.client.OK)

            ud_entity = self.build_role_assignment_entity(
                domain_id=self.domain_id,
                user_id=user1['id'],
                role_id=role['id'])
            self.put(ud_entity['links']['assignment'])
            r = self.get(collection_url)
            self.assertValidRoleAssignmentListResponse(
                r,
                expected_length=existing_assignments + 2,
                resource_url=collection_url)
            self.assertRoleAssignmentInListResponse(r, ud_entity)
            self.head(collection_url, expected_status=http.client.OK)

            gp_entity = self.build_role_assignment_entity(
                project_id=self.project_id, group_id=self.group_id,
                role_id=role['id'])
            self.put(gp_entity['links']['assignment'])
            r = self.get(collection_url)
            self.assertValidRoleAssignmentListResponse(
                r,
                expected_length=existing_assignments + 3,
                resource_url=collection_url)
            self.assertRoleAssignmentInListResponse(r, gp_entity)
            self.head(collection_url, expected_status=http.client.OK)

            up_entity = self.build_role_assignment_entity(
                project_id=self.project_id, user_id=user1['id'],
                role_id=role['id'])
            self.put(up_entity['links']['assignment'])
            r = self.get(collection_url)
            self.assertValidRoleAssignmentListResponse(
                r,
                expected_length=existing_assignments + 4,
                resource_url=collection_url)
            self.assertRoleAssignmentInListResponse(r, up_entity)
            self.head(collection_url, expected_status=http.client.OK)

            # Now delete the four we added and make sure they are removed
            # from the collection.

            self.delete(gd_entity['links']['assignment'])
            self.delete(ud_entity['links']['assignment'])
            self.delete(gp_entity['links']['assignment'])
            self.delete(up_entity['links']['assignment'])
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            r = self.get(collection_url)
            self.assertValidRoleAssignmentListResponse(
                r,
                expected_length=existing_assignments,
                resource_url=collection_url)
            self.assertRoleAssignmentNotInListResponse(r, gd_entity)
            self.assertRoleAssignmentNotInListResponse(r, ud_entity)
            self.assertRoleAssignmentNotInListResponse(r, gp_entity)
            self.assertRoleAssignmentNotInListResponse(r, up_entity)
            self.head(collection_url, expected_status=http.client.OK)

    def test_get_effective_role_assignments(self):
        """Call ``GET /role_assignments?effective``.

        Test Plan:

        - Create two extra user for tests
        - Add these users to a group
        - Add a role assignment for the group on a domain
        - Get a list of all role assignments, checking one has been added
        - Then get a list of all effective role assignments - the group
          assignment should have turned into assignments on the domain
          for each of the group members.

        """
        user1 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])
        user2 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])

        PROVIDERS.identity_api.add_user_to_group(user1['id'], self.group['id'])
        PROVIDERS.identity_api.add_user_to_group(user2['id'], self.group['id'])

        collection_url = '/role_assignments'
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   resource_url=collection_url)
        existing_assignments = len(r.result.get('role_assignments'))

        gd_entity = self.build_role_assignment_entity(domain_id=self.domain_id,
                                                      group_id=self.group_id,
                                                      role_id=self.role_id)
        self.put(gd_entity['links']['assignment'])
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            r,
            expected_length=existing_assignments + 1,
            resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, gd_entity)

        # Now re-read the collection asking for effective roles - this
        # should mean the group assignment is translated into the two
        # member user assignments
        collection_url = '/role_assignments?effective'
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            r,
            expected_length=existing_assignments + 2,
            resource_url=collection_url)
        ud_entity = self.build_role_assignment_entity(
            link=gd_entity['links']['assignment'], domain_id=self.domain_id,
            user_id=user1['id'], role_id=self.role_id)
        self.assertRoleAssignmentInListResponse(r, ud_entity)
        ud_entity = self.build_role_assignment_entity(
            link=gd_entity['links']['assignment'], domain_id=self.domain_id,
            user_id=user2['id'], role_id=self.role_id)
        self.assertRoleAssignmentInListResponse(r, ud_entity)

    def test_check_effective_values_for_role_assignments(self):
        """Call ``GET & HEAD /role_assignments?effective=value``.

        Check the various ways of specifying the 'effective'
        query parameter.  If the 'effective' query parameter
        is included then this should always be treated as meaning 'True'
        unless it is specified as:

        {url}?effective=0

        This is by design to match the agreed way of handling
        policy checking on query/filter parameters.

        Test Plan:

        - Create two extra user for tests
        - Add these users to a group
        - Add a role assignment for the group on a domain
        - Get a list of all role assignments, checking one has been added
        - Then issue various request with different ways of defining
          the 'effective' query parameter. As we have tested the
          correctness of the data coming back when we get effective roles
          in other tests, here we just use the count of entities to
          know if we are getting effective roles or not

        """
        user1 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])
        user2 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])

        PROVIDERS.identity_api.add_user_to_group(user1['id'], self.group['id'])
        PROVIDERS.identity_api.add_user_to_group(user2['id'], self.group['id'])

        collection_url = '/role_assignments'
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   resource_url=collection_url)
        existing_assignments = len(r.result.get('role_assignments'))

        gd_entity = self.build_role_assignment_entity(domain_id=self.domain_id,
                                                      group_id=self.group_id,
                                                      role_id=self.role_id)
        self.put(gd_entity['links']['assignment'])
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(
            r,
            expected_length=existing_assignments + 1,
            resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, gd_entity)

        # Now re-read the collection asking for effective roles,
        # using the most common way of defining "effective'. This
        # should mean the group assignment is translated into the two
        # member user assignments
        collection_url = '/role_assignments?effective'
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(
            r,
            expected_length=existing_assignments + 2,
            resource_url=collection_url)
        # Now set 'effective' to false explicitly - should get
        # back the regular roles
        collection_url = '/role_assignments?effective=0'
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(
            r,
            expected_length=existing_assignments + 1,
            resource_url=collection_url)
        # Now try setting  'effective' to 'False' explicitly- this is
        # NOT supported as a way of setting a query or filter
        # parameter to false by design. Hence we should get back
        # effective roles.
        collection_url = '/role_assignments?effective=False'
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(
            r,
            expected_length=existing_assignments + 2,
            resource_url=collection_url)
        # Now set 'effective' to True explicitly
        collection_url = '/role_assignments?effective=True'
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(
            r,
            expected_length=existing_assignments + 2,
            resource_url=collection_url)

    def test_filtered_role_assignments(self):
        """Call ``GET /role_assignments?filters``.

        Test Plan:

        - Create extra users, group, role and project for tests
        - Make the following assignments:
          Give group1, role1 on project1 and domain
          Give user1, role2 on project1 and domain
          Make User1 a member of Group1
        - Test a series of single filter list calls, checking that
          the correct results are obtained
        - Test a multi-filtered list call
        - Test listing all effective roles for a given user
        - Test the equivalent of the list of roles in a project scoped
          token (all effective roles for a user on a project)

        """
        # Since the default fixtures already assign some roles to the
        # user it creates, we also need a new user that will not have any
        # existing assignments
        user1 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])
        user2 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])

        group1 = unit.new_group_ref(domain_id=self.domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        PROVIDERS.identity_api.add_user_to_group(user1['id'], group1['id'])
        PROVIDERS.identity_api.add_user_to_group(user2['id'], group1['id'])
        project1 = unit.new_project_ref(domain_id=self.domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        self.role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role1['id'], self.role1)
        self.role2 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role2['id'], self.role2)

        # Now add one of each of the six types of assignment

        gd_entity = self.build_role_assignment_entity(
            domain_id=self.domain_id, group_id=group1['id'],
            role_id=self.role1['id'])
        self.put(gd_entity['links']['assignment'])

        ud_entity = self.build_role_assignment_entity(domain_id=self.domain_id,
                                                      user_id=user1['id'],
                                                      role_id=self.role2['id'])
        self.put(ud_entity['links']['assignment'])

        gp_entity = self.build_role_assignment_entity(
            project_id=project1['id'],
            group_id=group1['id'],
            role_id=self.role1['id'])
        self.put(gp_entity['links']['assignment'])

        up_entity = self.build_role_assignment_entity(
            project_id=project1['id'],
            user_id=user1['id'],
            role_id=self.role2['id'])
        self.put(up_entity['links']['assignment'])

        gs_entity = self.build_role_assignment_entity(
            system='all',
            group_id=group1['id'],
            role_id=self.role1['id'])
        self.put(gs_entity['links']['assignment'])
        us_entity = self.build_role_assignment_entity(
            system='all',
            user_id=user1['id'],
            role_id=self.role2['id'])
        self.put(us_entity['links']['assignment'])
        us2_entity = self.build_role_assignment_entity(
            system='all',
            user_id=user2['id'],
            role_id=self.role2['id'])
        self.put(us2_entity['links']['assignment'])

        # Now list by various filters to make sure we get back the right ones

        collection_url = ('/role_assignments?scope.project.id=%s' %
                          project1['id'])
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=2,
                                                   resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, up_entity)
        self.assertRoleAssignmentInListResponse(r, gp_entity)

        collection_url = ('/role_assignments?scope.domain.id=%s' %
                          self.domain['id'])
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=2,
                                                   resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, ud_entity)
        self.assertRoleAssignmentInListResponse(r, gd_entity)

        collection_url = '/role_assignments?user.id=%s' % user1['id']
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=3,
                                                   resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, up_entity)
        self.assertRoleAssignmentInListResponse(r, ud_entity)

        collection_url = '/role_assignments?group.id=%s' % group1['id']
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=3,
                                                   resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, gd_entity)
        self.assertRoleAssignmentInListResponse(r, gp_entity)

        collection_url = '/role_assignments?role.id=%s' % self.role1['id']
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=3,
                                                   resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, gd_entity)
        self.assertRoleAssignmentInListResponse(r, gp_entity)
        self.assertRoleAssignmentInListResponse(r, gs_entity)

        collection_url = '/role_assignments?role.id=%s' % self.role2['id']
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=4,
                                                   resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, ud_entity)
        self.assertRoleAssignmentInListResponse(r, up_entity)
        self.assertRoleAssignmentInListResponse(r, us_entity)

        # Let's try combining two filers together....

        collection_url = (
            '/role_assignments?user.id=%(user_id)s'
            '&scope.project.id=%(project_id)s' % {
                'user_id': user1['id'],
                'project_id': project1['id']})
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=1,
                                                   resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(r, up_entity)

        # Now for a harder one - filter for user with effective
        # roles - this should return role assignment that were directly
        # assigned as well as by virtue of group membership

        collection_url = ('/role_assignments?effective&user.id=%s' %
                          user1['id'])
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=4,
                                                   resource_url=collection_url)
        # Should have the two direct roles...
        self.assertRoleAssignmentInListResponse(r, up_entity)
        self.assertRoleAssignmentInListResponse(r, ud_entity)
        # ...and the two via group membership...
        gp1_link = self.build_role_assignment_link(
            project_id=project1['id'],
            group_id=group1['id'],
            role_id=self.role1['id'])
        gd1_link = self.build_role_assignment_link(domain_id=self.domain_id,
                                                   group_id=group1['id'],
                                                   role_id=self.role1['id'])

        up1_entity = self.build_role_assignment_entity(
            link=gp1_link, project_id=project1['id'],
            user_id=user1['id'], role_id=self.role1['id'])
        ud1_entity = self.build_role_assignment_entity(
            link=gd1_link, domain_id=self.domain_id, user_id=user1['id'],
            role_id=self.role1['id'])
        self.assertRoleAssignmentInListResponse(r, up1_entity)
        self.assertRoleAssignmentInListResponse(r, ud1_entity)

        # ...and for the grand-daddy of them all, simulate the request
        # that would generate the list of effective roles in a project
        # scoped token.

        collection_url = (
            '/role_assignments?effective&user.id=%(user_id)s'
            '&scope.project.id=%(project_id)s' % {
                'user_id': user1['id'],
                'project_id': project1['id']})
        r = self.get(collection_url, expected_status=http.client.OK)
        self.head(collection_url, expected_status=http.client.OK)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=2,
                                                   resource_url=collection_url)
        # Should have one direct role and one from group membership...
        self.assertRoleAssignmentInListResponse(r, up_entity)
        self.assertRoleAssignmentInListResponse(r, up1_entity)

    def test_list_system_role_assignments(self):
        # create a bunch of roles
        user_system_role_id = self._create_new_role()
        user_domain_role_id = self._create_new_role()
        user_project_role_id = self._create_new_role()
        group_system_role_id = self._create_new_role()
        group_domain_role_id = self._create_new_role()
        group_project_role_id = self._create_new_role()

        # create a user and grant the user a role on the system, domain, and
        # project
        user = self._create_user()
        url = '/system/users/%s/roles/%s' % (user['id'], user_system_role_id)
        self.put(url)
        url = '/domains/%s/users/%s/roles/%s' % (
            self.domain_id, user['id'], user_domain_role_id
        )
        self.put(url)
        url = '/projects/%s/users/%s/roles/%s' % (
            self.project_id, user['id'], user_project_role_id
        )
        self.put(url)

        # create a group and grant the group a role on the system, domain, and
        # project
        group = self._create_group()
        url = '/system/groups/%s/roles/%s' % (
            group['id'], group_system_role_id
        )
        self.put(url)
        url = '/domains/%s/groups/%s/roles/%s' % (
            self.domain_id, group['id'], group_domain_role_id
        )
        self.put(url)
        url = '/projects/%s/groups/%s/roles/%s' % (
            self.project_id, group['id'], group_project_role_id
        )
        self.put(url)

        # /v3/role_assignments?scope.system=all should return two assignments
        response = self.get('/role_assignments?scope.system=all')
        self.assertValidRoleAssignmentListResponse(response, expected_length=2)
        for assignment in response.json_body['role_assignments']:
            self.assertTrue(assignment['scope']['system']['all'])
            if assignment.get('user'):
                self.assertEqual(user_system_role_id, assignment['role']['id'])
            if assignment.get('group'):
                self.assertEqual(
                    group_system_role_id,
                    assignment['role']['id']
                )

        # /v3/role_assignments?scope_system=all&user.id=$USER_ID should return
        # one role assignment
        url = '/role_assignments?scope.system=all&user.id=%s' % user['id']
        response = self.get(url)
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)
        self.assertEqual(
            user_system_role_id,
            response.json_body['role_assignments'][0]['role']['id']
        )

        # /v3/role_assignments?scope_system=all&group.id=$GROUP_ID should
        # return one role assignment
        url = '/role_assignments?scope.system=all&group.id=%s' % group['id']
        response = self.get(url)
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)
        self.assertEqual(
            group_system_role_id,
            response.json_body['role_assignments'][0]['role']['id']
        )

        # /v3/role_assignments?user.id=$USER_ID should return 3 assignments
        # and system should be in that list of assignments
        url = '/role_assignments?user.id=%s' % user['id']
        response = self.get(url)
        self.assertValidRoleAssignmentListResponse(response, expected_length=3)
        for assignment in response.json_body['role_assignments']:
            if 'system' in assignment['scope']:
                self.assertEqual(
                    user_system_role_id, assignment['role']['id']
                )
            if 'domain' in assignment['scope']:
                self.assertEqual(
                    user_domain_role_id, assignment['role']['id']
                )
            if 'project' in assignment['scope']:
                self.assertEqual(
                    user_project_role_id, assignment['role']['id']
                )

        # /v3/role_assignments?group.id=$GROUP_ID should return 3 assignments
        # and system should be in that list of assignments
        url = '/role_assignments?group.id=%s' % group['id']
        response = self.get(url)
        self.assertValidRoleAssignmentListResponse(response, expected_length=3)
        for assignment in response.json_body['role_assignments']:
            if 'system' in assignment['scope']:
                self.assertEqual(
                    group_system_role_id, assignment['role']['id']
                )
            if 'domain' in assignment['scope']:
                self.assertEqual(
                    group_domain_role_id, assignment['role']['id']
                )
            if 'project' in assignment['scope']:
                self.assertEqual(
                    group_project_role_id, assignment['role']['id']
                )


class RoleAssignmentBaseTestCase(test_v3.RestfulTestCase,
                                 test_v3.AssignmentTestMixin):
    """Base class for testing /v3/role_assignments API behavior."""

    MAX_HIERARCHY_BREADTH = 3
    MAX_HIERARCHY_DEPTH = CONF.max_project_tree_depth - 1

    def load_sample_data(self):
        """Create sample data to be used on tests.

        Created data are i) a role and ii) a domain containing: a project
        hierarchy and 3 users within 3 groups.

        """
        def create_project_hierarchy(parent_id, depth):
            """Create a random project hierarchy."""
            if depth == 0:
                return

            breadth = random.randint(1, self.MAX_HIERARCHY_BREADTH)

            subprojects = []
            for i in range(breadth):
                subprojects.append(unit.new_project_ref(
                    domain_id=self.domain_id, parent_id=parent_id))
                PROVIDERS.resource_api.create_project(
                    subprojects[-1]['id'], subprojects[-1]
                )

            new_parent = subprojects[random.randint(0, breadth - 1)]
            create_project_hierarchy(new_parent['id'], depth - 1)

        super(RoleAssignmentBaseTestCase, self).load_sample_data()

        # Create a domain
        self.domain = unit.new_domain_ref()
        self.domain_id = self.domain['id']
        PROVIDERS.resource_api.create_domain(self.domain_id, self.domain)

        # Create a project hierarchy
        self.project = unit.new_project_ref(domain_id=self.domain_id)
        self.project_id = self.project['id']
        PROVIDERS.resource_api.create_project(self.project_id, self.project)

        # Create a random project hierarchy
        create_project_hierarchy(self.project_id,
                                 random.randint(1, self.MAX_HIERARCHY_DEPTH))

        # Create 3 users
        self.user_ids = []
        for i in range(3):
            user = unit.new_user_ref(domain_id=self.domain_id)
            user = PROVIDERS.identity_api.create_user(user)
            self.user_ids.append(user['id'])

        # Create 3 groups
        self.group_ids = []
        for i in range(3):
            group = unit.new_group_ref(domain_id=self.domain_id)
            group = PROVIDERS.identity_api.create_group(group)
            self.group_ids.append(group['id'])

            # Put 2 members on each group
            PROVIDERS.identity_api.add_user_to_group(
                user_id=self.user_ids[i], group_id=group['id']
            )
            PROVIDERS.identity_api.add_user_to_group(
                user_id=self.user_ids[i % 2], group_id=group['id']
            )

        PROVIDERS.assignment_api.create_grant(
            user_id=self.user_id, project_id=self.project_id,
            role_id=self.role_id
        )

        # Create a role
        self.role = unit.new_role_ref()
        self.role_id = self.role['id']
        PROVIDERS.role_api.create_role(self.role_id, self.role)

        # Set default user and group to be used on tests
        self.default_user_id = self.user_ids[0]
        self.default_group_id = self.group_ids[0]

    def get_role_assignments(self, expected_status=http.client.OK, **filters):
        """Return the result from querying role assignment API + queried URL.

        Calls GET /v3/role_assignments?<params> and returns its result, where
        <params> is the HTTP query parameters form of effective option plus
        filters, if provided. Queried URL is returned as well.

        :returns: a tuple containing the list role assignments API response and
                  queried URL.

        """
        query_url = self._get_role_assignments_query_url(**filters)
        response = self.get(query_url, expected_status=expected_status)

        return (response, query_url)

    def _get_role_assignments_query_url(self, **filters):
        """Return non-effective role assignments query URL from given filters.

        :param filters: query parameters are created with the provided filters
                        on role assignments attributes. Valid filters are:
                        role_id, domain_id, project_id, group_id, user_id and
                        inherited_to_projects.

        :returns: role assignments query URL.

        """
        return self.build_role_assignment_query_url(**filters)


class RoleAssignmentFailureTestCase(RoleAssignmentBaseTestCase):
    """Class for testing invalid query params on /v3/role_assignments API.

    Querying domain and project, or user and group results in a HTTP 400 Bad
    Request, since a role assignment must contain only a single pair of (actor,
    target). In addition, since filtering on role assignments applies only to
    the final result, effective mode cannot be combined with i) group or ii)
    domain and inherited, because it would always result in an empty list.

    """

    def test_get_role_assignments_by_domain_and_project(self):
        self.get_role_assignments(domain_id=self.domain_id,
                                  project_id=self.project_id,
                                  expected_status=http.client.BAD_REQUEST)

    def test_get_role_assignments_by_user_and_group(self):
        self.get_role_assignments(user_id=self.default_user_id,
                                  group_id=self.default_group_id,
                                  expected_status=http.client.BAD_REQUEST)

    def test_get_role_assignments_by_effective_and_inherited(self):
        self.get_role_assignments(domain_id=self.domain_id, effective=True,
                                  inherited_to_projects=True,
                                  expected_status=http.client.BAD_REQUEST)

    def test_get_role_assignments_by_effective_and_group(self):
        self.get_role_assignments(effective=True,
                                  group_id=self.default_group_id,
                                  expected_status=http.client.BAD_REQUEST)


class RoleAssignmentDirectTestCase(RoleAssignmentBaseTestCase):
    """Class for testing direct assignments on /v3/role_assignments API.

    Direct assignments on a domain or project have effect on them directly,
    instead of on their project hierarchy, i.e they are non-inherited. In
    addition, group direct assignments are not expanded to group's users.

    Tests on this class make assertions on the representation and API filtering
    of direct assignments.

    """

    def _test_get_role_assignments(self, **filters):
        """Generic filtering test method.

        According to the provided filters, this method:
        - creates a new role assignment;
        - asserts that list role assignments API reponds correctly;
        - deletes the created role assignment.

        :param filters: filters to be considered when listing role assignments.
                        Valid filters are: role_id, domain_id, project_id,
                        group_id, user_id and inherited_to_projects.

        """
        # Fills default assignment with provided filters
        test_assignment = self._set_default_assignment_attributes(**filters)

        # Create new role assignment for this test
        PROVIDERS.assignment_api.create_grant(**test_assignment)

        # Get expected role assignments
        expected_assignments = self._list_expected_role_assignments(
            **test_assignment)

        # Get role assignments from API
        response, query_url = self.get_role_assignments(**test_assignment)
        self.assertValidRoleAssignmentListResponse(response,
                                                   resource_url=query_url)
        self.assertEqual(len(expected_assignments),
                         len(response.result.get('role_assignments')))

        # Assert that expected role assignments were returned by the API call
        for assignment in expected_assignments:
            self.assertRoleAssignmentInListResponse(response, assignment)

        # Delete created role assignment
        PROVIDERS.assignment_api.delete_grant(**test_assignment)

    def _set_default_assignment_attributes(self, **attribs):
        """Insert default values for missing attributes of role assignment.

        If no actor, target or role are provided, they will default to values
        from sample data.

        :param attribs: info from a role assignment entity. Valid attributes
                        are: role_id, domain_id, project_id, group_id, user_id
                        and inherited_to_projects.

        """
        if not any(target in attribs
                   for target in ('domain_id', 'projects_id')):
            attribs['project_id'] = self.project_id

        if not any(actor in attribs for actor in ('user_id', 'group_id')):
            attribs['user_id'] = self.default_user_id

        if 'role_id' not in attribs:
            attribs['role_id'] = self.role_id

        return attribs

    def _list_expected_role_assignments(self, **filters):
        """Given the filters, it returns expected direct role assignments.

        :param filters: filters that will be considered when listing role
                        assignments. Valid filters are: role_id, domain_id,
                        project_id, group_id, user_id and
                        inherited_to_projects.

        :returns: the list of the expected role assignments.

        """
        return [self.build_role_assignment_entity(**filters)]

    # Test cases below call the generic test method, providing different filter
    # combinations. Filters are provided as specified in the method name, after
    # 'by'. For example, test_get_role_assignments_by_project_user_and_role
    # calls the generic test method with project_id, user_id and role_id.

    def test_get_role_assignments_by_domain(self, **filters):
        self._test_get_role_assignments(domain_id=self.domain_id, **filters)

    def test_get_role_assignments_by_project(self, **filters):
        self._test_get_role_assignments(project_id=self.project_id, **filters)

    def test_get_role_assignments_by_user(self, **filters):
        self._test_get_role_assignments(user_id=self.default_user_id,
                                        **filters)

    def test_get_role_assignments_by_group(self, **filters):
        self._test_get_role_assignments(group_id=self.default_group_id,
                                        **filters)

    def test_get_role_assignments_by_role(self, **filters):
        self._test_get_role_assignments(role_id=self.role_id, **filters)

    def test_get_role_assignments_by_domain_and_user(self, **filters):
        self.test_get_role_assignments_by_domain(user_id=self.default_user_id,
                                                 **filters)

    def test_get_role_assignments_by_domain_and_group(self, **filters):
        self.test_get_role_assignments_by_domain(
            group_id=self.default_group_id, **filters)

    def test_get_role_assignments_by_project_and_user(self, **filters):
        self.test_get_role_assignments_by_project(user_id=self.default_user_id,
                                                  **filters)

    def test_get_role_assignments_by_project_and_group(self, **filters):
        self.test_get_role_assignments_by_project(
            group_id=self.default_group_id, **filters)

    def test_get_role_assignments_by_domain_user_and_role(self, **filters):
        self.test_get_role_assignments_by_domain_and_user(role_id=self.role_id,
                                                          **filters)

    def test_get_role_assignments_by_domain_group_and_role(self, **filters):
        self.test_get_role_assignments_by_domain_and_group(
            role_id=self.role_id, **filters)

    def test_get_role_assignments_by_project_user_and_role(self, **filters):
        self.test_get_role_assignments_by_project_and_user(
            role_id=self.role_id, **filters)

    def test_get_role_assignments_by_project_group_and_role(self, **filters):
        self.test_get_role_assignments_by_project_and_group(
            role_id=self.role_id, **filters)


class RoleAssignmentInheritedTestCase(RoleAssignmentDirectTestCase):
    """Class for testing inherited assignments on /v3/role_assignments API.

    Inherited assignments on a domain or project have no effect on them
    directly, but on the projects under them instead.

    Tests on this class do not make assertions on the effect of inherited
    assignments, but in their representation and API filtering.

    """

    def _test_get_role_assignments(self, **filters):
        """Add inherited_to_project filter to expected entity in tests."""
        super(RoleAssignmentInheritedTestCase,
              self)._test_get_role_assignments(inherited_to_projects=True,
                                               **filters)


class RoleAssignmentEffectiveTestCase(RoleAssignmentInheritedTestCase):
    """Class for testing inheritance effects on /v3/role_assignments API.

    Inherited assignments on a domain or project have no effect on them
    directly, but on the projects under them instead.

    Tests on this class make assertions on the effect of inherited assignments
    and API filtering.

    """

    def _get_role_assignments_query_url(self, **filters):
        """Return effective role assignments query URL from given filters.

        For test methods in this class, effetive will always be true. As in
        effective mode, inherited_to_projects, group_id, domain_id and
        project_id will always be desconsidered from provided filters.

        :param filters: query parameters are created with the provided filters.
                        Valid filters are: role_id, domain_id, project_id,
                        group_id, user_id and inherited_to_projects.

        :returns: role assignments query URL.

        """
        query_filters = filters.copy()
        query_filters.pop('inherited_to_projects')

        query_filters.pop('group_id', None)
        query_filters.pop('domain_id', None)
        query_filters.pop('project_id', None)

        return self.build_role_assignment_query_url(effective=True,
                                                    **query_filters)

    def _list_expected_role_assignments(self, **filters):
        """Given the filters, it returns expected direct role assignments.

        :param filters: filters that will be considered when listing role
                        assignments. Valid filters are: role_id, domain_id,
                        project_id, group_id, user_id and
                        inherited_to_projects.

        :returns: the list of the expected role assignments.

        """
        # Get assignment link, to be put on 'links': {'assignment': link}
        assignment_link = self.build_role_assignment_link(**filters)

        # Expand group membership
        user_ids = [None]
        if filters.get('group_id'):
            user_ids = [user['id'] for user in
                        PROVIDERS.identity_api.list_users_in_group(
                            filters['group_id'])]
        else:
            user_ids = [self.default_user_id]

        # Expand role inheritance
        project_ids = [None]
        if filters.get('domain_id'):
            project_ids = [project['id'] for project in
                           PROVIDERS.resource_api.list_projects_in_domain(
                               filters.pop('domain_id'))]
        else:
            project_ids = [project['id'] for project in
                           PROVIDERS.resource_api.list_projects_in_subtree(
                               self.project_id)]

        # Compute expected role assignments
        assignments = []
        for project_id in project_ids:
            filters['project_id'] = project_id
            for user_id in user_ids:
                filters['user_id'] = user_id
                assignments.append(self.build_role_assignment_entity(
                    link=assignment_link, **filters))

        return assignments


class AssignmentInheritanceTestCase(test_v3.RestfulTestCase,
                                    test_v3.AssignmentTestMixin):
    """Test inheritance crud and its effects."""

    def test_get_token_from_inherited_user_domain_role_grants(self):
        # Create a new user to ensure that no grant is loaded from sample data
        user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )

        # Define domain and project authentication data
        domain_auth_data = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            domain_id=self.domain_id)
        project_auth_data = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            project_id=self.project_id)

        # Check the user cannot get a domain nor a project token
        self.v3_create_token(domain_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Grant non-inherited role for user on domain
        non_inher_ud_link = self.build_role_assignment_link(
            domain_id=self.domain_id, user_id=user['id'], role_id=self.role_id)
        self.put(non_inher_ud_link)

        # Check the user can get only a domain token
        self.v3_create_token(domain_auth_data)
        self.v3_create_token(project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Create inherited role
        inherited_role = unit.new_role_ref(name='inherited')
        PROVIDERS.role_api.create_role(inherited_role['id'], inherited_role)

        # Grant inherited role for user on domain
        inher_ud_link = self.build_role_assignment_link(
            domain_id=self.domain_id, user_id=user['id'],
            role_id=inherited_role['id'], inherited_to_projects=True)
        self.put(inher_ud_link)

        # Check the user can get both a domain and a project token
        self.v3_create_token(domain_auth_data)
        self.v3_create_token(project_auth_data)

        # Delete inherited grant
        self.delete(inher_ud_link)

        # Check the user can only get a domain token
        self.v3_create_token(domain_auth_data)
        self.v3_create_token(project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Delete non-inherited grant
        self.delete(non_inher_ud_link)

        # Check the user cannot get a domain token anymore
        self.v3_create_token(domain_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_get_token_from_inherited_group_domain_role_grants(self):
        # Create a new group and put a new user in it to
        # ensure that no grant is loaded from sample data
        user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )

        group = unit.new_group_ref(domain_id=self.domain['id'])
        group = PROVIDERS.identity_api.create_group(group)
        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        # Define domain and project authentication data
        domain_auth_data = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            domain_id=self.domain_id)
        project_auth_data = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            project_id=self.project_id)

        # Check the user cannot get a domain nor a project token
        self.v3_create_token(domain_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Grant non-inherited role for user on domain
        non_inher_gd_link = self.build_role_assignment_link(
            domain_id=self.domain_id, user_id=user['id'], role_id=self.role_id)
        self.put(non_inher_gd_link)

        # Check the user can get only a domain token
        self.v3_create_token(domain_auth_data)
        self.v3_create_token(project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Create inherited role
        inherited_role = unit.new_role_ref(name='inherited')
        PROVIDERS.role_api.create_role(inherited_role['id'], inherited_role)

        # Grant inherited role for user on domain
        inher_gd_link = self.build_role_assignment_link(
            domain_id=self.domain_id, user_id=user['id'],
            role_id=inherited_role['id'], inherited_to_projects=True)
        self.put(inher_gd_link)

        # Check the user can get both a domain and a project token
        self.v3_create_token(domain_auth_data)
        self.v3_create_token(project_auth_data)

        # Delete inherited grant
        self.delete(inher_gd_link)

        # Check the user can only get a domain token
        self.v3_create_token(domain_auth_data)
        self.v3_create_token(project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Delete non-inherited grant
        self.delete(non_inher_gd_link)

        # Check the user cannot get a domain token anymore
        self.v3_create_token(domain_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def _test_crud_inherited_and_direct_assignment_on_target(self, target_url):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            # Create a new role to avoid assignments loaded from sample data
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)

            # Define URLs
            direct_url = '%s/users/%s/roles/%s' % (
                target_url, self.user_id, role['id'])
            inherited_url = ('/OS-INHERIT/%s/inherited_to_projects' %
                             direct_url.lstrip('/'))

            # Create the direct assignment
            self.put(direct_url)
            # Check the direct assignment exists, but the inherited one does
            # not
            self.head(direct_url)
            self.head(inherited_url, expected_status=http.client.NOT_FOUND)

            # Now add the inherited assignment
            self.put(inherited_url)
            # Check both the direct and inherited assignment exist
            self.head(direct_url)
            self.head(inherited_url)

            # Delete indirect assignment
            self.delete(inherited_url)
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            # Check the direct assignment exists, but the inherited one does
            # not
            self.head(direct_url)
            self.head(inherited_url, expected_status=http.client.NOT_FOUND)

            # Now delete the inherited assignment
            self.delete(direct_url)
            # Check that none of them exist
            self.head(direct_url, expected_status=http.client.NOT_FOUND)
            self.head(inherited_url, expected_status=http.client.NOT_FOUND)

    def test_crud_inherited_and_direct_assignment_on_domains(self):
        self._test_crud_inherited_and_direct_assignment_on_target(
            '/domains/%s' % self.domain_id)

    def test_crud_inherited_and_direct_assignment_on_projects(self):
        self._test_crud_inherited_and_direct_assignment_on_target(
            '/projects/%s' % self.project_id)

    def test_crud_user_inherited_domain_role_grants(self):
        role_list = []
        for _ in range(2):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Create a non-inherited role as a spoiler
        PROVIDERS.assignment_api.create_grant(
            role_list[1]['id'], user_id=self.user['id'],
            domain_id=self.domain_id)

        base_collection_url = (
            '/OS-INHERIT/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.domain_id,
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s/inherited_to_projects' % {
            'collection_url': base_collection_url,
            'role_id': role_list[0]['id']}
        collection_url = base_collection_url + '/inherited_to_projects'

        self.put(member_url)

        # Check we can read it back
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=role_list[0],
                                         resource_url=collection_url)

        # Now delete and check its gone
        self.delete(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, expected_length=0,
                                         resource_url=collection_url)

    def test_list_role_assignments_for_inherited_domain_grants(self):
        """Call ``GET /role_assignments with inherited domain grants``.

        Test Plan:

        - Create 4 roles
        - Create a domain with a user and two projects
        - Assign two direct roles to project1
        - Assign a spoiler role to project2
        - Issue the URL to add inherited role to the domain
        - Issue the URL to check it is indeed on the domain
        - Issue the URL to check effective roles on project1 - this
          should return 3 roles.

        """
        role_list = []
        for _ in range(4):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user1 = unit.create_user(
            PROVIDERS.identity_api, domain_id=domain['id']
        )
        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        # Add some roles to the project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project1['id'], role_list[0]['id'])
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project1['id'], role_list[1]['id'])
        # ..and one on a different project as a spoiler
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project2['id'], role_list[2]['id'])

        # Now create our inherited role on the domain
        base_collection_url = (
            '/OS-INHERIT/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': domain['id'],
                'user_id': user1['id']})
        member_url = '%(collection_url)s/%(role_id)s/inherited_to_projects' % {
            'collection_url': base_collection_url,
            'role_id': role_list[3]['id']}
        collection_url = base_collection_url + '/inherited_to_projects'

        self.put(member_url)
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=role_list[3],
                                         resource_url=collection_url)

        # Now use the list domain role assignments api to check if this
        # is included
        collection_url = (
            '/role_assignments?user.id=%(user_id)s'
            '&scope.domain.id=%(domain_id)s' % {
                'user_id': user1['id'],
                'domain_id': domain['id']})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=1,
                                                   resource_url=collection_url)
        ud_entity = self.build_role_assignment_entity(
            domain_id=domain['id'], user_id=user1['id'],
            role_id=role_list[3]['id'], inherited_to_projects=True)
        self.assertRoleAssignmentInListResponse(r, ud_entity)

        # Now ask for effective list role assignments - the role should
        # turn into a project role, along with the two direct roles that are
        # on the project
        collection_url = (
            '/role_assignments?effective&user.id=%(user_id)s'
            '&scope.project.id=%(project_id)s' % {
                'user_id': user1['id'],
                'project_id': project1['id']})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=3,
                                                   resource_url=collection_url)
        # An effective role for an inherited role will be a project
        # entity, with a domain link to the inherited assignment
        ud_url = self.build_role_assignment_link(
            domain_id=domain['id'], user_id=user1['id'],
            role_id=role_list[3]['id'], inherited_to_projects=True)
        up_entity = self.build_role_assignment_entity(
            link=ud_url, project_id=project1['id'],
            user_id=user1['id'], role_id=role_list[3]['id'],
            inherited_to_projects=True)
        self.assertRoleAssignmentInListResponse(r, up_entity)

    def _test_list_role_assignments_include_names(self, role1):
        """Call ``GET /role_assignments with include names``.

        Test Plan:

        - Create a domain with a group and a user
        - Create a project with a group and a user

        """
        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)
        user1 = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        group = unit.new_group_ref(domain_id=self.domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        project1 = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project1['id'], project1)

        expected_entity1 = self.build_role_assignment_entity_include_names(
            role_ref=role1,
            project_ref=project1,
            user_ref=user1)
        self.put(expected_entity1['links']['assignment'])
        expected_entity2 = self.build_role_assignment_entity_include_names(
            role_ref=role1,
            domain_ref=self.domain,
            group_ref=group)
        self.put(expected_entity2['links']['assignment'])
        expected_entity3 = self.build_role_assignment_entity_include_names(
            role_ref=role1,
            domain_ref=self.domain,
            user_ref=user1)
        self.put(expected_entity3['links']['assignment'])
        expected_entity4 = self.build_role_assignment_entity_include_names(
            role_ref=role1,
            project_ref=project1,
            group_ref=group)
        self.put(expected_entity4['links']['assignment'])

        collection_url_domain = (
            '/role_assignments?include_names&scope.domain.id=%(domain_id)s' % {
                'domain_id': self.domain_id})
        rs_domain = self.get(collection_url_domain)
        collection_url_project = (
            '/role_assignments?include_names&'
            'scope.project.id=%(project_id)s' % {
                'project_id': project1['id']})
        rs_project = self.get(collection_url_project)
        collection_url_group = (
            '/role_assignments?include_names&group.id=%(group_id)s' % {
                'group_id': group['id']})
        rs_group = self.get(collection_url_group)
        collection_url_user = (
            '/role_assignments?include_names&user.id=%(user_id)s' % {
                'user_id': user1['id']})
        rs_user = self.get(collection_url_user)
        collection_url_role = (
            '/role_assignments?include_names&role.id=%(role_id)s' % {
                'role_id': role1['id']})
        rs_role = self.get(collection_url_role)
        # Make sure all entities were created successfully
        self.assertEqual(http.client.OK, rs_domain.status_int)
        self.assertEqual(http.client.OK, rs_project.status_int)
        self.assertEqual(http.client.OK, rs_group.status_int)
        self.assertEqual(http.client.OK, rs_user.status_int)
        # Make sure we can get back the correct number of entities
        self.assertValidRoleAssignmentListResponse(
            rs_domain,
            expected_length=2,
            resource_url=collection_url_domain)
        self.assertValidRoleAssignmentListResponse(
            rs_project,
            expected_length=2,
            resource_url=collection_url_project)
        self.assertValidRoleAssignmentListResponse(
            rs_group,
            expected_length=2,
            resource_url=collection_url_group)
        self.assertValidRoleAssignmentListResponse(
            rs_user,
            expected_length=2,
            resource_url=collection_url_user)
        self.assertValidRoleAssignmentListResponse(
            rs_role,
            expected_length=4,
            resource_url=collection_url_role)
        # Verify all types of entities have the correct format
        self.assertRoleAssignmentInListResponse(rs_domain, expected_entity2)
        self.assertRoleAssignmentInListResponse(rs_project, expected_entity1)
        self.assertRoleAssignmentInListResponse(rs_group, expected_entity4)
        self.assertRoleAssignmentInListResponse(rs_user, expected_entity3)
        self.assertRoleAssignmentInListResponse(rs_role, expected_entity1)

    def test_list_role_assignments_include_names_global_role(self):
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        self._test_list_role_assignments_include_names(role)

    def test_list_role_assignments_include_names_domain_role(self):
        role = unit.new_role_ref(domain_id=self.domain['id'])
        PROVIDERS.role_api.create_role(role['id'], role)

        self._test_list_role_assignments_include_names(role)

    def test_remove_assignment_for_project_acting_as_domain(self):
        """Test goal: remove assignment for project acting as domain.

        Ensure when we have two role assignments for the project
        acting as domain, one dealing with it as a domain and other as a
        project, we still able to remove those assignments later.

        Test plan:
        - Create a role and a domain with a user;
        - Grant a role for this user in this domain;
        - Grant a role for this user in the same entity as a project;
        - Ensure that both assignments were created and it was valid;
        - Remove the domain assignment for the user and show that the project
        assignment for him still valid

        """
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user = unit.create_user(PROVIDERS.identity_api, domain_id=domain['id'])

        assignment_domain = self.build_role_assignment_entity(
            role_id=role['id'], domain_id=domain['id'], user_id=user['id'],
            inherited_to_projects=False)
        assignment_project = self.build_role_assignment_entity(
            role_id=role['id'], project_id=domain['id'], user_id=user['id'],
            inherited_to_projects=False)

        self.put(assignment_domain['links']['assignment'])
        self.put(assignment_project['links']['assignment'])

        collection_url = '/role_assignments?user.id=%(user_id)s' % (
                         {'user_id': user['id']})
        result = self.get(collection_url)
        # We have two role assignments based in both roles for the domain and
        # project scope
        self.assertValidRoleAssignmentListResponse(
            result, expected_length=2, resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(result, assignment_domain)

        domain_url = '/domains/%s/users/%s/roles/%s' % (
            domain['id'], user['id'], role['id'])
        self.delete(domain_url)

        collection_url = '/role_assignments?user.id=%(user_id)s' % (
                         {'user_id': user['id']})
        result = self.get(collection_url)
        # Now we only have one assignment for the project scope since the
        # domain scope was removed.
        self.assertValidRoleAssignmentListResponse(
            result, expected_length=1, resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(result, assignment_project)

    def test_list_inherited_role_assignments_include_names(self):
        """Call ``GET /role_assignments?include_names``.

        Test goal: ensure calling list role assignments including names
        honors the inherited role assignments flag.

        Test plan:
        - Create a role and a domain with a user;
        - Create a inherited role assignment;
        - List role assignments for that user;
        - List role assignments for that user including names.

        """
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user = unit.create_user(PROVIDERS.identity_api, domain_id=domain['id'])

        # Create and store expected assignment refs
        assignment = self.build_role_assignment_entity(
            role_id=role['id'], domain_id=domain['id'], user_id=user['id'],
            inherited_to_projects=True)
        assignment_names = self.build_role_assignment_entity_include_names(
            role_ref=role, domain_ref=domain, user_ref=user,
            inherited_assignment=True)

        # Ensure expected assignment refs are inherited and have the same URL
        self.assertEqual('projects',
                         assignment['scope']['OS-INHERIT:inherited_to'])
        self.assertEqual('projects',
                         assignment_names['scope']['OS-INHERIT:inherited_to'])
        self.assertEqual(assignment['links']['assignment'],
                         assignment_names['links']['assignment'])

        self.put(assignment['links']['assignment'])

        collection_url = '/role_assignments?user.id=%(user_id)s' % (
                         {'user_id': user['id']})
        result = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            result, expected_length=1, resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(result, assignment)

        collection_url = ('/role_assignments?include_names&'
                          'user.id=%(user_id)s' % {'user_id': user['id']})
        result = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            result, expected_length=1, resource_url=collection_url)
        self.assertRoleAssignmentInListResponse(result, assignment_names)

    def test_list_role_assignments_for_disabled_inheritance_extension(self):
        """Call ``GET /role_assignments with inherited domain grants``.

        Test Plan:

        - Issue the URL to add inherited role to the domain
        - Issue the URL to check effective roles on project include the
          inherited role
        - Disable the extension
        - Re-check the effective roles, proving the inherited role no longer
          shows up.

        """
        role_list = []
        for _ in range(4):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user1 = unit.create_user(
            PROVIDERS.identity_api, domain_id=domain['id']
        )
        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        # Add some roles to the project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project1['id'], role_list[0]['id'])
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project1['id'], role_list[1]['id'])
        # ..and one on a different project as a spoiler
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project2['id'], role_list[2]['id'])

        # Now create our inherited role on the domain
        base_collection_url = (
            '/OS-INHERIT/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': domain['id'],
                'user_id': user1['id']})
        member_url = '%(collection_url)s/%(role_id)s/inherited_to_projects' % {
            'collection_url': base_collection_url,
            'role_id': role_list[3]['id']}
        collection_url = base_collection_url + '/inherited_to_projects'

        self.put(member_url)
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=role_list[3],
                                         resource_url=collection_url)

        # Get effective list role assignments - the role should
        # turn into a project role, along with the two direct roles that are
        # on the project
        collection_url = (
            '/role_assignments?effective&user.id=%(user_id)s'
            '&scope.project.id=%(project_id)s' % {
                'user_id': user1['id'],
                'project_id': project1['id']})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=3,
                                                   resource_url=collection_url)

        ud_url = self.build_role_assignment_link(
            domain_id=domain['id'], user_id=user1['id'],
            role_id=role_list[3]['id'], inherited_to_projects=True)
        up_entity = self.build_role_assignment_entity(
            link=ud_url, project_id=project1['id'],
            user_id=user1['id'], role_id=role_list[3]['id'],
            inherited_to_projects=True)

        self.assertRoleAssignmentInListResponse(r, up_entity)

    def test_list_role_assignments_for_inherited_group_domain_grants(self):
        """Call ``GET /role_assignments with inherited group domain grants``.

        Test Plan:

        - Create 4 roles
        - Create a domain with a user and two projects
        - Assign two direct roles to project1
        - Assign a spoiler role to project2
        - Issue the URL to add inherited role to the domain
        - Issue the URL to check it is indeed on the domain
        - Issue the URL to check effective roles on project1 - this
          should return 3 roles.

        """
        role_list = []
        for _ in range(4):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user1 = unit.create_user(
            PROVIDERS.identity_api, domain_id=domain['id']
        )
        user2 = unit.create_user(
            PROVIDERS.identity_api, domain_id=domain['id']
        )
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user2['id'], group1['id']
        )
        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        # Add some roles to the project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project1['id'], role_list[0]['id'])
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project1['id'], role_list[1]['id'])
        # ..and one on a different project as a spoiler
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project2['id'], role_list[2]['id'])

        # Now create our inherited role on the domain
        base_collection_url = (
            '/OS-INHERIT/domains/%(domain_id)s/groups/%(group_id)s/roles' % {
                'domain_id': domain['id'],
                'group_id': group1['id']})
        member_url = '%(collection_url)s/%(role_id)s/inherited_to_projects' % {
            'collection_url': base_collection_url,
            'role_id': role_list[3]['id']}
        collection_url = base_collection_url + '/inherited_to_projects'

        self.put(member_url)
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=role_list[3],
                                         resource_url=collection_url)

        # Now use the list domain role assignments api to check if this
        # is included
        collection_url = (
            '/role_assignments?group.id=%(group_id)s'
            '&scope.domain.id=%(domain_id)s' % {
                'group_id': group1['id'],
                'domain_id': domain['id']})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=1,
                                                   resource_url=collection_url)
        gd_entity = self.build_role_assignment_entity(
            domain_id=domain['id'], group_id=group1['id'],
            role_id=role_list[3]['id'], inherited_to_projects=True)
        self.assertRoleAssignmentInListResponse(r, gd_entity)

        # Now ask for effective list role assignments - the role should
        # turn into a user project role, along with the two direct roles
        # that are on the project
        collection_url = (
            '/role_assignments?effective&user.id=%(user_id)s'
            '&scope.project.id=%(project_id)s' % {
                'user_id': user1['id'],
                'project_id': project1['id']})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=3,
                                                   resource_url=collection_url)
        # An effective role for an inherited role will be a project
        # entity, with a domain link to the inherited assignment
        up_entity = self.build_role_assignment_entity(
            link=gd_entity['links']['assignment'], project_id=project1['id'],
            user_id=user1['id'], role_id=role_list[3]['id'],
            inherited_to_projects=True)
        self.assertRoleAssignmentInListResponse(r, up_entity)

    def test_filtered_role_assignments_for_inherited_grants(self):
        """Call ``GET /role_assignments?scope.OS-INHERIT:inherited_to``.

        Test Plan:

        - Create 5 roles
        - Create a domain with a user, group and two projects
        - Assign three direct spoiler roles to projects
        - Issue the URL to add an inherited user role to the domain
        - Issue the URL to add an inherited group role to the domain
        - Issue the URL to filter by inherited roles - this should
          return just the 2 inherited roles.

        """
        role_list = []
        for _ in range(5):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user1 = unit.create_user(
            PROVIDERS.identity_api, domain_id=domain['id']
        )
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        # Add some spoiler roles to the projects
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project1['id'], role_list[0]['id'])
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user1['id'], project2['id'], role_list[1]['id'])
        # Create a non-inherited role as a spoiler
        PROVIDERS.assignment_api.create_grant(
            role_list[2]['id'], user_id=user1['id'], domain_id=domain['id'])

        # Now create two inherited roles on the domain, one for a user
        # and one for a domain
        base_collection_url = (
            '/OS-INHERIT/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': domain['id'],
                'user_id': user1['id']})
        member_url = '%(collection_url)s/%(role_id)s/inherited_to_projects' % {
            'collection_url': base_collection_url,
            'role_id': role_list[3]['id']}
        collection_url = base_collection_url + '/inherited_to_projects'

        self.put(member_url)
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=role_list[3],
                                         resource_url=collection_url)

        base_collection_url = (
            '/OS-INHERIT/domains/%(domain_id)s/groups/%(group_id)s/roles' % {
                'domain_id': domain['id'],
                'group_id': group1['id']})
        member_url = '%(collection_url)s/%(role_id)s/inherited_to_projects' % {
            'collection_url': base_collection_url,
            'role_id': role_list[4]['id']}
        collection_url = base_collection_url + '/inherited_to_projects'

        self.put(member_url)
        self.head(member_url)
        self.get(member_url, expected_status=http.client.NO_CONTENT)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=role_list[4],
                                         resource_url=collection_url)

        # Now use the list role assignments api to get a list of inherited
        # roles on the domain - should get back the two roles
        collection_url = (
            '/role_assignments?scope.OS-INHERIT:inherited_to=projects')
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   expected_length=2,
                                                   resource_url=collection_url)
        ud_entity = self.build_role_assignment_entity(
            domain_id=domain['id'], user_id=user1['id'],
            role_id=role_list[3]['id'], inherited_to_projects=True)
        gd_entity = self.build_role_assignment_entity(
            domain_id=domain['id'], group_id=group1['id'],
            role_id=role_list[4]['id'], inherited_to_projects=True)
        self.assertRoleAssignmentInListResponse(r, ud_entity)
        self.assertRoleAssignmentInListResponse(r, gd_entity)

    def _setup_hierarchical_projects_scenario(self):
        """Create basic hierarchical projects scenario.

        This basic scenario contains a root with one leaf project and
        two roles with the following names: non-inherited and inherited.

        """
        # Create project hierarchy
        root = unit.new_project_ref(domain_id=self.domain['id'])
        leaf = unit.new_project_ref(domain_id=self.domain['id'],
                                    parent_id=root['id'])

        PROVIDERS.resource_api.create_project(root['id'], root)
        PROVIDERS.resource_api.create_project(leaf['id'], leaf)

        # Create 'non-inherited' and 'inherited' roles
        non_inherited_role = unit.new_role_ref(name='non-inherited')
        PROVIDERS.role_api.create_role(
            non_inherited_role['id'], non_inherited_role
        )
        inherited_role = unit.new_role_ref(name='inherited')
        PROVIDERS.role_api.create_role(inherited_role['id'], inherited_role)

        return (root['id'], leaf['id'],
                non_inherited_role['id'], inherited_role['id'])

    def test_get_token_from_inherited_user_project_role_grants(self):
        # Create default scenario
        root_id, leaf_id, non_inherited_role_id, inherited_role_id = (
            self._setup_hierarchical_projects_scenario())

        # Define root and leaf projects authentication data
        root_project_auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=root_id)
        leaf_project_auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=leaf_id)

        # Check the user cannot get a token on root nor leaf project
        self.v3_create_token(root_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(leaf_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Grant non-inherited role for user on leaf project
        non_inher_up_link = self.build_role_assignment_link(
            project_id=leaf_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_up_link)

        # Check the user can only get a token on leaf project
        self.v3_create_token(root_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(leaf_project_auth_data)

        # Grant inherited role for user on root project
        inher_up_link = self.build_role_assignment_link(
            project_id=root_id, user_id=self.user['id'],
            role_id=inherited_role_id, inherited_to_projects=True)
        self.put(inher_up_link)

        # Check the user still can get a token only on leaf project
        self.v3_create_token(root_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(leaf_project_auth_data)

        # Delete non-inherited grant
        self.delete(non_inher_up_link)

        # Check the inherited role still applies for leaf project
        self.v3_create_token(root_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(leaf_project_auth_data)

        # Delete inherited grant
        self.delete(inher_up_link)

        # Check the user cannot get a token on leaf project anymore
        self.v3_create_token(leaf_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_get_token_from_inherited_group_project_role_grants(self):
        # Create default scenario
        root_id, leaf_id, non_inherited_role_id, inherited_role_id = (
            self._setup_hierarchical_projects_scenario())

        # Create group and add user to it
        group = unit.new_group_ref(domain_id=self.domain['id'])
        group = PROVIDERS.identity_api.create_group(group)
        PROVIDERS.identity_api.add_user_to_group(self.user['id'], group['id'])

        # Define root and leaf projects authentication data
        root_project_auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=root_id)
        leaf_project_auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=leaf_id)

        # Check the user cannot get a token on root nor leaf project
        self.v3_create_token(root_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(leaf_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # Grant non-inherited role for group on leaf project
        non_inher_gp_link = self.build_role_assignment_link(
            project_id=leaf_id, group_id=group['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_gp_link)

        # Check the user can only get a token on leaf project
        self.v3_create_token(root_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(leaf_project_auth_data)

        # Grant inherited role for group on root project
        inher_gp_link = self.build_role_assignment_link(
            project_id=root_id, group_id=group['id'],
            role_id=inherited_role_id, inherited_to_projects=True)
        self.put(inher_gp_link)

        # Check the user still can get a token only on leaf project
        self.v3_create_token(root_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)
        self.v3_create_token(leaf_project_auth_data)

        # Delete no-inherited grant
        self.delete(non_inher_gp_link)

        # Check the inherited role still applies for leaf project
        self.v3_create_token(leaf_project_auth_data)

        # Delete inherited grant
        self.delete(inher_gp_link)

        # Check the user cannot get a token on leaf project anymore
        self.v3_create_token(leaf_project_auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_get_role_assignments_for_project_hierarchy(self):
        """Call ``GET /role_assignments``.

        Test Plan:

        - Create 2 roles
        - Create a hierarchy of projects with one root and one leaf project
        - Issue the URL to add a non-inherited user role to the root project
        - Issue the URL to add an inherited user role to the root project
        - Issue the URL to get all role assignments - this should return just
          2 roles (non-inherited and inherited) in the root project.

        """
        # Create default scenario
        root_id, leaf_id, non_inherited_role_id, inherited_role_id = (
            self._setup_hierarchical_projects_scenario())

        # Grant non-inherited role
        non_inher_up_entity = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_up_entity['links']['assignment'])

        # Grant inherited role
        inher_up_entity = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=inherited_role_id, inherited_to_projects=True)
        self.put(inher_up_entity['links']['assignment'])

        # Get role assignments
        collection_url = '/role_assignments'
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   resource_url=collection_url)

        # Assert that the user has non-inherited role on root project
        self.assertRoleAssignmentInListResponse(r, non_inher_up_entity)

        # Assert that the user has inherited role on root project
        self.assertRoleAssignmentInListResponse(r, inher_up_entity)

        # Assert that the user does not have non-inherited role on leaf project
        non_inher_up_entity = self.build_role_assignment_entity(
            project_id=leaf_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.assertRoleAssignmentNotInListResponse(r, non_inher_up_entity)

        # Assert that the user does not have inherited role on leaf project
        inher_up_entity['scope']['project']['id'] = leaf_id
        self.assertRoleAssignmentNotInListResponse(r, inher_up_entity)

    def test_get_effective_role_assignments_for_project_hierarchy(self):
        """Call ``GET /role_assignments?effective``.

        Test Plan:

        - Create 2 roles
        - Create a hierarchy of projects with one root and one leaf project
        - Issue the URL to add a non-inherited user role to the root project
        - Issue the URL to add an inherited user role to the root project
        - Issue the URL to get effective role assignments - this should return
          1 role (non-inherited) on the root project and 1 role (inherited) on
          the leaf project.

        """
        # Create default scenario
        root_id, leaf_id, non_inherited_role_id, inherited_role_id = (
            self._setup_hierarchical_projects_scenario())

        # Grant non-inherited role
        non_inher_up_entity = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_up_entity['links']['assignment'])

        # Grant inherited role
        inher_up_entity = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=inherited_role_id, inherited_to_projects=True)
        self.put(inher_up_entity['links']['assignment'])

        # Get effective role assignments
        collection_url = '/role_assignments?effective'
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   resource_url=collection_url)

        # Assert that the user has non-inherited role on root project
        self.assertRoleAssignmentInListResponse(r, non_inher_up_entity)

        # Assert that the user does not have inherited role on root project
        self.assertRoleAssignmentNotInListResponse(r, inher_up_entity)

        # Assert that the user does not have non-inherited role on leaf project
        non_inher_up_entity = self.build_role_assignment_entity(
            project_id=leaf_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.assertRoleAssignmentNotInListResponse(r, non_inher_up_entity)

        # Assert that the user has inherited role on leaf project
        inher_up_entity['scope']['project']['id'] = leaf_id
        self.assertRoleAssignmentInListResponse(r, inher_up_entity)

    def test_project_id_specified_if_include_subtree_specified(self):
        """When using include_subtree, you must specify a project ID."""
        r = self.get('/role_assignments?include_subtree=True',
                     expected_status=http.client.BAD_REQUEST)
        error_msg = ("scope.project.id must be specified if include_subtree "
                     "is also specified")
        self.assertEqual(error_msg, r.result['error']['message'])
        r = self.get('/role_assignments?scope.project.id&'
                     'include_subtree=True',
                     expected_status=http.client.BAD_REQUEST)
        self.assertEqual(error_msg, r.result['error']['message'])

    def test_get_role_assignments_for_project_tree(self):
        """Get role_assignment?scope.project.id=X&include_subtree``.

        Test Plan:

        - Create 2 roles and a hierarchy of projects with one root and one leaf
        - Issue the URL to add a non-inherited user role to the root project
          and the leaf project
        - Issue the URL to get role assignments for the root project but
          not the subtree - this should return just the root assignment
        - Issue the URL to get role assignments for the root project and
          it's subtree - this should return both assignments
        - Check that explicitly setting include_subtree to False is the
          equivalent to not including it at all in the query.

        """
        # Create default scenario
        root_id, leaf_id, non_inherited_role_id, unused_role_id = (
            self._setup_hierarchical_projects_scenario())

        # Grant non-inherited role to root and leaf projects
        non_inher_entity_root = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_entity_root['links']['assignment'])
        non_inher_entity_leaf = self.build_role_assignment_entity(
            project_id=leaf_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_entity_leaf['links']['assignment'])

        # Without the subtree, we should get the one assignment on the
        # root project
        collection_url = (
            '/role_assignments?scope.project.id=%(project)s' % {
                'project': root_id})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            r, resource_url=collection_url)

        self.assertThat(r.result['role_assignments'], matchers.HasLength(1))
        self.assertRoleAssignmentInListResponse(r, non_inher_entity_root)

        # With the subtree, we should get both assignments
        collection_url = (
            '/role_assignments?scope.project.id=%(project)s'
            '&include_subtree=True' % {
                'project': root_id})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            r, resource_url=collection_url)

        self.assertThat(r.result['role_assignments'], matchers.HasLength(2))
        self.assertRoleAssignmentInListResponse(r, non_inher_entity_root)
        self.assertRoleAssignmentInListResponse(r, non_inher_entity_leaf)

        # With subtree=0, we should also only get the one assignment on the
        # root project
        collection_url = (
            '/role_assignments?scope.project.id=%(project)s'
            '&include_subtree=0' % {
                'project': root_id})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            r, resource_url=collection_url)

        self.assertThat(r.result['role_assignments'], matchers.HasLength(1))
        self.assertRoleAssignmentInListResponse(r, non_inher_entity_root)

    def test_get_effective_role_assignments_for_project_tree(self):
        """Get role_assignment ?project_id=X&include_subtree=True&effective``.

        Test Plan:

        - Create 2 roles and a hierarchy of projects with one root and 4 levels
          of child project
        - Issue the URL to add a non-inherited user role to the root project
          and a level 1 project
        - Issue the URL to add an inherited user role on the level 2 project
        - Issue the URL to get effective role assignments for the level 1
          project and it's subtree - this should return a role (non-inherited)
          on the level 1 project and roles (inherited) on each of the level
          2, 3 and 4 projects

        """
        # Create default scenario
        root_id, leaf_id, non_inherited_role_id, inherited_role_id = (
            self._setup_hierarchical_projects_scenario())

        # Add some extra projects to the project hierarchy
        level2 = unit.new_project_ref(domain_id=self.domain['id'],
                                      parent_id=leaf_id)
        level3 = unit.new_project_ref(domain_id=self.domain['id'],
                                      parent_id=level2['id'])
        level4 = unit.new_project_ref(domain_id=self.domain['id'],
                                      parent_id=level3['id'])
        PROVIDERS.resource_api.create_project(level2['id'], level2)
        PROVIDERS.resource_api.create_project(level3['id'], level3)
        PROVIDERS.resource_api.create_project(level4['id'], level4)

        # Grant non-inherited role to root (as a spoiler) and to
        # the level 1 (leaf) project
        non_inher_entity_root = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_entity_root['links']['assignment'])
        non_inher_entity_leaf = self.build_role_assignment_entity(
            project_id=leaf_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_entity_leaf['links']['assignment'])

        # Grant inherited role to level 2
        inher_entity = self.build_role_assignment_entity(
            project_id=level2['id'], user_id=self.user['id'],
            role_id=inherited_role_id, inherited_to_projects=True)
        self.put(inher_entity['links']['assignment'])

        # Get effective role assignments
        collection_url = (
            '/role_assignments?scope.project.id=%(project)s'
            '&include_subtree=True&effective' % {
                'project': leaf_id})
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(
            r, resource_url=collection_url)

        # There should be three assignments returned in total
        self.assertThat(r.result['role_assignments'], matchers.HasLength(3))

        # Assert that the user does not non-inherited role on root project
        self.assertRoleAssignmentNotInListResponse(r, non_inher_entity_root)

        # Assert that the user does have non-inherited role on leaf project
        self.assertRoleAssignmentInListResponse(r, non_inher_entity_leaf)

        # Assert that the user has inherited role on levels 3 and 4
        inher_entity['scope']['project']['id'] = level3['id']
        self.assertRoleAssignmentInListResponse(r, inher_entity)
        inher_entity['scope']['project']['id'] = level4['id']
        self.assertRoleAssignmentInListResponse(r, inher_entity)

    def test_get_inherited_role_assignments_for_project_hierarchy(self):
        """Call ``GET /role_assignments?scope.OS-INHERIT:inherited_to``.

        Test Plan:

        - Create 2 roles
        - Create a hierarchy of projects with one root and one leaf project
        - Issue the URL to add a non-inherited user role to the root project
        - Issue the URL to add an inherited user role to the root project
        - Issue the URL to filter inherited to projects role assignments - this
          should return 1 role (inherited) on the root project.

        """
        # Create default scenario
        root_id, leaf_id, non_inherited_role_id, inherited_role_id = (
            self._setup_hierarchical_projects_scenario())

        # Grant non-inherited role
        non_inher_up_entity = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.put(non_inher_up_entity['links']['assignment'])

        # Grant inherited role
        inher_up_entity = self.build_role_assignment_entity(
            project_id=root_id, user_id=self.user['id'],
            role_id=inherited_role_id, inherited_to_projects=True)
        self.put(inher_up_entity['links']['assignment'])

        # Get inherited role assignments
        collection_url = ('/role_assignments'
                          '?scope.OS-INHERIT:inherited_to=projects')
        r = self.get(collection_url)
        self.assertValidRoleAssignmentListResponse(r,
                                                   resource_url=collection_url)

        # Assert that the user does not have non-inherited role on root project
        self.assertRoleAssignmentNotInListResponse(r, non_inher_up_entity)

        # Assert that the user has inherited role on root project
        self.assertRoleAssignmentInListResponse(r, inher_up_entity)

        # Assert that the user does not have non-inherited role on leaf project
        non_inher_up_entity = self.build_role_assignment_entity(
            project_id=leaf_id, user_id=self.user['id'],
            role_id=non_inherited_role_id)
        self.assertRoleAssignmentNotInListResponse(r, non_inher_up_entity)

        # Assert that the user does not have inherited role on leaf project
        inher_up_entity['scope']['project']['id'] = leaf_id
        self.assertRoleAssignmentNotInListResponse(r, inher_up_entity)


class ImpliedRolesTests(test_v3.RestfulTestCase, test_v3.AssignmentTestMixin,
                        unit.TestCase):
    def _create_role(self):
        """Call ``POST /roles``."""
        ref = unit.new_role_ref()
        r = self.post('/roles', body={'role': ref})
        return self.assertValidRoleResponse(r, ref)

    def test_list_implied_roles_none(self):
        self.prior = self._create_role()
        url = '/roles/%s/implies' % (self.prior['id'])
        response = self.get(url).json["role_inference"]
        self.head(url, expected_status=http.client.OK)
        self.assertEqual(self.prior['id'], response['prior_role']['id'])
        self.assertEqual(0, len(response['implies']))

    def _create_implied_role(self, prior, implied):
        self.put('/roles/%s/implies/%s' % (prior['id'], implied['id']),
                 expected_status=http.client.CREATED)

    def _delete_implied_role(self, prior, implied):
        self.delete('/roles/%s/implies/%s' % (prior['id'], implied['id']))

    def _setup_prior_two_implied(self):
        self.prior = self._create_role()
        self.implied1 = self._create_role()
        self._create_implied_role(self.prior, self.implied1)
        self.implied2 = self._create_role()
        self._create_implied_role(self.prior, self.implied2)

    def _assert_expected_implied_role_response(
            self, expected_prior_id, expected_implied_ids):
        r = self.get('/roles/%s/implies' % expected_prior_id)
        response = r.json
        role_inference = response['role_inference']
        self.assertEqual(expected_prior_id, role_inference['prior_role']['id'])
        prior_link = '/v3/roles/' + expected_prior_id + '/implies'
        self.assertThat(response['links']['self'],
                        matchers.EndsWith(prior_link))

        actual_implied_ids = [implied['id']
                              for implied in role_inference['implies']]

        self.assertCountEqual(expected_implied_ids, actual_implied_ids)

        self.assertIsNotNone(role_inference['prior_role']['links']['self'])
        for implied in role_inference['implies']:
            self.assertIsNotNone(implied['links']['self'])

    def _assert_expected_role_inference_rule_response(
            self, expected_prior_id, expected_implied_id):
        url = '/roles/%s/implies/%s' % (expected_prior_id, expected_implied_id)
        response = self.get(url).json
        self.assertThat(response['links']['self'],
                        matchers.EndsWith('/v3%s' % url))
        role_inference = response['role_inference']
        prior_role = role_inference['prior_role']
        self.assertEqual(expected_prior_id, prior_role['id'])
        self.assertIsNotNone(prior_role['name'])
        self.assertThat(prior_role['links']['self'],
                        matchers.EndsWith('/v3/roles/%s' % expected_prior_id))
        implied_role = role_inference['implies']
        self.assertEqual(expected_implied_id, implied_role['id'])
        self.assertIsNotNone(implied_role['name'])
        self.assertThat(implied_role['links']['self'], matchers.EndsWith(
            '/v3/roles/%s' % expected_implied_id))

    def _assert_two_roles_implied(self):
        self._assert_expected_implied_role_response(
            self.prior['id'], [self.implied1['id'], self.implied2['id']])
        self._assert_expected_role_inference_rule_response(
            self.prior['id'], self.implied1['id'])
        self._assert_expected_role_inference_rule_response(
            self.prior['id'], self.implied2['id'])

    def _assert_one_role_implied(self):
        self._assert_expected_implied_role_response(
            self.prior['id'], [self.implied1['id']])

        self.get('/roles/%s/implies/%s' %
                 (self.prior['id'], self.implied2['id']),
                 expected_status=http.client.NOT_FOUND)

    def _assert_two_rules_defined(self):
        r = self.get('/role_inferences/')

        rules = r.result['role_inferences']

        self.assertEqual(self.prior['id'], rules[0]['prior_role']['id'])
        self.assertEqual(2, len(rules[0]['implies']))
        implied_ids = [implied['id'] for implied in rules[0]['implies']]
        implied_names = [implied['name'] for implied in rules[0]['implies']]

        self.assertIn(self.implied1['id'], implied_ids)
        self.assertIn(self.implied2['id'], implied_ids)
        self.assertIn(self.implied1['name'], implied_names)
        self.assertIn(self.implied2['name'], implied_names)

    def _assert_one_rule_defined(self):
        r = self.get('/role_inferences/')
        rules = r.result['role_inferences']
        self.assertEqual(self.prior['id'], rules[0]['prior_role']['id'])
        self.assertEqual(self.implied1['id'], rules[0]['implies'][0]['id'])
        self.assertEqual(self.implied1['name'], rules[0]['implies'][0]['name'])
        self.assertEqual(1, len(rules[0]['implies']))

    def test_list_all_rules(self):
        self._setup_prior_two_implied()
        self._assert_two_rules_defined()

        self._delete_implied_role(self.prior, self.implied2)
        self._assert_one_rule_defined()

    def test_CRD_implied_roles(self):

        self._setup_prior_two_implied()
        self._assert_two_roles_implied()

        self._delete_implied_role(self.prior, self.implied2)
        self._assert_one_role_implied()

    def _create_three_roles(self):
        self.role_list = []
        for _ in range(3):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            self.role_list.append(role)

    def _create_test_domain_user_project(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user = unit.create_user(PROVIDERS.identity_api, domain_id=domain['id'])
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)
        return domain, user, project

    def _assign_top_role_to_user_on_project(self, user, project):
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'], project['id'], self.role_list[0]['id'])

    def _build_effective_role_assignments_url(self, user):
        return '/role_assignments?effective&user.id=%(user_id)s' % {
            'user_id': user['id']}

    def _assert_all_roles_in_assignment(self, response, user):
        # Now use the list role assignments api to check that all three roles
        # appear in the collection
        self.assertValidRoleAssignmentListResponse(
            response,
            expected_length=len(self.role_list),
            resource_url=self._build_effective_role_assignments_url(user))

    def _assert_initial_assignment_in_effective(self, response, user, project):
        # The initial assignment should be there (the link url will be
        # generated and checked automatically since it matches the assignment)
        entity = self.build_role_assignment_entity(
            project_id=project['id'],
            user_id=user['id'], role_id=self.role_list[0]['id'])
        self.assertRoleAssignmentInListResponse(response, entity)

    def _assert_effective_role_for_implied_has_prior_in_links(
            self, response, user, project, prior_index, implied_index):
        # An effective role for an implied role will have the prior role
        # assignment in the links
        prior_link = '/prior_roles/%(prior)s/implies/%(implied)s' % {
            'prior': self.role_list[prior_index]['id'],
            'implied': self.role_list[implied_index]['id']}
        link = self.build_role_assignment_link(
            project_id=project['id'], user_id=user['id'],
            role_id=self.role_list[prior_index]['id'])
        entity = self.build_role_assignment_entity(
            link=link, project_id=project['id'],
            user_id=user['id'], role_id=self.role_list[implied_index]['id'],
            prior_link=prior_link)
        self.assertRoleAssignmentInListResponse(response, entity)

    def test_list_role_assignments_with_implied_roles(self):
        """Call ``GET /role_assignments`` with implied role grant.

        Test Plan:

        - Create a domain with a user and a project
        - Create 3 roles
        - Role 0 implies role 1 and role 1 implies role 2
        - Assign the top role to the project
        - Issue the URL to check effective roles on project - this
          should return all 3 roles.
        - Check the links of the 3 roles indicate the prior role where
          appropriate

        """
        (domain, user, project) = self._create_test_domain_user_project()
        self._create_three_roles()
        self._create_implied_role(self.role_list[0], self.role_list[1])
        self._create_implied_role(self.role_list[1], self.role_list[2])
        self._assign_top_role_to_user_on_project(user, project)

        response = self.get(self._build_effective_role_assignments_url(user))
        r = response

        self._assert_all_roles_in_assignment(r, user)
        self._assert_initial_assignment_in_effective(response, user, project)
        self._assert_effective_role_for_implied_has_prior_in_links(
            response, user, project, 0, 1)
        self._assert_effective_role_for_implied_has_prior_in_links(
            response, user, project, 1, 2)

    def _create_named_role(self, name):
        role = unit.new_role_ref()
        role['name'] = name
        PROVIDERS.role_api.create_role(role['id'], role)
        return role

    def test_root_role_as_implied_role_forbidden(self):
        """Test root role is forbidden to be set as an implied role.

        Create 2 roles that are prohibited from being an implied role.
        Create 1 additional role which should be accepted as an implied
        role. Assure the prohibited role names cannot be set as an implied
        role. Assure the accepted role name which is not a member of the
        prohibited implied role list can be successfully set an implied
        role.
        """
        prohibited_name1 = 'root1'
        prohibited_name2 = 'root2'
        accepted_name1 = 'implied1'

        prohibited_names = [prohibited_name1, prohibited_name2]
        self.config_fixture.config(group='assignment',
                                   prohibited_implied_role=prohibited_names)

        prior_role = self._create_role()

        prohibited_role1 = self._create_named_role(prohibited_name1)
        url = '/roles/{prior_role_id}/implies/{implied_role_id}'.format(
            prior_role_id=prior_role['id'],
            implied_role_id=prohibited_role1['id'])
        self.put(url, expected_status=http.client.FORBIDDEN)

        prohibited_role2 = self._create_named_role(prohibited_name2)
        url = '/roles/{prior_role_id}/implies/{implied_role_id}'.format(
            prior_role_id=prior_role['id'],
            implied_role_id=prohibited_role2['id'])
        self.put(url, expected_status=http.client.FORBIDDEN)

        accepted_role1 = self._create_named_role(accepted_name1)
        url = '/roles/{prior_role_id}/implies/{implied_role_id}'.format(
            prior_role_id=prior_role['id'],
            implied_role_id=accepted_role1['id'])
        self.put(url, expected_status=http.client.CREATED)

    def test_trusts_from_implied_role(self):
        self._create_three_roles()
        self._create_implied_role(self.role_list[0], self.role_list[1])
        self._create_implied_role(self.role_list[1], self.role_list[2])
        self._assign_top_role_to_user_on_project(self.user, self.project)

        # Create a trustee and assign the prior role to her
        trustee = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        ref = unit.new_trust_ref(
            trustor_user_id=self.user['id'],
            trustee_user_id=trustee['id'],
            project_id=self.project['id'],
            role_ids=[self.role_list[0]['id']])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = r.result['trust']

        # Only the role that was specified is in the trust, NOT implied roles
        self.assertEqual(self.role_list[0]['id'], trust['roles'][0]['id'])
        self.assertThat(trust['roles'], matchers.HasLength(1))

        # Authenticate as the trustee
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        token = r.result['token']
        self.assertThat(token['roles'],
                        matchers.HasLength(len(self.role_list)))
        for role in token['roles']:
            self.assertIn(role, self.role_list)
        for role in self.role_list:
            self.assertIn(role, token['roles'])

    def test_trusts_from_domain_specific_implied_role(self):
        self._create_three_roles()
        # Overwrite the first role with a domain specific role
        role = unit.new_role_ref(domain_id=self.domain_id)
        self.role_list[0] = PROVIDERS.role_api.create_role(role['id'], role)
        self._create_implied_role(self.role_list[0], self.role_list[1])
        self._create_implied_role(self.role_list[1], self.role_list[2])
        self._assign_top_role_to_user_on_project(self.user, self.project)

        # Create a trustee and assign the prior role to her
        trustee = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        ref = unit.new_trust_ref(
            trustor_user_id=self.user['id'],
            trustee_user_id=trustee['id'],
            project_id=self.project['id'],
            role_ids=[self.role_list[0]['id']])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = r.result['trust']

        # Only the role that was specified is in the trust, NOT implied roles
        self.assertEqual(self.role_list[0]['id'], trust['roles'][0]['id'])
        self.assertThat(trust['roles'], matchers.HasLength(1))

        # Authenticate as the trustee
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        token = r.result['token']

        # The token should have the roles implies by the domain specific role,
        # but not the domain specific role itself.
        self.assertThat(token['roles'],
                        matchers.HasLength(len(self.role_list) - 1))
        for role in token['roles']:
            self.assertIn(role, self.role_list)
        for role in [self.role_list[1], self.role_list[2]]:
            self.assertIn(role, token['roles'])
        self.assertNotIn(self.role_list[0], token['roles'])

    def test_global_role_cannot_imply_domain_specific_role(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        domain_role_ref = unit.new_role_ref(domain_id=domain['id'])
        domain_role = PROVIDERS.role_api.create_role(
            domain_role_ref['id'], domain_role_ref
        )
        global_role_ref = unit.new_role_ref()
        global_role = PROVIDERS.role_api.create_role(
            global_role_ref['id'], global_role_ref
        )

        self.put('/roles/%s/implies/%s' % (global_role['id'],
                                           domain_role['id']),
                 expected_status=http.client.FORBIDDEN)


class DomainSpecificRoleTests(test_v3.RestfulTestCase, unit.TestCase):
    def setUp(self):
        def create_role(domain_id=None):
            """Call ``POST /roles``."""
            ref = unit.new_role_ref(domain_id=domain_id)
            r = self.post(
                '/roles',
                body={'role': ref})
            return self.assertValidRoleResponse(r, ref)

        super(DomainSpecificRoleTests, self).setUp()
        self.domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainB['id'], self.domainB)

        self.global_role1 = create_role()
        self.global_role2 = create_role()
        # Since there maybe other global roles already created, let's count
        # them, so we can ensure we can check subsequent list responses
        # are correct
        r = self.get('/roles')
        self.existing_global_roles = len(r.result['roles'])

        # And now create some domain specific roles
        self.domainA_role1 = create_role(domain_id=self.domainA['id'])
        self.domainA_role2 = create_role(domain_id=self.domainA['id'])
        self.domainB_role = create_role(domain_id=self.domainB['id'])

    def test_get_and_list_domain_specific_roles(self):
        # Check we can get a domain specific role
        r = self.get('/roles/%s' % self.domainA_role1['id'])
        self.assertValidRoleResponse(r, self.domainA_role1)

        # If we list without specifying a domain, we should only get global
        # roles back.
        r = self.get('/roles')
        self.assertValidRoleListResponse(
            r, expected_length=self.existing_global_roles)
        self.assertRoleInListResponse(r, self.global_role1)
        self.assertRoleInListResponse(r, self.global_role2)
        self.assertRoleNotInListResponse(r, self.domainA_role1)
        self.assertRoleNotInListResponse(r, self.domainA_role2)
        self.assertRoleNotInListResponse(r, self.domainB_role)

        # Now list those in domainA, making sure that's all we get back
        r = self.get('/roles?domain_id=%s' % self.domainA['id'])
        self.assertValidRoleListResponse(r, expected_length=2)
        self.assertRoleInListResponse(r, self.domainA_role1)
        self.assertRoleInListResponse(r, self.domainA_role2)

    def test_update_domain_specific_roles(self):
        self.domainA_role1['name'] = uuid.uuid4().hex
        self.patch('/roles/%(role_id)s' % {
            'role_id': self.domainA_role1['id']},
            body={'role': self.domainA_role1})
        r = self.get('/roles/%s' % self.domainA_role1['id'])
        self.assertValidRoleResponse(r, self.domainA_role1)

    def test_delete_domain_specific_roles(self):
        # Check delete only removes that one domain role
        self.delete('/roles/%(role_id)s' % {
            'role_id': self.domainA_role1['id']})

        self.get('/roles/%s' % self.domainA_role1['id'],
                 expected_status=http.client.NOT_FOUND)
        # Now re-list those in domainA, making sure there's only one left
        r = self.get('/roles?domain_id=%s' % self.domainA['id'])
        self.assertValidRoleListResponse(r, expected_length=1)
        self.assertRoleInListResponse(r, self.domainA_role2)

    def test_same_domain_assignment(self):
        user = unit.create_user(PROVIDERS.identity_api,
                                domain_id=self.domainA['id'])

        projectA = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(projectA['id'], projectA)

        PROVIDERS.assignment_api.create_grant(
            self.domainA_role1['id'], user_id=user['id'],
            project_id=projectA['id']
        )

    def test_cross_domain_assignment_valid(self):
        user = unit.create_user(PROVIDERS.identity_api,
                                domain_id=self.domainB['id'])

        projectA = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(projectA['id'], projectA)

        # Positive: a role on domainA can be assigned to a user from domainB
        # but only for use on a project from domainA
        PROVIDERS.assignment_api.create_grant(
            self.domainA_role1['id'], user_id=user['id'],
            project_id=projectA['id']
        )

    def test_cross_domain_assignment_invalid(self):
        user = unit.create_user(PROVIDERS.identity_api,
                                domain_id=self.domainB['id'])

        projectB = unit.new_project_ref(domain_id=self.domainB['id'])
        PROVIDERS.resource_api.create_project(projectB['id'], projectB)

        # Negative: a role on domainA can be assigned to a user from domainB
        # only for a project from domainA
        self.assertRaises(exception.DomainSpecificRoleMismatch,
                          PROVIDERS.assignment_api.create_grant,
                          self.domainA_role1['id'],
                          user_id=user['id'],
                          project_id=projectB['id'])

    def test_cross_domain_implied_roles_authentication(self):
        # Create a user in domainB
        user = unit.create_user(PROVIDERS.identity_api,
                                domain_id=self.domainB['id'])

        # Create project in domainA
        projectA = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(projectA['id'], projectA)

        # Now we create an implied rule from a role in domainA to a
        # role in domainB
        self.put('/roles/%s/implies/%s' %
                 (self.domainA_role1['id'], self.domainB_role['id']),
                 expected_status=http.client.CREATED)

        # A role in domainA can be assigned to a user from domainB
        # only for a project from domainA
        PROVIDERS.assignment_api.create_grant(
            self.domainA_role1['id'], user_id=user['id'],
            project_id=projectA['id']
        )

        # The role assignments should return an empty list since domain roles
        # can only be used to imply another roles
        assignments = PROVIDERS.assignment_api.list_role_assignments(
            user_id=user['id'], effective=True)
        self.assertEqual([], assignments)

        # This also means we can't authenticate using the existing assignment
        auth_body = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            project_id=projectA['id'])
        self.post('/auth/tokens', body=auth_body,
                  expected_status=http.client.UNAUTHORIZED)


class ListUserProjectsTestCase(test_v3.RestfulTestCase):
    """Test for /users/<user>/projects."""

    def load_sample_data(self):
        # do not load base class's data, keep it focused on the tests

        self.auths = []
        self.domains = []
        self.projects = []
        self.roles = []
        self.users = []

        root_domain = unit.new_domain_ref(
            id=resource_base.NULL_DOMAIN_ID,
            name=resource_base.NULL_DOMAIN_ID
        )
        self.resource_api.create_domain(resource_base.NULL_DOMAIN_ID,
                                        root_domain)

        # Create 3 sets of domain, roles, projects, and users to demonstrate
        # the right user's data is loaded and only projects they can access
        # are returned.

        for _ in range(3):
            domain = unit.new_domain_ref()
            PROVIDERS.resource_api.create_domain(domain['id'], domain)

            user = unit.create_user(
                PROVIDERS.identity_api, domain_id=domain['id']
            )

            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)

            PROVIDERS.assignment_api.create_grant(
                role['id'], user_id=user['id'], domain_id=domain['id']
            )

            project = unit.new_project_ref(domain_id=domain['id'])
            PROVIDERS.resource_api.create_project(project['id'], project)

            PROVIDERS.assignment_api.create_grant(
                role['id'], user_id=user['id'], project_id=project['id']
            )

            auth = self.build_authentication_request(
                user_id=user['id'],
                password=user['password'],
                domain_id=domain['id'])

            self.auths.append(auth)
            self.domains.append(domain)
            self.projects.append(project)
            self.roles.append(role)
            self.users.append(user)

    def test_list_head_all(self):
        for i in range(len(self.users)):
            user = self.users[i]
            auth = self.auths[i]

            url = '/users/%s/projects' % user['id']
            result = self.get(url, auth=auth)
            projects_result = result.json['projects']
            self.assertEqual(1, len(projects_result))
            self.assertEqual(self.projects[i]['id'], projects_result[0]['id'])
            self.head(url, auth=auth, expected_status=http.client.OK)

    def test_list_enabled(self):
        for i in range(len(self.users)):
            user = self.users[i]
            auth = self.auths[i]

            # There are no disabled projects
            url = '/users/%s/projects?enabled=True' % user['id']
            result = self.get(url, auth=auth)
            projects_result = result.json['projects']
            self.assertEqual(1, len(projects_result))
            self.assertEqual(self.projects[i]['id'], projects_result[0]['id'])

    def test_list_disabled(self):
        for i in range(len(self.users)):
            user = self.users[i]
            auth = self.auths[i]
            project = self.projects[i]

            # There are no disabled projects
            url = '/users/%s/projects?enabled=False' % user['id']
            result = self.get(url, auth=auth)
            self.assertEqual(0, len(result.json['projects']))

            # disable this one and check again
            project['enabled'] = False
            PROVIDERS.resource_api.update_project(project['id'], project)
            result = self.get(url, auth=auth)
            projects_result = result.json['projects']
            self.assertEqual(1, len(projects_result))
            self.assertEqual(self.projects[i]['id'], projects_result[0]['id'])

    def test_list_by_domain_id(self):
        for i in range(len(self.users)):
            user = self.users[i]
            domain = self.domains[i]
            auth = self.auths[i]

            # Try looking for projects with a non-existent domain_id
            url = '/users/%s/projects?domain_id=%s' % (user['id'],
                                                       uuid.uuid4().hex)
            result = self.get(url, auth=auth)
            self.assertEqual(0, len(result.json['projects']))

            # Now try a valid one
            url = '/users/%s/projects?domain_id=%s' % (user['id'],
                                                       domain['id'])
            result = self.get(url, auth=auth)
            projects_result = result.json['projects']
            self.assertEqual(1, len(projects_result))
            self.assertEqual(self.projects[i]['id'], projects_result[0]['id'])


# FIXME(lbragstad): These tests contain system-level API calls, which means
# they will log a warning message if they are called with a project-scoped
# token, regardless of the role assignment on the project.  We need to fix
# them by using a proper system-scoped admin token to make the call instead
# of a project scoped token.
class UserSystemRoleAssignmentTestCase(test_v3.RestfulTestCase,
                                       SystemRoleAssignmentMixin):

    def test_assign_system_role_to_user(self):
        system_role_id = self._create_new_role()

        # assign the user a role on the system
        member_url = (
            '/system/users/%(user_id)s/roles/%(role_id)s' % {
                'user_id': self.user['id'],
                'role_id': system_role_id
            }
        )
        self.put(member_url)

        # validate the role assignment
        self.head(member_url)

        # list system roles
        collection_url = (
            '/system/users/%(user_id)s/roles' % {'user_id': self.user['id']}
        )
        roles = self.get(collection_url).json_body['roles']
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]['id'], system_role_id)
        self.head(collection_url, expected_status=http.client.OK)

        response = self.get(
            '/role_assignments?scope.system=all&user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response)

    def test_list_role_assignments_for_user_returns_all_assignments(self):
        system_role_id = self._create_new_role()

        # assign the user a role on the system
        member_url = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # the response should contain one role assignment for the system role
        # and one for a role that was setup during setUp().
        response = self.get(
            '/role_assignments?user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=2)

    def test_list_system_roles_for_user_returns_none_without_assignment(self):
        # list system roles for user
        collection_url = '/system/users/%(user_id)s/roles' % {
            'user_id': self.user['id']
        }
        response = self.get(collection_url)

        # assert that the user doesn't have any system role assignments, which
        # is denoted by an empty list
        self.assertEqual(response.json_body['roles'], [])

        response = self.get(
            '/role_assignments?scope.system=all&user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertEqual(len(response.json_body['role_assignments']), 0)
        self.assertValidRoleAssignmentListResponse(response)

    def test_list_system_roles_for_user_does_not_return_project_roles(self):
        system_role_id = self._create_new_role()

        # assign the user a role on the system
        member_url = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # list project role assignments and save the role id of that
        # assignment, this assignment was created during setUp
        response = self.get(
            '/projects/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.project['id'],
                'user_id': self.user['id']
            }
        )
        self.assertEqual(len(response.json_body['roles']), 1)
        project_role_id = response.json_body['roles'][0]['id']

        # list system role assignments
        collection_url = '/system/users/%(user_id)s/roles' % {
            'user_id': self.user['id']
        }
        response = self.get(collection_url)

        # assert the project role assignment is not in the system role
        # assignments
        for role in response.json_body['roles']:
            self.assertNotEqual(role['id'], project_role_id)

        # make sure the role_assignment API filters correctly based on system
        # scope
        response = self.get(
            '/role_assignments?scope.system=all&user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertEqual(len(response.json_body['role_assignments']), 1)
        system_assignment = response.json_body['role_assignments'][0]
        self.assertEqual(system_assignment['role']['id'], system_role_id)
        self.assertTrue(system_assignment['scope']['system']['all'])

        # make sure the role_assignment API doesn't include the system role
        # assignment when we filter based on project
        path = (
            '/role_assignments?scope.project.id=%(project_id)s&'
            'user.id=%(user_id)s'
        ) % {'project_id': self.project['id'],
             'user_id': self.user['id']}
        response = self.get(path)
        self.assertEqual(len(response.json_body['role_assignments']), 1)
        project_assignment = response.json_body['role_assignments'][0]
        self.assertEqual(project_assignment['role']['id'], project_role_id)

    def test_list_system_roles_for_user_does_not_return_domain_roles(self):
        system_role_id = self._create_new_role()
        domain_role_id = self._create_new_role()

        # assign a role to the user on a domain
        domain_member_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'domain_id': self.user['domain_id'],
                'user_id': self.user['id'],
                'role_id': domain_role_id
            }
        )
        self.put(domain_member_url)

        # assign the user a role on the system
        member_url = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # list domain role assignments
        response = self.get(
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.user['domain_id'],
                'user_id': self.user['id']
            }
        )
        self.assertEqual(len(response.json_body['roles']), 1)

        # list system role assignments
        collection_url = '/system/users/%(user_id)s/roles' % {
            'user_id': self.user['id']
        }
        response = self.get(collection_url)

        # assert the domain role assignment is not in the system role
        # assignments
        for role in response.json_body['roles']:
            self.assertNotEqual(role['id'], domain_role_id)

        # make sure the role_assignment API filters correctly based on system
        # scope
        response = self.get(
            '/role_assignments?scope.system=all&user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertEqual(len(response.json_body['role_assignments']), 1)
        system_assignment = response.json_body['role_assignments'][0]
        self.assertEqual(system_assignment['role']['id'], system_role_id)
        self.assertTrue(system_assignment['scope']['system']['all'])

        # make sure the role_assignment API doesn't include the system role
        # assignment when we filter based on domain
        path = (
            '/role_assignments?scope.domain.id=%(domain_id)s&'
            'user.id=%(user_id)s'
        ) % {'domain_id': self.user['domain_id'],
             'user_id': self.user['id']}
        response = self.get(path)
        self.assertEqual(len(response.json_body['role_assignments']), 1)
        domain_assignment = response.json_body['role_assignments'][0]
        self.assertEqual(domain_assignment['role']['id'], domain_role_id)

    def test_check_user_has_system_role_when_assignment_exists(self):
        system_role_id = self._create_new_role()

        # assign the user a role on the system
        member_url = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # check the user has the system role assignment
        self.head(member_url)

    def test_check_user_does_not_have_system_role_without_assignment(self):
        system_role_id = self._create_new_role()

        # check the user does't have the system role assignment
        member_url = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role_id
        }
        self.head(member_url, expected_status=http.client.NOT_FOUND)

        response = self.get(
            '/role_assignments?scope.system=all&user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertEqual(len(response.json_body['role_assignments']), 0)
        self.assertValidRoleAssignmentListResponse(response)

    def test_unassign_system_role_from_user(self):
        system_role_id = self._create_new_role()

        # assign the user a role on the system
        member_url = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # ensure the user has the role assignment
        self.head(member_url)

        response = self.get(
            '/role_assignments?scope.system=all&user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertEqual(len(response.json_body['role_assignments']), 1)
        self.assertValidRoleAssignmentListResponse(response)

        # remove the system role assignment from the user
        self.delete(member_url)

        # ensure the user doesn't have any system role assignments
        collection_url = '/system/users/%(user_id)s/roles' % {
            'user_id': self.user['id']
        }
        response = self.get(collection_url)
        self.assertEqual(len(response.json_body['roles']), 0)
        response = self.get(
            '/role_assignments?scope.system=all&user.id=%(user_id)s' % {
                'user_id': self.user['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=0)

    def test_query_for_system_scope_and_domain_scope_fails(self):
        # When asking for assignments and providing query parameters, we
        # shouldn't be able to ask for two different types of scope. This is
        # also true for project + domain scope.
        path = (
            '/role_assignments?scope.system=all'
            '&scope.domain.id=%(domain_id)s'
        ) % {'domain_id': self.domain_id}
        self.get(path, expected_status=http.client.BAD_REQUEST)

    def test_query_for_system_scope_and_project_scope_fails(self):
        # When asking for assignments and providing query parameters, we
        # shouldn't be able to ask for two different types of scope. This is
        # also true for project + domain scope.
        path = (
            '/role_assignments?scope.system=all'
            '&scope.project.id=%(project_id)s'
        ) % {'project_id': self.project_id}
        self.get(path, expected_status=http.client.BAD_REQUEST)

    def test_query_for_role_id_does_not_return_system_user_roles(self):
        system_role_id = self._create_new_role()

        # assign the user a role on the system
        member_url = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # Make sure we only get one role assignment back since the system role
        # assignment shouldn't be returned.
        path = (
            '/role_assignments?role.id=%(role_id)s&user.id=%(user_id)s'
        ) % {'role_id': self.role_id, 'user_id': self.user['id']}
        response = self.get(path)
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)


# FIXME(lbragstad): These tests contain system-level API calls, which means
# they will log a warning message if they are called with a project-scoped
# token, regardless of the role assignment on the project.  We need to fix
# them by using a proper system-scoped admin token to make the call instead
# of a project scoped token.
class GroupSystemRoleAssignmentTestCase(test_v3.RestfulTestCase,
                                        SystemRoleAssignmentMixin):

    def test_assign_system_role_to_group(self):
        system_role_id = self._create_new_role()
        group = self._create_group()

        # assign the role to the group globally
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # validate the role assignment
        self.head(member_url)

        # list global roles
        collection_url = '/system/groups/%(group_id)s/roles' % {
            'group_id': group['id']
        }
        roles = self.get(collection_url).json_body['roles']
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]['id'], system_role_id)
        self.head(collection_url, expected_status=http.client.OK)

        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)
        self.assertEqual(
            response.json_body['role_assignments'][0]['role']['id'],
            system_role_id
        )

    def test_assign_system_role_to_non_existant_group_fails(self):
        system_role_id = self._create_new_role()
        group_id = uuid.uuid4().hex

        # assign the role to the group globally
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group_id,
            'role_id': system_role_id
        }
        self.put(member_url, expected_status=http.client.NOT_FOUND)

    def test_list_role_assignments_for_group_returns_all_assignments(self):
        system_role_id = self._create_new_role()
        group = self._create_group()

        # assign the role to the group globally and on a single project
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.put(member_url)
        member_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/'
            'roles/%(role_id)s'
        ) % {
            'project_id': self.project_id,
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # make sure both assignments exist in the response, there should be two
        response = self.get(
            '/role_assignments?group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=2)

    def test_list_system_roles_for_group_returns_none_without_assignment(self):
        group = self._create_group()

        # list global roles for group
        collection_url = '/system/groups/%(group_id)s/roles' % {
            'group_id': group['id']
        }
        response = self.get(collection_url)

        # assert that the group doesn't have any system role assignments, which
        # is denoted by an empty list
        self.assertEqual(response.json_body['roles'], [])

        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=0)

    def test_list_system_roles_for_group_does_not_return_project_roles(self):
        system_role_id = self._create_new_role()
        project_role_id = self._create_new_role()
        group = self._create_group()

        # assign the group a role on the system and a role on a project
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'], 'role_id': system_role_id
        }
        self.put(member_url)
        member_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/'
            'roles/%(role_id)s'
        ) % {
            'project_id': self.project_id,
            'group_id': group['id'],
            'role_id': project_role_id
        }
        self.put(member_url)

        # list system role assignments
        collection_url = '/system/groups/%(group_id)s/roles' % {
            'group_id': group['id']
        }
        response = self.get(collection_url)

        # assert the project role assignment is not in the system role
        # assignments
        for role in response.json_body['roles']:
            self.assertNotEqual(role['id'], project_role_id)

        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)

    def test_list_system_roles_for_group_does_not_return_domain_roles(self):
        system_role_id = self._create_new_role()
        domain_role_id = self._create_new_role()
        group = self._create_group()

        # assign a role to the group on a domain
        domain_member_url = (
            '/domains/%(domain_id)s/groups/%(group_id)s/'
            'roles/%(role_id)s' % {
                'domain_id': group['domain_id'],
                'group_id': group['id'],
                'role_id': domain_role_id
            }
        )
        self.put(domain_member_url)

        # assign the group a role on the system
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # list domain role assignments
        response = self.get(
            '/domains/%(domain_id)s/groups/%(group_id)s/roles' % {
                'domain_id': group['domain_id'], 'group_id': group['id']
            }
        )
        self.assertEqual(len(response.json_body['roles']), 1)

        # list system role assignments
        collection_url = '/system/groups/%(group_id)s/roles' % {
            'group_id': group['id']
        }
        response = self.get(collection_url)

        # assert the domain role assignment is not in the system role
        # assignments
        for role in response.json_body['roles']:
            self.assertNotEqual(role['id'], domain_role_id)

        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)

    def test_check_group_has_system_role_when_assignment_exists(self):
        system_role_id = self._create_new_role()
        group = self._create_group()

        # assign the group a role on the system
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # check the group has the system role assignment
        self.head(member_url)

        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)
        self.assertEqual(
            response.json_body['role_assignments'][0]['role']['id'],
            system_role_id
        )

    def test_check_group_does_not_have_system_role_without_assignment(self):
        system_role_id = self._create_new_role()
        group = self._create_group()

        # check the group does't have the system role assignment
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.head(member_url, expected_status=http.client.NOT_FOUND)

        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=0)

    def test_unassign_system_role_from_group(self):
        system_role_id = self._create_new_role()
        group = self._create_group()

        # assign the group a role on the system
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # ensure the group has the role assignment
        self.head(member_url)

        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertEqual(len(response.json_body['role_assignments']), 1)
        self.assertValidRoleAssignmentListResponse(response)

        # remove the system role assignment from the group
        self.delete(member_url)

        # ensure the group doesn't have any system role assignments
        collection_url = '/system/groups/%(group_id)s/roles' % {
            'group_id': group['id']
        }
        response = self.get(collection_url)
        self.assertEqual(len(response.json_body['roles']), 0)
        response = self.get(
            '/role_assignments?scope.system=all&group.id=%(group_id)s' % {
                'group_id': group['id']
            }
        )
        self.assertValidRoleAssignmentListResponse(response, expected_length=0)

    def test_query_for_role_id_does_not_return_system_group_roles(self):
        system_role_id = self._create_new_role()
        group = self._create_group()

        # assign the group a role on the system
        member_url = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': system_role_id
        }
        self.put(member_url)

        # assign the group a role on the system
        member_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/roles/%(role_id)s' %
            {'project_id': self.project_id,
             'group_id': group['id'],
             'role_id': self.role_id}
        )
        self.put(member_url)

        # Make sure we only get one role assignment back since the system role
        # assignment shouldn't be returned.
        path = (
            '/role_assignments?role.id=%(role_id)s&group.id=%(group_id)s'
        ) % {'role_id': self.role_id, 'group_id': group['id']}
        response = self.get(path)
        self.assertValidRoleAssignmentListResponse(response, expected_length=1)
