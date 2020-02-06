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

import copy
import http.client
import uuid

from oslo_serialization import jsonutils

from keystone.common.policies import role_assignment as rp
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _AssignmentTestUtilities(object):
    """Useful utilities for setting up test assignments and assertions."""

    def _setup_test_role_assignments(self):
        # Utility to create assignments and return important data for
        # assertions.

        # Since the role doesn't really matter too much, we can just re-use an
        # existing role instead of creating a new one.
        role_id = self.bootstrapper.reader_role_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        # create a user+project role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, user_id=user['id'], project_id=project['id']
        )

        # create a user+domain role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, user_id=user['id'], domain_id=domain['id']
        )

        # create a user+system role assignment.
        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], role_id
        )

        # create a group+project role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, group_id=group['id'], project_id=project['id']
        )

        # create a group+domain role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, group_id=group['id'], domain_id=domain['id']
        )

        # create a group+system role assignment.
        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], role_id
        )

        return {
            'user_id': user['id'],
            'group_id': group['id'],
            'domain_id': domain['id'],
            'project_id': project['id'],
            'role_id': role_id,
        }

    def _extract_role_assignments_from_response_body(self, r):
        # Condense the role assignment details into a set of key things we can
        # use in assertions.
        assignments = []
        for assignment in r.json['role_assignments']:
            a = {}
            if 'project' in assignment['scope']:
                a['project_id'] = assignment['scope']['project']['id']
            elif 'domain' in assignment['scope']:
                a['domain_id'] = assignment['scope']['domain']['id']
            elif 'system' in assignment['scope']:
                a['system'] = 'all'

            if 'user' in assignment:
                a['user_id'] = assignment['user']['id']
            elif 'group' in assignment:
                a['group_id'] = assignment['group']['id']

            a['role_id'] = assignment['role']['id']

            assignments.append(a)
        return assignments


class _SystemUserTests(object):
    """Common functionality for system users regardless of default role."""

    def test_user_can_list_all_role_assignments_in_the_deployment(self):
        assignments = self._setup_test_role_assignments()

        # this assignment is created by keystone-manage bootstrap
        self.expected.append({
            'user_id': self.bootstrapper.admin_user_id,
            'project_id': self.bootstrapper.project_id,
            'role_id': self.bootstrapper.admin_role_id
        })

        # this assignment is created by keystone-manage bootstrap
        self.expected.append({
            'user_id': self.bootstrapper.admin_user_id,
            'system': 'all',
            'role_id': self.bootstrapper.admin_role_id
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'project_id': assignments['project_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'domain_id': assignments['domain_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'project_id': assignments['project_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'domain_id': assignments['domain_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })

        with self.test_client() as c:
            r = c.get('/v3/role_assignments', headers=self.headers)
            self.assertEqual(
                len(self.expected), len(r.json['role_assignments'])
            )
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, self.expected)

    def test_user_can_list_all_role_names_assignments_in_the_deployment(self):
        assignments = self._setup_test_role_assignments()

        # this assignment is created by keystone-manage bootstrap
        self.expected.append({
            'user_id': self.bootstrapper.admin_user_id,
            'project_id': self.bootstrapper.project_id,
            'role_id': self.bootstrapper.admin_role_id
        })

        # this assignment is created by keystone-manage bootstrap
        self.expected.append({
            'user_id': self.bootstrapper.admin_user_id,
            'system': 'all',
            'role_id': self.bootstrapper.admin_role_id
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'project_id': assignments['project_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'domain_id': assignments['domain_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'project_id': assignments['project_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'domain_id': assignments['domain_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?include_names=True', headers=self.headers
            )
            self.assertEqual(
                len(self.expected), len(r.json['role_assignments'])
            )
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, self.expected)

    def test_user_can_filter_role_assignments_by_project(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'user_id': assignments['user_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            }
        ]
        project_id = assignments['project_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.project.id=%s' % project_id,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_domain(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'user_id': assignments['user_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            }
        ]
        domain_id = assignments['domain_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.domain.id=%s' % domain_id,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_system(self):
        assignments = self._setup_test_role_assignments()

        # this assignment is created by keystone-manage bootstrap
        self.expected.append({
            'user_id': self.bootstrapper.admin_user_id,
            'system': 'all',
            'role_id': self.bootstrapper.admin_role_id
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.system=all',
                headers=self.headers
            )
            self.assertEqual(
                len(self.expected), len(r.json['role_assignments'])
            )
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, self.expected)

    def test_user_can_filter_role_assignments_by_user(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            # assignment of the user running the test case
            {
                'user_id': assignments['user_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'user_id': assignments['user_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            },
            {
                'user_id': assignments['user_id'],
                'system': 'all',
                'role_id': assignments['role_id']
            }
        ]
        user_id = assignments['user_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?user.id=%s' % user_id,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_group(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'group_id': assignments['group_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'system': 'all',
                'role_id': assignments['role_id']
            }
        ]
        group_id = assignments['group_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?group.id=%s' % group_id,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_role(self):
        assignments = self._setup_test_role_assignments()
        self.expected = [ra for ra in self.expected
                         if ra['role_id'] == assignments['role_id']]
        self.expected.append({
            'user_id': assignments['user_id'],
            'project_id': assignments['project_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'domain_id': assignments['domain_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'user_id': assignments['user_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'project_id': assignments['project_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'domain_id': assignments['domain_id'],
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })

        role_id = assignments['role_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?role.id=%s&include_names=True' % role_id,
                headers=self.headers
            )
            self.assertEqual(
                len(self.expected), len(r.json['role_assignments'])
            )
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, self.expected)

    def test_user_can_filter_role_assignments_by_project_and_role(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'user_id': assignments['user_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
        ]

        with self.test_client() as c:
            qs = (assignments['project_id'], assignments['role_id'])
            r = c.get(
                '/v3/role_assignments?scope.project.id=%s&role.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_domain_and_role(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'user_id': assignments['user_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            },
        ]
        qs = (assignments['domain_id'], assignments['role_id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.domain.id=%s&role.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_system_and_role(self):
        assignments = self._setup_test_role_assignments()
        self.expected = [ra for ra in self.expected
                         if ra['role_id'] == assignments['role_id']]
        self.expected.append({
            'user_id': assignments['user_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })
        self.expected.append({
            'group_id': assignments['group_id'],
            'system': 'all',
            'role_id': assignments['role_id']
        })
        role_id = assignments['role_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.system=all&role.id=%s' % role_id,
                headers=self.headers
            )
            self.assertEqual(
                len(self.expected), len(r.json['role_assignments'])
            )
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, self.expected)

    def test_user_can_filter_role_assignments_by_user_and_role(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'user_id': assignments['user_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'user_id': assignments['user_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            },
            {
                'user_id': assignments['user_id'],
                'system': 'all',
                'role_id': assignments['role_id']
            }
        ]
        qs = (assignments['user_id'], assignments['role_id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?user.id=%s&role.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_group_and_role(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'group_id': assignments['group_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'system': 'all',
                'role_id': assignments['role_id']
            }
        ]

        with self.test_client() as c:
            qs = (assignments['group_id'], assignments['role_id'])
            r = c.get(
                '/v3/role_assignments?group.id=%s&role.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_project_and_user(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'user_id': assignments['user_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            }
        ]
        qs = (assignments['project_id'], assignments['user_id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.project.id=%s&user.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_project_and_group(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'group_id': assignments['group_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            }
        ]
        qs = (assignments['project_id'], assignments['group_id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.project.id=%s&group.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_domain_and_user(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'user_id': assignments['user_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            }
        ]
        qs = (assignments['domain_id'], assignments['user_id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.domain.id=%s&user.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_domain_and_group(self):
        assignments = self._setup_test_role_assignments()
        expected = [
            {
                'group_id': assignments['group_id'],
                'domain_id': assignments['domain_id'],
                'role_id': assignments['role_id']
            }
        ]
        qs = (assignments['domain_id'], assignments['group_id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.domain.id=%s&group.id=%s' % qs,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_list_assignments_for_subtree(self):
        assignments = self._setup_test_role_assignments()
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id,
                                 parent_id=assignments['project_id'])
        )
        PROVIDERS.assignment_api.create_grant(
            assignments['role_id'],
            user_id=user['id'],
            project_id=project['id']
        )
        expected = [
            {
                'user_id': assignments['user_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': assignments['group_id'],
                'project_id': assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'user_id': user['id'],
                'project_id': project['id'],
                'role_id': assignments['role_id']
            }
        ]
        with self.test_client() as c:
            r = c.get(
                ('/v3/role_assignments?scope.project.id=%s&include_subtree' %
                 assignments['project_id']),
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)


class _DomainUserTests(object):
    """Common functionality for domain users."""

    def _setup_test_role_assignments_for_domain(self):
        # Populate role assignment within `self.domain_id` so that we can
        # assert users can view assignments within the domain they have
        # authorization on
        role_id = self.bootstrapper.reader_role_id

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        # create a user+project role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, user_id=user['id'], project_id=project['id']
        )

        # create a user+domain role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, user_id=user['id'], domain_id=self.domain_id
        )

        # create a group+project role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, group_id=group['id'], project_id=project['id']
        )

        # create a group+domain role assignment.
        PROVIDERS.assignment_api.create_grant(
            role_id, group_id=group['id'], domain_id=self.domain_id
        )

        return {
            'user_id': user['id'],
            'group_id': group['id'],
            'project_id': project['id'],
            'role_id': role_id,
        }

    def test_user_can_list_all_assignments_in_their_domain(self):
        self._setup_test_role_assignments()
        domain_assignments = self._setup_test_role_assignments_for_domain()

        self.expected.append({
            'user_id': domain_assignments['user_id'],
            'domain_id': self.domain_id,
            'role_id': domain_assignments['role_id']
        })
        self.expected.append({
            'user_id': domain_assignments['user_id'],
            'project_id': domain_assignments['project_id'],
            'role_id': domain_assignments['role_id']
        })
        self.expected.append({
            'group_id': domain_assignments['group_id'],
            'domain_id': self.domain_id,
            'role_id': domain_assignments['role_id']
        })
        self.expected.append({
            'group_id': domain_assignments['group_id'],
            'project_id': domain_assignments['project_id'],
            'role_id': domain_assignments['role_id']
        })

        with self.test_client() as c:
            r = c.get('/v3/role_assignments', headers=self.headers)
            self.assertEqual(
                len(self.expected), len(r.json['role_assignments'])
            )
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, self.expected)

    def test_user_can_filter_role_assignments_by_project_in_domain(self):
        self._setup_test_role_assignments()
        domain_assignments = self._setup_test_role_assignments_for_domain()

        expected = [
            {
                'user_id': domain_assignments['user_id'],
                'project_id': domain_assignments['project_id'],
                'role_id': domain_assignments['role_id']
            },
            {
                'group_id': domain_assignments['group_id'],
                'project_id': domain_assignments['project_id'],
                'role_id': domain_assignments['role_id']
            }
        ]

        project_id = domain_assignments['project_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.project.id=%s' % project_id,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_domain(self):
        # This shouldn't really provide any more value than just calling GET
        # /v3/role_assignments with a domain-scoped token, but we test it
        # anyway.
        self._setup_test_role_assignments()
        domain_assignments = self._setup_test_role_assignments_for_domain()

        self.expected.append({
            'user_id': domain_assignments['user_id'],
            'domain_id': self.domain_id,
            'role_id': domain_assignments['role_id']
        })
        self.expected.append({
            'group_id': domain_assignments['group_id'],
            'domain_id': self.domain_id,
            'role_id': domain_assignments['role_id']
        })

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.domain.id=%s' % self.domain_id,
                headers=self.headers
            )
            self.assertEqual(
                len(self.expected), len(r.json['role_assignments'])
            )
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, self.expected)

    def test_user_can_filter_role_assignments_by_user_of_domain(self):
        self._setup_test_role_assignments()
        domain_assignments = self._setup_test_role_assignments_for_domain()

        expected = [
            {
                'user_id': domain_assignments['user_id'],
                'domain_id': self.domain_id,
                'role_id': domain_assignments['role_id']
            },
            {
                'user_id': domain_assignments['user_id'],
                'project_id': domain_assignments['project_id'],
                'role_id': domain_assignments['role_id']
            }
        ]

        user_id = domain_assignments['user_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?user.id=%s' % user_id,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_can_filter_role_assignments_by_group_of_domain(self):
        self._setup_test_role_assignments()
        domain_assignments = self._setup_test_role_assignments_for_domain()

        expected = [
            {
                'group_id': domain_assignments['group_id'],
                'domain_id': self.domain_id,
                'role_id': domain_assignments['role_id']
            },
            {
                'group_id': domain_assignments['group_id'],
                'project_id': domain_assignments['project_id'],
                'role_id': domain_assignments['role_id']
            }
        ]

        group_id = domain_assignments['group_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?group.id=%s' % group_id,
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_cannot_filter_role_assignments_by_system(self):
        self._setup_test_role_assignments()
        self._setup_test_role_assignments_for_domain()

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.system=all',
                headers=self.headers
            )
            self.assertEqual(0, len(r.json['role_assignments']))

    def test_user_cannot_filter_role_assignments_by_other_domain(self):
        assignments = self._setup_test_role_assignments()
        domain = assignments['domain_id']
        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.domain.id=%s' % domain,
                headers=self.headers
            )
            self.assertEqual([], r.json['role_assignments'])

    def test_user_cannot_filter_role_assignments_by_other_domain_project(self):
        assignments = self._setup_test_role_assignments()
        self._setup_test_role_assignments_for_domain()

        # This project is in an entirely separate domain that this user doesn't
        # have authorization to access, so they should only see an empty list
        project_id = assignments['project_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?scope.project.id=%s' % project_id,
                headers=self.headers
            )
            self.assertEqual(0, len(r.json['role_assignments']))

    def test_user_cannot_filter_role_assignments_by_other_domain_user(self):
        assignments = self._setup_test_role_assignments()
        self._setup_test_role_assignments_for_domain()

        # This user doesn't have any role assignments on self.domain_id, so the
        # domain user of self.domain_id should only see an empty list of role
        # assignments.
        user_id = assignments['user_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?user.id=%s' % user_id,
                headers=self.headers
            )
            self.assertEqual(0, len(r.json['role_assignments']))

    def test_user_cannot_filter_role_assignments_by_other_domain_group(self):
        assignments = self._setup_test_role_assignments()
        self._setup_test_role_assignments_for_domain()

        # This group doesn't have any role assignments on self.domain_id, so
        # the domain user of self.domain_id should only see an empty list of
        # role assignments.
        group_id = assignments['group_id']

        with self.test_client() as c:
            r = c.get(
                '/v3/role_assignments?group.id=%s' % group_id,
                headers=self.headers,
            )
            self.assertEqual(0, len(r.json['role_assignments']))

    def test_user_can_list_assignments_for_subtree_in_their_domain(self):
        assignments = self._setup_test_role_assignments()
        domain_assignments = self._setup_test_role_assignments_for_domain()
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id,
                                 parent_id=domain_assignments['project_id'])
        )
        PROVIDERS.assignment_api.create_grant(
            assignments['role_id'],
            user_id=user['id'],
            project_id=project['id']
        )
        expected = [
            {
                'user_id': domain_assignments['user_id'],
                'project_id': domain_assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'group_id': domain_assignments['group_id'],
                'project_id': domain_assignments['project_id'],
                'role_id': assignments['role_id']
            },
            {
                'user_id': user['id'],
                'project_id': project['id'],
                'role_id': assignments['role_id']
            }
        ]
        with self.test_client() as c:
            r = c.get(
                ('/v3/role_assignments?scope.project.id=%s&include_subtree' %
                 domain_assignments['project_id']),
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_cannot_list_assignments_for_subtree_in_other_domain(self):
        assignments = self._setup_test_role_assignments()
        with self.test_client() as c:
            c.get(
                ('/v3/role_assignments?scope.project.id=%s&include_subtree' %
                 assignments['project_id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _ProjectUserTests(object):

    def test_user_cannot_list_all_assignments_in_their_project(self):
        with self.test_client() as c:
            c.get(
                '/v3/role_assignments', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_role_assignments_by_user_of_project(self):
        assignments = self._setup_test_role_assignments()
        user_id = assignments['user_id']

        with self.test_client() as c:
            c.get(
                '/v3/role_assignments?user.id=%s' % user_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_role_assignments_by_group_of_project(self):
        assignments = self._setup_test_role_assignments()
        group_id = assignments['group_id']

        with self.test_client() as c:
            c.get(
                '/v3/role_assignments?group.id=%s' % group_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_role_assignments_by_system(self):
        with self.test_client() as c:
            c.get(
                '/v3/role_assignments?scope.system=all',
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_role_assignments_by_domain(self):
        with self.test_client() as c:
            c.get(
                '/v3/role_assignments?scope.domain.id=%s'
                % self.domain_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_role_assignments_by_other_project(self):
        project1 = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.get(
                '/v3/role_assignments?scope.project.id=%s'
                % project1,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_role_assignments_by_other_project_user(self):
        assignments = self._setup_test_role_assignments()

        # This user doesn't have any role assignments on self.project_id, so
        # the project user of self.project_id should only see an empty list of
        # role assignments.
        user_id = assignments['user_id']

        with self.test_client() as c:
            c.get(
                '/v3/role_assignments?user.id=%s' % user_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_role_assignments_by_other_project_group(self):
        assignments = self._setup_test_role_assignments()

        # This group doesn't have any role assignments on self.project_id, so
        # the project user of self.project_id should only see an empty list of
        # role assignments.
        group_id = assignments['group_id']

        with self.test_client() as c:
            c.get(
                '/v3/role_assignments?group.id=%s' % group_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _ProjectReaderMemberTests(object):
    def test_user_cannot_list_assignments_for_subtree(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id,
                                 parent_id=self.project_id)
        )
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id,
            user_id=user['id'],
            project_id=project['id']
        )
        with self.test_client() as c:
            c.get(
                ('/v3/role_assignments?scope.project.id=%s&include_subtree' %
                 self.project_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _AssignmentTestUtilities,
                        _SystemUserTests):

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
        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'system': 'all',
                'role_id': self.bootstrapper.reader_role_id
            }
        ]

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
                        _AssignmentTestUtilities,
                        _SystemUserTests):

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
        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'system': 'all',
                'role_id': self.bootstrapper.member_role_id
            }
        ]

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
                       _AssignmentTestUtilities,
                       _SystemUserTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self.user_id = self.bootstrapper.admin_user_id
        self.expected = []

        auth = self.build_authentication_request(
            user_id=self.user_id, password=self.bootstrapper.admin_password,
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _AssignmentTestUtilities,
                        _DomainUserTests):

    def setUp(self):
        super(DomainReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_reader = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_reader)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )
        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'domain_id': self.domain_id,
                'role_id': self.bootstrapper.reader_role_id
            }]

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_reader['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _AssignmentTestUtilities,
                        _DomainUserTests):

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
        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'domain_id': self.domain_id,
                'role_id': self.bootstrapper.member_role_id
            }]

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
                       _AssignmentTestUtilities,
                       _DomainUserTests):

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.role_assignment have been removed. This is
        # only here to make sure we test the new policies instead of the
        # deprecated ones. Oslo.policy will OR deprecated policies with new
        # policies to maintain compatibility and give operators a chance to
        # update permissions or update policies without breaking users. This
        # will cause these specific tests to fail since we're trying to correct
        # this broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:list_role_assignments': (
                    rp.SYSTEM_READER_OR_DOMAIN_READER
                ),
                'identity:list_role_assignments_for_tree': (
                    rp.SYSTEM_READER_OR_PROJECT_DOMAIN_READER_OR_PROJECT_ADMIN
                )
            }
            f.write(jsonutils.dumps(overridden_policies))

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
        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'domain_id': self.domain_id,
                'role_id': self.bootstrapper.admin_role_id
            }]

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectReaderTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _AssignmentTestUtilities,
                         _ProjectUserTests,
                         _ProjectReaderMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        project = unit.new_project_ref(domain_id=self.domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        self.project_id = project['id']

        project_reader = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(project_reader)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'project_id': self.project_id,
                'role_id': self.bootstrapper.reader_role_id
            }]

        auth = self.build_authentication_request(
            user_id=self.user_id, password=project_reader['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _AssignmentTestUtilities,
                         _ProjectUserTests,
                         _ProjectReaderMemberTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        project = unit.new_project_ref(domain_id=self.domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        self.project_id = project['id']

        project_member = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(project_member)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'project_id': self.project_id,
                'role_id': self.bootstrapper.member_role_id
            }]

        auth = self.build_authentication_request(
            user_id=self.user_id, password=project_member['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _AssignmentTestUtilities,
                        _ProjectUserTests):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
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

        self.user_id = self.bootstrapper.admin_user_id

        project = unit.new_project_ref(domain_id=self.domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        self.project_id = project['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'project_id': self.project_id,
                'role_id': self.bootstrapper.admin_role_id
            }]

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.role_assignment have been removed. This is
        # only here to make sure we test the new policies instead of the
        # deprecated ones. Oslo.policy will OR deprecated policies with new
        # policies to maintain compatibility and give operators a chance to
        # update permissions or update policies without breaking users. This
        # will cause these specific tests to fail since we're trying to correct
        # this broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:list_role_assignments': (
                    rp.SYSTEM_READER_OR_DOMAIN_READER
                ),
                'identity:list_role_assignments_for_tree': (
                    rp.SYSTEM_READER_OR_PROJECT_DOMAIN_READER_OR_PROJECT_ADMIN
                )
            }
            f.write(jsonutils.dumps(overridden_policies))

    def test_user_can_list_assignments_for_subtree_on_own_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id,
                                 parent_id=self.project_id)
        )
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id,
            user_id=user['id'],
            project_id=project['id']
        )
        expected = copy.copy(self.expected)
        expected.append({
            'project_id': project['id'],
            'user_id': user['id'],
            'role_id': self.bootstrapper.reader_role_id
        })
        with self.test_client() as c:
            r = c.get(
                ('/v3/role_assignments?scope.project.id=%s&include_subtree' %
                 self.project_id),
                headers=self.headers
            )
            self.assertEqual(len(expected), len(r.json['role_assignments']))
            actual = self._extract_role_assignments_from_response_body(r)
            for assignment in actual:
                self.assertIn(assignment, expected)

    def test_user_cannot_list_assignments_for_subtree_on_other_project(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id,
            user_id=user['id'],
            project_id=project['id']
        )
        with self.test_client() as c:
            c.get(
                ('/v3/role_assignments?scope.project.id=%s&include_subtree' %
                 project['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )
