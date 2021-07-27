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

from testtools import matchers

from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class AssignmentTestHelperMixin(object):
    """Mixin class to aid testing of assignments.

    This class supports data driven test plans that enable:

    - Creation of initial entities, such as domains, users, groups, projects
      and roles
    - Creation of assignments referencing the above entities
    - A set of input parameters and expected outputs to list_role_assignments
      based on the above test data

    A test plan is a dict of the form:

    test_plan = {
        entities: details and number of entities,
        group_memberships: group-user entity memberships,
        assignments: list of assignments to create,
        tests: list of pairs of input params and expected outputs}

    An example test plan:

    test_plan = {
        # First, create the entities required. Entities are specified by
        # a dict with the key being the entity type and the value an
        # entity specification which can be one of:
        #
        # - a simple number, e.g. {'users': 3} creates 3 users
        # - a dict where more information regarding the contents of the entity
        #   is required, e.g. {'domains' : {'users : 3}} creates a domain
        #   with three users
        # - a list of entity specifications if multiple are required
        #
        # The following creates a domain that contains a single user, group and
        # project, as well as creating three roles.

        'entities': {'domains': {'users': 1, 'groups': 1, 'projects': 1},
                     'roles': 3},

        # If it is required that an existing domain be used for the new
        # entities, then the id of that domain can be included in the
        # domain dict.  For example, if alternatively we wanted to add 3 users
        # to the default domain, add a second domain containing 3 projects as
        # well as 5 additional empty domains, the entities would be defined as:
        #
        # 'entities': {'domains': [{'id': DEFAULT_DOMAIN, 'users': 3},
        #                          {'projects': 3}, 5]},
        #
        # A project hierarchy can be specified within the 'projects' section by
        # nesting the 'project' key, for example to create a project with three
        # sub-projects you would use:

                     'projects': {'project': 3}

        # A more complex hierarchy can also be defined, for example the
        # following would define three projects each containing a
        # sub-project, each of which contain a further three sub-projects.

                     'projects': [{'project': {'project': 3}},
                                  {'project': {'project': 3}},
                                  {'project': {'project': 3}}]

        # If the 'roles' entity count is defined as top level key in 'entities'
        # dict then these are global roles. If it is placed within the
        # 'domain' dict, then they will be domain specific roles. A mix of
        # domain specific and global roles are allowed, with the role index
        # being calculated in the order they are defined in the 'entities'
        # dict.

        # A set of implied role specifications. In this case, prior role
        # index 0 implies role index 1, and role 1 implies roles 2 and 3.

        'roles': [{'role': 0, 'implied_roles': [1]},
                  {'role': 1, 'implied_roles': [2, 3]}]

        # A list of groups and their members. In this case make users with
        # index 0 and 1 members of group with index 0. Users and Groups are
        # indexed in the order they appear in the 'entities' key above.

        'group_memberships': [{'group': 0, 'users': [0, 1]}]

        # Next, create assignments between the entities, referencing the
        # entities by index, i.e. 'user': 0 refers to user[0]. Entities are
        # indexed in the order they appear in the 'entities' key above within
        # their entity type.

        'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                        {'user': 0, 'role': 1, 'project': 0},
                        {'group': 0, 'role': 2, 'domain': 0},
                        {'user': 0, 'role': 2, 'project': 0}],

        # Finally, define an array of tests where list_role_assignment() is
        # called with the given input parameters and the results are then
        # confirmed to be as given in 'results'. Again, all entities are
        # referenced by index.

        'tests': [
            {'params': {},
             'results': [{'user': 0, 'role': 0, 'domain': 0},
                         {'user': 0, 'role': 1, 'project': 0},
                         {'group': 0, 'role': 2, 'domain': 0},
                         {'user': 0, 'role': 2, 'project': 0}]},
            {'params': {'role': 2},
             'results': [{'group': 0, 'role': 2, 'domain': 0},
                         {'user': 0, 'role': 2, 'project': 0}]}]

        # The 'params' key also supports the 'effective',
        # 'inherited_to_projects' and 'source_from_group_ids' options to
        # list_role_assignments.}

    """

    def _handle_project_spec(self, test_data, domain_id, project_spec,
                             parent_id=None):
        """Handle the creation of a project or hierarchy of projects.

        project_spec may either be a count of the number of projects to
        create, or it may be a list of the form:

        [{'project': project_spec}, {'project': project_spec}, ...]

        This method is called recursively to handle the creation of a
        hierarchy of projects.

        """
        def _create_project(domain_id, parent_id):
            new_project = unit.new_project_ref(domain_id=domain_id,
                                               parent_id=parent_id)
            new_project = PROVIDERS.resource_api.create_project(
                new_project['id'], new_project
            )
            return new_project

        if isinstance(project_spec, list):
            for this_spec in project_spec:
                self._handle_project_spec(
                    test_data, domain_id, this_spec, parent_id=parent_id)
        elif isinstance(project_spec, dict):
            new_proj = _create_project(domain_id, parent_id)
            test_data['projects'].append(new_proj)
            self._handle_project_spec(
                test_data, domain_id, project_spec['project'],
                parent_id=new_proj['id'])
        else:
            for _ in range(project_spec):
                test_data['projects'].append(
                    _create_project(domain_id, parent_id))

    def _create_role(self, domain_id=None):
        new_role = unit.new_role_ref(domain_id=domain_id)
        return PROVIDERS.role_api.create_role(new_role['id'], new_role)

    def _handle_domain_spec(self, test_data, domain_spec):
        """Handle the creation of domains and their contents.

        domain_spec may either be a count of the number of empty domains to
        create, a dict describing the domain contents, or a list of
        domain_specs.

        In the case when a list is provided, this method calls itself
        recursively to handle the list elements.

        This method will insert any entities created into test_data

        """
        def _create_domain(domain_id=None):
            if domain_id is None:
                new_domain = unit.new_domain_ref()
                PROVIDERS.resource_api.create_domain(
                    new_domain['id'], new_domain
                )
                return new_domain
            else:
                # The test plan specified an existing domain to use
                return PROVIDERS.resource_api.get_domain(domain_id)

        def _create_entity_in_domain(entity_type, domain_id):
            """Create a user or group entity in the domain."""
            if entity_type == 'users':
                new_entity = unit.new_user_ref(domain_id=domain_id)
                new_entity = PROVIDERS.identity_api.create_user(new_entity)
            elif entity_type == 'groups':
                new_entity = unit.new_group_ref(domain_id=domain_id)
                new_entity = PROVIDERS.identity_api.create_group(new_entity)
            elif entity_type == 'roles':
                new_entity = self._create_role(domain_id=domain_id)
            else:
                # Must be a bad test plan
                raise exception.NotImplemented()
            return new_entity

        if isinstance(domain_spec, list):
            for x in domain_spec:
                self._handle_domain_spec(test_data, x)
        elif isinstance(domain_spec, dict):
            # If there is a domain ID specified, then use it
            the_domain = _create_domain(domain_spec.get('id'))
            test_data['domains'].append(the_domain)
            for entity_type, value in domain_spec.items():
                if entity_type == 'id':
                    # We already used this above to determine whether to
                    # use and existing domain
                    continue
                if entity_type == 'projects':
                    # If it's projects, we need to handle the potential
                    # specification of a project hierarchy
                    self._handle_project_spec(
                        test_data, the_domain['id'], value)
                else:
                    # It's a count of number of entities
                    for _ in range(value):
                        test_data[entity_type].append(
                            _create_entity_in_domain(
                                entity_type, the_domain['id']))
        else:
            for _ in range(domain_spec):
                test_data['domains'].append(_create_domain())

    def create_entities(self, entity_pattern):
        """Create the entities specified in the test plan.

        Process the 'entities' key in the test plan, creating the requested
        entities. Each created entity will be added to the array of entities
        stored in the returned test_data object, e.g.:

        test_data['users'] = [user[0], user[1]....]

        """
        test_data = {}
        for entity in ['users', 'groups', 'domains', 'projects', 'roles']:
            test_data[entity] = []

        # Create any domains requested and, if specified, any entities within
        # those domains
        if 'domains' in entity_pattern:
            self._handle_domain_spec(test_data, entity_pattern['domains'])

        # Create any roles requested
        if 'roles' in entity_pattern:
            for _ in range(entity_pattern['roles']):
                test_data['roles'].append(self._create_role())

        return test_data

    def _convert_entity_shorthand(self, key, shorthand_data, reference_data):
        """Convert a shorthand entity description into a full ID reference.

        In test plan definitions, we allow a shorthand for referencing to an
        entity of the form:

        'user': 0

        which is actually shorthand for:

        'user_id': reference_data['users'][0]['id']

        This method converts the shorthand version into the full reference.

        """
        expanded_key = '%s_id' % key
        reference_index = '%ss' % key
        index_value = (
            reference_data[reference_index][shorthand_data[key]]['id'])
        return expanded_key, index_value

    def create_implied_roles(self, implied_pattern, test_data):
        """Create the implied roles specified in the test plan."""
        for implied_spec in implied_pattern:
            # Each implied role specification is a dict of the form:
            #
            # {'role': 0, 'implied_roles': list of roles}

            prior_role = test_data['roles'][implied_spec['role']]['id']
            if isinstance(implied_spec['implied_roles'], list):
                for this_role in implied_spec['implied_roles']:
                    implied_role = test_data['roles'][this_role]['id']
                    PROVIDERS.role_api.create_implied_role(
                        prior_role, implied_role
                    )
            else:
                implied_role = (
                    test_data['roles'][implied_spec['implied_roles']]['id'])
                PROVIDERS.role_api.create_implied_role(
                    prior_role, implied_role
                )

    def create_group_memberships(self, group_pattern, test_data):
        """Create the group memberships specified in the test plan."""
        for group_spec in group_pattern:
            # Each membership specification is a dict of the form:
            #
            # {'group': 0, 'users': [list of user indexes]}
            #
            # Add all users in the list to the specified group, first
            # converting from index to full entity ID.
            group_value = test_data['groups'][group_spec['group']]['id']
            for user_index in group_spec['users']:
                user_value = test_data['users'][user_index]['id']
                PROVIDERS.identity_api.add_user_to_group(
                    user_value, group_value
                )
        return test_data

    def create_assignments(self, assignment_pattern, test_data):
        """Create the assignments specified in the test plan."""
        # First store how many assignments are already in the system,
        # so during the tests we can check the number of new assignments
        # created.
        test_data['initial_assignment_count'] = (
            len(PROVIDERS.assignment_api.list_role_assignments()))

        # Now create the new assignments in the test plan
        for assignment in assignment_pattern:
            # Each assignment is a dict of the form:
            #
            # { 'user': 0, 'project':1, 'role': 6}
            #
            # where the value of each item is the index into the array of
            # entities created earlier.
            #
            # We process the assignment dict to create the args required to
            # make the create_grant() call.
            args = {}
            for param in assignment:
                if param == 'inherited_to_projects':
                    args[param] = assignment[param]
                else:
                    # Turn 'entity : 0' into 'entity_id = ac6736ba873d'
                    # where entity in user, group, project or domain
                    key, value = self._convert_entity_shorthand(
                        param, assignment, test_data)
                    args[key] = value
            PROVIDERS.assignment_api.create_grant(**args)
        return test_data

    def execute_assignment_cases(self, test_plan, test_data):
        """Execute the test plan, based on the created test_data."""
        def check_results(expected, actual, param_arg_count):
            if param_arg_count == 0:
                # It was an unfiltered call, so default fixture assignments
                # might be polluting our answer - so we take into account
                # how many assignments there were before the test.
                self.assertEqual(
                    len(expected) + test_data['initial_assignment_count'],
                    len(actual))
            else:
                self.assertThat(actual, matchers.HasLength(len(expected)))

            for each_expected in expected:
                expected_assignment = {}
                for param in each_expected:
                    if param == 'inherited_to_projects':
                        expected_assignment[param] = each_expected[param]
                    elif param == 'indirect':
                        # We're expecting the result to contain an indirect
                        # dict with the details how the role came to be placed
                        # on this entity - so convert the key/value pairs of
                        # that dict into real entity references.
                        indirect_term = {}
                        for indirect_param in each_expected[param]:
                            key, value = self._convert_entity_shorthand(
                                indirect_param, each_expected[param],
                                test_data)
                            indirect_term[key] = value
                        expected_assignment[param] = indirect_term
                    else:
                        # Convert a simple shorthand entry into a full
                        # entity reference
                        key, value = self._convert_entity_shorthand(
                            param, each_expected, test_data)
                        expected_assignment[key] = value
                self.assertIn(expected_assignment, actual)

        def convert_group_ids_sourced_from_list(index_list, reference_data):
            value_list = []
            for group_index in index_list:
                value_list.append(
                    reference_data['groups'][group_index]['id'])
            return value_list

        # Go through each test in the array, processing the input params, which
        # we build into an args dict, and then call list_role_assignments. Then
        # check the results against those specified in the test plan.
        for test in test_plan.get('tests', []):
            args = {}
            for param in test['params']:
                if param in ['effective', 'inherited', 'include_subtree']:
                    # Just pass the value into the args
                    args[param] = test['params'][param]
                elif param == 'source_from_group_ids':
                    # Convert the list of indexes into a list of IDs
                    args[param] = convert_group_ids_sourced_from_list(
                        test['params']['source_from_group_ids'], test_data)
                else:
                    # Turn 'entity : 0' into 'entity_id = ac6736ba873d'
                    # where entity in user, group, project or domain
                    key, value = self._convert_entity_shorthand(
                        param, test['params'], test_data)
                    args[key] = value
            results = PROVIDERS.assignment_api.list_role_assignments(**args)
            check_results(test['results'], results, len(args))

    def execute_assignment_plan(self, test_plan):
        """Create entities, assignments and execute the test plan.

        The standard method to call to create entities and assignments and
        execute the tests as specified in the test_plan. The test_data
        dict is returned so that, if required, the caller can execute
        additional manual tests with the entities and assignments created.

        """
        test_data = self.create_entities(test_plan['entities'])
        if 'implied_roles' in test_plan:
            self.create_implied_roles(test_plan['implied_roles'], test_data)
        if 'group_memberships' in test_plan:
            self.create_group_memberships(test_plan['group_memberships'],
                                          test_data)
        if 'assignments' in test_plan:
            test_data = self.create_assignments(test_plan['assignments'],
                                                test_data)
        self.execute_assignment_cases(test_plan, test_data)
        return test_data


class AssignmentTests(AssignmentTestHelperMixin):

    def _get_domain_fixture(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        return domain

    def test_project_add_and_remove_user_role(self):
        user_ids = PROVIDERS.assignment_api.list_user_ids_for_project(
            self.project_bar['id'])
        self.assertNotIn(self.user_two['id'], user_ids)

        PROVIDERS.assignment_api.add_role_to_user_and_project(
            project_id=self.project_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])
        user_ids = PROVIDERS.assignment_api.list_user_ids_for_project(
            self.project_bar['id'])
        self.assertIn(self.user_two['id'], user_ids)

        PROVIDERS.assignment_api.remove_role_from_user_and_project(
            project_id=self.project_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])

        user_ids = PROVIDERS.assignment_api.list_user_ids_for_project(
            self.project_bar['id'])
        self.assertNotIn(self.user_two['id'], user_ids)

    def test_remove_user_role_not_assigned(self):
        # Expect failure if attempt to remove a role that was never assigned to
        # the user.
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.assignment_api.
                          remove_role_from_user_and_project,
                          project_id=self.project_bar['id'],
                          user_id=self.user_two['id'],
                          role_id=self.role_other['id'])

    def test_list_user_ids_for_project(self):
        user_ids = PROVIDERS.assignment_api.list_user_ids_for_project(
            self.project_baz['id'])
        self.assertEqual(2, len(user_ids))
        self.assertIn(self.user_two['id'], user_ids)
        self.assertIn(self.user_badguy['id'], user_ids)

    def test_list_user_ids_for_project_no_duplicates(self):
        # Create user
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        # Create project
        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(
            project_ref['id'], project_ref)
        # Create 2 roles and give user each role in project
        for i in range(2):
            role_ref = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
            PROVIDERS.assignment_api.add_role_to_user_and_project(
                user_id=user_ref['id'],
                project_id=project_ref['id'],
                role_id=role_ref['id'])
        # Get the list of user_ids in project
        user_ids = PROVIDERS.assignment_api.list_user_ids_for_project(
            project_ref['id'])
        # Ensure the user is only returned once
        self.assertEqual(1, len(user_ids))

    def test_get_project_user_ids_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.assignment_api.list_user_ids_for_project,
                          uuid.uuid4().hex)

    def test_list_role_assignments_unfiltered(self):
        """Test unfiltered listing of role assignments."""
        test_plan = {
            # Create a domain, with a user, group & project
            'entities': {'domains': {'users': 1, 'groups': 1, 'projects': 1},
                         'roles': 3},
            # Create a grant of each type (user/group on project/domain)
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'user': 0, 'role': 1, 'project': 0},
                            {'group': 0, 'role': 2, 'domain': 0},
                            {'group': 0, 'role': 2, 'project': 0}],
            'tests': [
                # Check that we get back the 4 assignments
                {'params': {},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'project': 0},
                             {'group': 0, 'role': 2, 'domain': 0},
                             {'group': 0, 'role': 2, 'project': 0}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_role_assignments_filtered_by_role(self):
        """Test listing of role assignments filtered by role ID."""
        test_plan = {
            # Create a user, group & project in the default domain
            'entities': {'domains': {'id': CONF.identity.default_domain_id,
                                     'users': 1, 'groups': 1, 'projects': 1},
                         'roles': 3},
            # Create a grant of each type (user/group on project/domain)
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'user': 0, 'role': 1, 'project': 0},
                            {'group': 0, 'role': 2, 'domain': 0},
                            {'group': 0, 'role': 2, 'project': 0}],
            'tests': [
                # Check that when filtering by role, we only get back those
                # that match
                {'params': {'role': 2},
                 'results': [{'group': 0, 'role': 2, 'domain': 0},
                             {'group': 0, 'role': 2, 'project': 0}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_group_role_assignment(self):
        # When a group role assignment is created and the role assignments are
        # listed then the group role assignment is included in the list.

        test_plan = {
            'entities': {'domains': {'id': CONF.identity.default_domain_id,
                                     'groups': 1, 'projects': 1},
                         'roles': 1},
            'assignments': [{'group': 0, 'role': 0, 'project': 0}],
            'tests': [
                {'params': {},
                 'results': [{'group': 0, 'role': 0, 'project': 0}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_role_assignments_bad_role(self):
        assignment_list = PROVIDERS.assignment_api.list_role_assignments(
            role_id=uuid.uuid4().hex)
        self.assertEqual([], assignment_list)

    def test_list_role_assignments_user_not_found(self):
        def _user_not_found(value):
            raise exception.UserNotFound(user_id=value)

        # Note(knikolla): Patch get_user to return UserNotFound
        # this simulates the possibility of a user being deleted
        # directly in the backend and still having lingering role
        # assignments.
        with mock.patch.object(PROVIDERS.identity_api, 'get_user',
                               _user_not_found):
            assignment_list = PROVIDERS.assignment_api.list_role_assignments(
                include_names=True
            )

        self.assertNotEqual([], assignment_list)
        for assignment in assignment_list:
            if 'user_name' in assignment:
                # Note(knikolla): In the case of a not found user we
                # populate the values with empty strings.
                self.assertEqual('', assignment['user_name'])
                self.assertEqual('', assignment['user_domain_id'])
                self.assertEqual('', assignment['user_domain_name'])

    def test_list_role_assignments_group_not_found(self):
        def _group_not_found(value):
            raise exception.GroupNotFound(group_id=value)

        # Setup
        # 1) Remove any pre-existing assignments so we control what's there
        for a in PROVIDERS.assignment_api.list_role_assignments():
            PROVIDERS.assignment_api.delete_grant(**a)
        # 2) create a group and 2 users in that group
        domain_id = CONF.identity.default_domain_id
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain_id))
        user1 = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain_id))
        user2 = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain_id))
        PROVIDERS.identity_api.add_user_to_group(user1['id'], group['id'])
        PROVIDERS.identity_api.add_user_to_group(user2['id'], group['id'])
        # 3) create a role assignment for the group
        PROVIDERS.assignment_api.create_grant(
            group_id=group['id'],
            domain_id=domain_id,
            role_id=default_fixtures.MEMBER_ROLE_ID)

        num_assignments = len(PROVIDERS.assignment_api.list_role_assignments())
        self.assertEqual(1, num_assignments)

        # Patch get_group to return GroupNotFound, allowing us to confirm
        # that the exception is handled properly when include_names processing
        # attempts to lookup a group that has been deleted in the backend
        with mock.patch.object(PROVIDERS.identity_api, 'get_group',
                               _group_not_found):
            assignment_list = PROVIDERS.assignment_api.list_role_assignments(
                include_names=True
            )

        self.assertEqual(num_assignments, len(assignment_list))
        for assignment in assignment_list:
            includes_group_assignments = False
            if 'group_name' in assignment:
                includes_group_assignments = True
                # Note(knikolla): In the case of a not-found group we
                # populate the values with empty strings.
                self.assertEqual('', assignment['group_name'])
                self.assertEqual('', assignment['group_domain_id'])
                self.assertEqual('', assignment['group_domain_name'])
        self.assertTrue(includes_group_assignments)

        num_effective = len(PROVIDERS.assignment_api.list_role_assignments(
            effective=True))
        self.assertGreater(num_effective, len(assignment_list))

        # Patch list_users_in_group to return GroupNotFound allowing us to
        # confirm that the exception is handled properly when effective
        # processing attempts to lookup users for a group that has been deleted
        # in the backend
        with mock.patch.object(PROVIDERS.identity_api, 'list_users_in_group',
                               _group_not_found):
            assignment_list = PROVIDERS.assignment_api.list_role_assignments(
                effective=True
            )

        self.assertGreater(num_effective, len(assignment_list))

        # cleanup
        PROVIDERS.assignment_api.delete_grant(
            group_id=group['id'],
            domain_id=domain_id,
            role_id=default_fixtures.MEMBER_ROLE_ID)
        # TODO(edmondsw) should cleanup users/groups as well, but that raises
        # LDAP read-only issues

    def test_add_duplicate_role_grant(self):
        roles_ref = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.project_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.project_bar['id'], self.role_admin['id'])
        self.assertRaises(
            exception.Conflict,
            PROVIDERS.assignment_api.add_role_to_user_and_project,
            self.user_foo['id'],
            self.project_bar['id'],
            self.role_admin['id']
        )

    def test_get_role_by_user_and_project_with_user_in_group(self):
        """Test for get role by user and project, user was added into a group.

        Test Plan:

        - Create a user, a project & a group, add this user to group
        - Create roles and grant them to user and project
        - Check the role list get by the user and project was as expected

        """
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)

        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group)['id']
        PROVIDERS.identity_api.add_user_to_group(user_ref['id'], group_id)

        role_ref_list = []
        for i in range(2):
            role_ref = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
            role_ref_list.append(role_ref)

            PROVIDERS.assignment_api.add_role_to_user_and_project(
                user_id=user_ref['id'],
                project_id=project_ref['id'],
                role_id=role_ref['id'])

        role_list = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            user_ref['id'],
            project_ref['id'])

        self.assertEqual(set([r['id'] for r in role_ref_list]),
                         set(role_list))

    def test_get_role_by_user_and_project(self):
        roles_ref = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.project_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.project_bar['id'], self.role_admin['id'])
        roles_ref = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.project_bar['id'])
        self.assertIn(self.role_admin['id'], roles_ref)
        self.assertNotIn(default_fixtures.MEMBER_ROLE_ID, roles_ref)

        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.project_bar['id'],
            default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.project_bar['id'])
        self.assertIn(self.role_admin['id'], roles_ref)
        self.assertIn(default_fixtures.MEMBER_ROLE_ID, roles_ref)

    def test_get_role_by_trustor_and_project(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)
        role = self._create_role(domain_id=new_domain['id'])

        # Now create the grants (roles are defined in default_fixtures)
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'],
            project_id=new_project['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'],
            domain_id=new_domain['id'],
            role_id=role['id'],
            inherited_to_projects=True)

        roles_ids = PROVIDERS.assignment_api.get_roles_for_trustor_and_project(
            new_user['id'], new_project['id'])
        self.assertEqual(2, len(roles_ids))
        self.assertIn(self.role_member['id'], roles_ids)
        self.assertIn(role['id'], roles_ids)

    def test_get_roles_for_user_and_domain(self):
        """Test for getting roles for user on a domain.

        Test Plan:

        - Create a domain, with 2 users
        - Check no roles yet exit
        - Give user1 two roles on the domain, user2 one role
        - Get roles on user1 and the domain - maybe sure we only
          get back the 2 roles on user1
        - Delete both roles from user1
        - Check we get no roles back for user1 on domain

        """
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        new_user1 = unit.new_user_ref(domain_id=new_domain['id'])
        new_user1 = PROVIDERS.identity_api.create_user(new_user1)
        new_user2 = unit.new_user_ref(domain_id=new_domain['id'])
        new_user2 = PROVIDERS.identity_api.create_user(new_user2)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=new_user1['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        # Now create the grants (roles are defined in default_fixtures)
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user1['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user1['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.OTHER_ROLE_ID)
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user2['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.ADMIN_ROLE_ID)
        # Read back the roles for user1 on domain
        roles_ids = PROVIDERS.assignment_api.get_roles_for_user_and_domain(
            new_user1['id'], new_domain['id'])
        self.assertEqual(2, len(roles_ids))
        self.assertIn(self.role_member['id'], roles_ids)
        self.assertIn(self.role_other['id'], roles_ids)

        # Now delete both grants for user1
        PROVIDERS.assignment_api.delete_grant(
            user_id=new_user1['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        PROVIDERS.assignment_api.delete_grant(
            user_id=new_user1['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.OTHER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=new_user1['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))

    def test_get_roles_for_user_and_domain_returns_not_found(self):
        """Test errors raised when getting roles for user on a domain.

        Test Plan:

        - Check non-existing user gives UserNotFound
        - Check non-existing domain gives DomainNotFound

        """
        new_domain = self._get_domain_fixture()
        new_user1 = unit.new_user_ref(domain_id=new_domain['id'])
        new_user1 = PROVIDERS.identity_api.create_user(new_user1)

        self.assertRaises(
            exception.UserNotFound,
            PROVIDERS.assignment_api.get_roles_for_user_and_domain,
            uuid.uuid4().hex,
            new_domain['id']
        )

        self.assertRaises(
            exception.DomainNotFound,
            PROVIDERS.assignment_api.get_roles_for_user_and_domain,
            new_user1['id'],
            uuid.uuid4().hex
        )

    def test_get_roles_for_user_and_project_returns_not_found(self):
        self.assertRaises(
            exception.UserNotFound,
            PROVIDERS.assignment_api.get_roles_for_user_and_project,
            uuid.uuid4().hex,
            self.project_bar['id']
        )

        self.assertRaises(
            exception.ProjectNotFound,
            PROVIDERS.assignment_api.get_roles_for_user_and_project,
            self.user_foo['id'],
            uuid.uuid4().hex
        )

    def test_add_role_to_user_and_project_returns_not_found(self):
        self.assertRaises(
            exception.ProjectNotFound,
            PROVIDERS.assignment_api.add_role_to_user_and_project,
            self.user_foo['id'],
            uuid.uuid4().hex,
            self.role_admin['id']
        )

        self.assertRaises(
            exception.RoleNotFound,
            PROVIDERS.assignment_api.add_role_to_user_and_project,
            self.user_foo['id'],
            self.project_bar['id'],
            uuid.uuid4().hex
        )

    def test_add_role_to_user_and_project_no_user(self):
        # If add_role_to_user_and_project and the user doesn't exist, then
        # no error.
        user_id_not_exist = uuid.uuid4().hex
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user_id_not_exist, self.project_bar['id'], self.role_admin['id'])

    def test_remove_role_from_user_and_project(self):
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.project_bar['id'],
            default_fixtures.MEMBER_ROLE_ID)
        PROVIDERS.assignment_api.remove_role_from_user_and_project(
            self.user_foo['id'],
            self.project_bar['id'],
            default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.project_bar['id'])
        self.assertNotIn(default_fixtures.MEMBER_ROLE_ID, roles_ref)
        self.assertRaises(exception.NotFound,
                          PROVIDERS.assignment_api.
                          remove_role_from_user_and_project,
                          self.user_foo['id'],
                          self.project_bar['id'],
                          default_fixtures.MEMBER_ROLE_ID)

    def test_get_role_grant_by_user_and_project(self):
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.project_bar['id'])
        self.assertEqual(1, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            user_id=self.user_foo['id'], project_id=self.project_bar['id'],
            role_id=self.role_admin['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.project_bar['id'])
        self.assertIn(self.role_admin['id'],
                      [role_ref['id'] for role_ref in roles_ref])

        PROVIDERS.assignment_api.create_grant(
            user_id=self.user_foo['id'],
            project_id=self.project_bar['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.project_bar['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(self.role_admin['id'], roles_ref_ids)
        self.assertIn(default_fixtures.MEMBER_ROLE_ID, roles_ref_ids)

    def test_remove_role_grant_from_user_and_project(self):
        PROVIDERS.assignment_api.create_grant(
            user_id=self.user_foo['id'],
            project_id=self.project_baz['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.project_baz['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        PROVIDERS.assignment_api.delete_grant(
            user_id=self.user_foo['id'],
            project_id=self.project_baz['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.project_baz['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.project_baz['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_get_role_assignment_by_project_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.check_grant_role_id,
                          user_id=self.user_foo['id'],
                          project_id=self.project_baz['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.check_grant_role_id,
                          group_id=uuid.uuid4().hex,
                          project_id=self.project_baz['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_get_role_assignment_by_domain_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.check_grant_role_id,
                          user_id=self.user_foo['id'],
                          domain_id=CONF.identity.default_domain_id,
                          role_id=default_fixtures.MEMBER_ROLE_ID)

        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.check_grant_role_id,
                          group_id=uuid.uuid4().hex,
                          domain_id=CONF.identity.default_domain_id,
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_del_role_assignment_by_project_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.project_baz['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          group_id=uuid.uuid4().hex,
                          project_id=self.project_baz['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_del_role_assignment_by_domain_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          domain_id=CONF.identity.default_domain_id,
                          role_id=default_fixtures.MEMBER_ROLE_ID)

        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          group_id=uuid.uuid4().hex,
                          domain_id=CONF.identity.default_domain_id,
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_get_and_remove_role_grant_by_group_and_project(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.project_bar['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'],
            project_id=self.project_bar['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.project_bar['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        PROVIDERS.assignment_api.delete_grant(
            group_id=new_group['id'],
            project_id=self.project_bar['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.project_bar['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          project_id=self.project_bar['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_get_and_remove_role_grant_by_group_and_domain(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )

        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))

        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)

        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        PROVIDERS.assignment_api.delete_grant(
            group_id=new_group['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_get_and_remove_correct_role_grant_from_a_mix(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_group2 = unit.new_group_ref(domain_id=new_domain['id'])
        new_group2 = PROVIDERS.identity_api.create_group(new_group2)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        new_user2 = unit.new_user_ref(domain_id=new_domain['id'])
        new_user2 = PROVIDERS.identity_api.create_user(new_user2)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )
        # First check we have no grants
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        # Now add the grant we are going to test for, and some others as
        # well just to make sure we get back the right one
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)

        PROVIDERS.assignment_api.create_grant(
            group_id=new_group2['id'], domain_id=new_domain['id'],
            role_id=self.role_admin['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user2['id'], domain_id=new_domain['id'],
            role_id=self.role_admin['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'], project_id=new_project['id'],
            role_id=self.role_admin['id']
        )

        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        PROVIDERS.assignment_api.delete_grant(
            group_id=new_group['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_get_and_remove_role_grant_by_user_and_domain(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        PROVIDERS.assignment_api.delete_grant(
            user_id=new_user['id'],
            domain_id=new_domain['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          user_id=new_user['id'],
                          domain_id=new_domain['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_get_and_remove_role_grant_by_group_and_cross_domain(self):
        group1_domain1_role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            group1_domain1_role['id'], group1_domain1_role
        )
        group1_domain2_role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            group1_domain2_role['id'], group1_domain2_role
        )
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain1['id'],
            role_id=group1_domain1_role['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain2['id'],
            role_id=group1_domain2_role['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(group1_domain1_role, roles_ref[0])
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(group1_domain2_role, roles_ref[0])

        PROVIDERS.assignment_api.delete_grant(
            group_id=group1['id'], domain_id=domain2['id'],
            role_id=group1_domain2_role['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          group_id=group1['id'],
                          domain_id=domain2['id'],
                          role_id=group1_domain2_role['id'])

    def test_get_and_remove_role_grant_by_user_and_cross_domain(self):
        user1_domain1_role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            user1_domain1_role['id'], user1_domain1_role
        )
        user1_domain2_role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            user1_domain2_role['id'], user1_domain2_role
        )
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'],
            role_id=user1_domain1_role['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain2['id'],
            role_id=user1_domain2_role['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(user1_domain1_role, roles_ref[0])
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(user1_domain2_role, roles_ref[0])

        PROVIDERS.assignment_api.delete_grant(
            user_id=user1['id'], domain_id=domain2['id'],
            role_id=user1_domain2_role['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          user_id=user1['id'],
                          domain_id=domain2['id'],
                          role_id=user1_domain2_role['id'])

    def test_role_grant_by_group_and_cross_domain_project(self):
        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role2['id'], role2)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        project1 = unit.new_project_ref(domain_id=domain2['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role2['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        PROVIDERS.assignment_api.delete_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role1['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        self.assertDictEqual(role2, roles_ref[0])

    def test_role_grant_by_user_and_cross_domain_project(self):
        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role2['id'], role2)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        project1 = unit.new_project_ref(domain_id=domain2['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'], role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'], role_id=role2['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        PROVIDERS.assignment_api.delete_grant(
            user_id=user1['id'], project_id=project1['id'], role_id=role1['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        self.assertDictEqual(role2, roles_ref[0])

    def test_delete_user_grant_no_user(self):
        # Can delete a grant where the user doesn't exist.
        role = unit.new_role_ref()
        role_id = role['id']
        PROVIDERS.role_api.create_role(role_id, role)

        user_id = uuid.uuid4().hex

        PROVIDERS.assignment_api.create_grant(
            role_id, user_id=user_id, project_id=self.project_bar['id']
        )

        PROVIDERS.assignment_api.delete_grant(
            role_id, user_id=user_id, project_id=self.project_bar['id']
        )

    def test_delete_group_grant_no_group(self):
        # Can delete a grant where the group doesn't exist.
        role = unit.new_role_ref()
        role_id = role['id']
        PROVIDERS.role_api.create_role(role_id, role)

        group_id = uuid.uuid4().hex

        PROVIDERS.assignment_api.create_grant(
            role_id, group_id=group_id, project_id=self.project_bar['id']
        )

        PROVIDERS.assignment_api.delete_grant(
            role_id, group_id=group_id, project_id=self.project_bar['id']
        )

    def test_grant_crud_throws_exception_if_invalid_role(self):
        """Ensure RoleNotFound thrown if role does not exist."""
        def assert_role_not_found_exception(f, **kwargs):
            self.assertRaises(exception.RoleNotFound, f,
                              role_id=uuid.uuid4().hex, **kwargs)

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_resp = PROVIDERS.identity_api.create_user(user)
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_resp = PROVIDERS.identity_api.create_group(group)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_resp = PROVIDERS.resource_api.create_project(
            project['id'], project
        )

        for manager_call in [PROVIDERS.assignment_api.create_grant,
                             PROVIDERS.assignment_api.get_grant]:
            assert_role_not_found_exception(
                manager_call,
                user_id=user_resp['id'], project_id=project_resp['id'])
            assert_role_not_found_exception(
                manager_call,
                group_id=group_resp['id'], project_id=project_resp['id'])
            assert_role_not_found_exception(
                manager_call,
                user_id=user_resp['id'],
                domain_id=CONF.identity.default_domain_id)
            assert_role_not_found_exception(
                manager_call,
                group_id=group_resp['id'],
                domain_id=CONF.identity.default_domain_id)

        assert_role_not_found_exception(
            PROVIDERS.assignment_api.delete_grant,
            user_id=user_resp['id'], project_id=project_resp['id'])
        assert_role_not_found_exception(
            PROVIDERS.assignment_api.delete_grant,
            group_id=group_resp['id'], project_id=project_resp['id'])
        assert_role_not_found_exception(
            PROVIDERS.assignment_api.delete_grant,
            user_id=user_resp['id'],
            domain_id=CONF.identity.default_domain_id)
        assert_role_not_found_exception(
            PROVIDERS.assignment_api.delete_grant,
            group_id=group_resp['id'],
            domain_id=CONF.identity.default_domain_id)

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        role_list = []
        for _ in range(10):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain1['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)

        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group2['id']
        )

        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'],
            role_id=role_list[0]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'],
            role_id=role_list[1]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain1['id'],
            role_id=role_list[2]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain1['id'],
            role_id=role_list[3]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'],
            role_id=role_list[4]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'],
            role_id=role_list[5]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role_list[6]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role_list[7]['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'], domain_id=domain1['id']
        )
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[0], roles_ref)
        self.assertIn(role_list[1], roles_ref)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'], domain_id=domain1['id']
        )
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[2], roles_ref)
        self.assertIn(role_list[3], roles_ref)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'], project_id=project1['id']
        )
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[4], roles_ref)
        self.assertIn(role_list[5], roles_ref)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'], project_id=project1['id']
        )
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[6], roles_ref)
        self.assertIn(role_list[7], roles_ref)

        # Now test the alternate way of getting back lists of grants,
        # where user and group roles are combined.  These should match
        # the above results.
        combined_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user1['id'], project1['id']
            )
        )
        self.assertEqual(4, len(combined_list))
        self.assertIn(role_list[4]['id'], combined_list)
        self.assertIn(role_list[5]['id'], combined_list)
        self.assertIn(role_list[6]['id'], combined_list)
        self.assertIn(role_list[7]['id'], combined_list)

        combined_role_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_domain(
                user1['id'], domain1['id']
            )
        )
        self.assertEqual(4, len(combined_role_list))
        self.assertIn(role_list[0]['id'], combined_role_list)
        self.assertIn(role_list[1]['id'], combined_role_list)
        self.assertIn(role_list[2]['id'], combined_role_list)
        self.assertIn(role_list[3]['id'], combined_role_list)

    def test_multi_group_grants_on_project_domain(self):
        """Test multiple group roles for user on project and domain.

        Test Plan:

        - Create 6 roles
        - Create a domain, with a project, user and two groups
        - Make the user a member of both groups
        - Check no roles yet exit
        - Assign a role to each user and both groups on both the
          project and domain
        - Get a list of effective roles for the user on both the
          project and domain, checking we get back the correct three
          roles

        """
        role_list = []
        for _ in range(6):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain1['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)

        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group2['id']
        )

        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'],
            role_id=role_list[0]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain1['id'],
            role_id=role_list[1]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], domain_id=domain1['id'],
            role_id=role_list[2]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'],
            role_id=role_list[3]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role_list[4]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], project_id=project1['id'],
            role_id=role_list[5]['id']
        )

        # Read by the roles, ensuring we get the correct 3 roles for
        # both project and domain
        combined_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user1['id'], project1['id']
            )
        )
        self.assertEqual(3, len(combined_list))
        self.assertIn(role_list[3]['id'], combined_list)
        self.assertIn(role_list[4]['id'], combined_list)
        self.assertIn(role_list[5]['id'], combined_list)

        combined_role_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_domain(
                user1['id'], domain1['id']
            )
        )
        self.assertEqual(3, len(combined_role_list))
        self.assertIn(role_list[0]['id'], combined_role_list)
        self.assertIn(role_list[1]['id'], combined_role_list)
        self.assertIn(role_list[2]['id'], combined_role_list)

    def test_delete_role_with_user_and_group_grants(self):
        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'], role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'], role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain1['id'], role_id=role1['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        PROVIDERS.role_api.delete_role(role1['id'])
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))

    def test_list_role_assignment_by_domain(self):
        """Test listing of role assignment filtered by domain."""
        test_plan = {
            # A domain with 3 users, 1 group, a spoiler domain and 2 roles.
            'entities': {'domains': [{'users': 3, 'groups': 1}, 1],
                         'roles': 2},
            # Users 1 & 2 are in the group
            'group_memberships': [{'group': 0, 'users': [1, 2]}],
            # Assign a role for user 0 and the group
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'group': 0, 'role': 1, 'domain': 0}],
            'tests': [
                # List all effective assignments for domain[0].
                # Should get one direct user role and user roles for each of
                # the users in the group.
                {'params': {'domain': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 1, 'role': 1, 'domain': 0,
                              'indirect': {'group': 0}},
                             {'user': 2, 'role': 1, 'domain': 0,
                              'indirect': {'group': 0}}
                             ]},
                # Using domain[1] should return nothing
                {'params': {'domain': 1, 'effective': True},
                 'results': []},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_role_assignment_by_user_with_domain_group_roles(self):
        """Test listing assignments by user, with group roles on a domain."""
        test_plan = {
            # A domain with 3 users, 3 groups, a spoiler domain
            # plus 3 roles.
            'entities': {'domains': [{'users': 3, 'groups': 3}, 1],
                         'roles': 3},
            # Users 1 & 2 are in the group 0, User 1 also in group 1
            'group_memberships': [{'group': 0, 'users': [0, 1]},
                                  {'group': 1, 'users': [0]}],
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'group': 0, 'role': 1, 'domain': 0},
                            {'group': 1, 'role': 2, 'domain': 0},
                            # ...and two spoiler assignments
                            {'user': 1, 'role': 1, 'domain': 0},
                            {'group': 2, 'role': 2, 'domain': 0}],
            'tests': [
                # List all effective assignments for user[0].
                # Should get one direct user role and a user roles for each of
                # groups 0 and 1
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'domain': 0,
                              'indirect': {'group': 0}},
                             {'user': 0, 'role': 2, 'domain': 0,
                              'indirect': {'group': 1}}
                             ]},
                # Adding domain[0] as a filter should return the same data
                {'params': {'user': 0, 'domain': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'domain': 0,
                              'indirect': {'group': 0}},
                             {'user': 0, 'role': 2, 'domain': 0,
                              'indirect': {'group': 1}}
                             ]},
                # Using domain[1] should return nothing
                {'params': {'user': 0, 'domain': 1, 'effective': True},
                 'results': []},
                # Using user[2] should return nothing
                {'params': {'user': 2, 'domain': 0, 'effective': True},
                 'results': []},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_role_assignment_using_sourced_groups(self):
        """Test listing assignments when restricted by source groups."""
        test_plan = {
            # The default domain with 3 users, 3 groups, 3 projects,
            # plus 3 roles.
            'entities': {'domains': {'id': CONF.identity.default_domain_id,
                                     'users': 3, 'groups': 3, 'projects': 3},
                         'roles': 3},
            # Users 0 & 1 are in the group 0, User 0 also in group 1
            'group_memberships': [{'group': 0, 'users': [0, 1]},
                                  {'group': 1, 'users': [0]}],
            # Spread the assignments around - we want to be able to show that
            # if sourced by group, assignments from other sources are excluded
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'group': 0, 'role': 1, 'project': 1},
                            {'group': 1, 'role': 2, 'project': 0},
                            {'group': 1, 'role': 2, 'project': 1},
                            {'user': 2, 'role': 1, 'project': 1},
                            {'group': 2, 'role': 2, 'project': 2}
                            ],
            'tests': [
                # List all effective assignments sourced from groups 0 and 1
                {'params': {'source_from_group_ids': [0, 1],
                            'effective': True},
                 'results': [{'group': 0, 'role': 1, 'project': 1},
                             {'group': 1, 'role': 2, 'project': 0},
                             {'group': 1, 'role': 2, 'project': 1}
                             ]},
                # Adding a role a filter should further restrict the entries
                {'params': {'source_from_group_ids': [0, 1], 'role': 2,
                            'effective': True},
                 'results': [{'group': 1, 'role': 2, 'project': 0},
                             {'group': 1, 'role': 2, 'project': 1}
                             ]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_role_assignment_using_sourced_groups_with_domains(self):
        """Test listing domain assignments when restricted by source groups."""
        test_plan = {
            # A domain with 3 users, 3 groups, 3 projects, a second domain,
            # plus 3 roles.
            'entities': {'domains': [{'users': 3, 'groups': 3, 'projects': 3},
                                     1],
                         'roles': 3},
            # Users 0 & 1 are in the group 0, User 0 also in group 1
            'group_memberships': [{'group': 0, 'users': [0, 1]},
                                  {'group': 1, 'users': [0]}],
            # Spread the assignments around - we want to be able to show that
            # if sourced by group, assignments from other sources are excluded
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'group': 0, 'role': 1, 'domain': 1},
                            {'group': 1, 'role': 2, 'project': 0},
                            {'group': 1, 'role': 2, 'project': 1},
                            {'user': 2, 'role': 1, 'project': 1},
                            {'group': 2, 'role': 2, 'project': 2}
                            ],
            'tests': [
                # List all effective assignments sourced from groups 0 and 1
                {'params': {'source_from_group_ids': [0, 1],
                            'effective': True},
                 'results': [{'group': 0, 'role': 1, 'domain': 1},
                             {'group': 1, 'role': 2, 'project': 0},
                             {'group': 1, 'role': 2, 'project': 1}
                             ]},
                # Adding a role a filter should further restrict the entries
                {'params': {'source_from_group_ids': [0, 1], 'role': 1,
                            'effective': True},
                 'results': [{'group': 0, 'role': 1, 'domain': 1},
                             ]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_role_assignment_fails_with_userid_and_source_groups(self):
        """Show we trap this unsupported internal combination of params."""
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        self.assertRaises(exception.UnexpectedError,
                          PROVIDERS.assignment_api.list_role_assignments,
                          effective=True,
                          user_id=self.user_foo['id'],
                          source_from_group_ids=[group['id']])

    def test_list_user_project_ids_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.assignment_api.list_projects_for_user,
                          uuid.uuid4().hex)

    def test_delete_user_with_project_association(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'], self.project_bar['id'], role_member['id']
        )
        PROVIDERS.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.assignment_api.list_projects_for_user,
                          user['id'])

    def test_delete_user_with_project_roles(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'],
            self.project_bar['id'],
            self.role_member['id'])
        PROVIDERS.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.assignment_api.list_projects_for_user,
                          user['id'])

    def test_delete_role_returns_not_found(self):
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.delete_role,
                          uuid.uuid4().hex)

    def test_delete_project_with_role_assignments(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            project['id'],
            default_fixtures.MEMBER_ROLE_ID)
        PROVIDERS.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.assignment_api.list_user_ids_for_project,
                          project['id'])

    def test_delete_role_check_role_grant(self):
        role = unit.new_role_ref()
        alt_role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        PROVIDERS.role_api.create_role(alt_role['id'], alt_role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.project_bar['id'], role['id'])
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.project_bar['id'], alt_role['id'])
        PROVIDERS.role_api.delete_role(role['id'])
        roles_ref = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.project_bar['id'])
        self.assertNotIn(role['id'], roles_ref)
        self.assertIn(alt_role['id'], roles_ref)

    def test_list_projects_for_user(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user1['id']
        )
        self.assertEqual(0, len(user_projects))
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_baz['id'],
            role_id=self.role_member['id']
        )
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user1['id']
        )
        self.assertEqual(2, len(user_projects))

    def test_list_projects_for_user_with_grants(self):
        # Create two groups each with a role on a different project, and
        # make user1 a member of both groups.  Both these new projects
        # should now be included, along with any direct user grants.
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        PROVIDERS.identity_api.add_user_to_group(user1['id'], group1['id'])
        PROVIDERS.identity_api.add_user_to_group(user1['id'], group2['id'])

        # Create 3 grants, one user grant, the other two as group grants
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=self.role_admin['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], project_id=project2['id'],
            role_id=self.role_admin['id']
        )
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user1['id']
        )
        self.assertEqual(3, len(user_projects))

    def test_create_grant_no_user(self):
        # If call create_grant with a user that doesn't exist, doesn't fail.
        PROVIDERS.assignment_api.create_grant(
            self.role_other['id'],
            user_id=uuid.uuid4().hex,
            project_id=self.project_bar['id'])

    def test_create_grant_no_group(self):
        # If call create_grant with a group that doesn't exist, doesn't fail.
        PROVIDERS.assignment_api.create_grant(
            self.role_other['id'],
            group_id=uuid.uuid4().hex,
            project_id=self.project_bar['id'])

    def test_delete_group_removes_role_assignments(self):
        # When a group is deleted any role assignments for the group are
        # removed.

        def get_member_assignments():
            assignments = PROVIDERS.assignment_api.list_role_assignments()
            return ([x for x in assignments if x['role_id'] ==
                    default_fixtures.MEMBER_ROLE_ID])

        orig_member_assignments = get_member_assignments()

        # Create a group.
        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = PROVIDERS.identity_api.create_group(new_group)

        # Create a project.
        new_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)

        # Assign a role to the group.
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'], project_id=new_project['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)

        # Delete the group.
        PROVIDERS.identity_api.delete_group(new_group['id'])

        # Check that the role assignment for the group is gone
        member_assignments = get_member_assignments()

        self.assertThat(member_assignments,
                        matchers.Equals(orig_member_assignments))

    def test_get_roles_for_groups_on_domain(self):
        """Test retrieving group domain roles.

        Test Plan:

        - Create a domain, three groups and three roles
        - Assign one an inherited and the others a non-inherited group role
          to the domain
        - Ensure that only the non-inherited roles are returned on the domain

        """
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        group_list = []
        group_id_list = []
        role_list = []
        for _ in range(3):
            group = unit.new_group_ref(domain_id=domain1['id'])
            group = PROVIDERS.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one is inherited
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[0]['id'], domain_id=domain1['id'],
            role_id=role_list[0]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[1]['id'], domain_id=domain1['id'],
            role_id=role_list[1]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[2]['id'], domain_id=domain1['id'],
            role_id=role_list[2]['id'], inherited_to_projects=True
        )

        # Now get the effective roles for the groups on the domain project. We
        # shouldn't get back the inherited role.

        role_refs = PROVIDERS.assignment_api.get_roles_for_groups(
            group_id_list, domain_id=domain1['id'])

        self.assertThat(role_refs, matchers.HasLength(2))
        self.assertIn(role_list[0], role_refs)
        self.assertIn(role_list[1], role_refs)

    def test_get_roles_for_groups_on_project(self):
        """Test retrieving group project roles.

        Test Plan:

        - Create two domains, two projects, six groups and six roles
        - Project1 is in Domain1, Project2 is in Domain2
        - Domain2/Project2 are spoilers
        - Assign a different direct group role to each project as well
          as both an inherited and non-inherited role to each domain
        - Get the group roles for Project 1 - depending on whether we have
          enabled inheritance, we should either get back just the direct role
          or both the direct one plus the inherited domain role from Domain 1

        """
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain2['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        group_list = []
        group_id_list = []
        role_list = []
        for _ in range(6):
            group = unit.new_group_ref(domain_id=domain1['id'])
            group = PROVIDERS.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one inherited and one non-inherited on Domain1,
        # plus one on Project1
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[0]['id'], domain_id=domain1['id'],
            role_id=role_list[0]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[1]['id'], domain_id=domain1['id'],
            role_id=role_list[1]['id'], inherited_to_projects=True
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[2]['id'], project_id=project1['id'],
            role_id=role_list[2]['id']
        )

        # ...and a duplicate set of spoiler assignments to Domain2/Project2
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[3]['id'], domain_id=domain2['id'],
            role_id=role_list[3]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[4]['id'], domain_id=domain2['id'],
            role_id=role_list[4]['id'], inherited_to_projects=True
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[5]['id'], project_id=project2['id'],
            role_id=role_list[5]['id']
        )

        # With inheritance on, we should also get back the inherited role from
        # its owning domain.

        role_refs = PROVIDERS.assignment_api.get_roles_for_groups(
            group_id_list, project_id=project1['id'])

        self.assertThat(role_refs, matchers.HasLength(2))
        self.assertIn(role_list[1], role_refs)
        self.assertIn(role_list[2], role_refs)

    def test_list_domains_for_groups(self):
        """Test retrieving domains for a list of groups.

        Test Plan:

        - Create three domains, three groups and one role
        - Assign a non-inherited group role to two domains, and an inherited
          group role to the third
        - Ensure only the domains with non-inherited roles are returned

        """
        domain_list = []
        group_list = []
        group_id_list = []
        for _ in range(3):
            domain = unit.new_domain_ref()
            PROVIDERS.resource_api.create_domain(domain['id'], domain)
            domain_list.append(domain)

            group = unit.new_group_ref(domain_id=domain['id'])
            group = PROVIDERS.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)

        # Assign the roles - one is inherited
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[0]['id'], domain_id=domain_list[0]['id'],
            role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[1]['id'], domain_id=domain_list[1]['id'],
            role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[2]['id'], domain_id=domain_list[2]['id'],
            role_id=role1['id'], inherited_to_projects=True
        )

        # Now list the domains that have roles for any of the 3 groups
        # We shouldn't get back domain[2] since that had an inherited role.

        domain_refs = (
            PROVIDERS.assignment_api.list_domains_for_groups(group_id_list))

        self.assertThat(domain_refs, matchers.HasLength(2))
        self.assertIn(domain_list[0], domain_refs)
        self.assertIn(domain_list[1], domain_refs)

    def test_list_projects_for_groups(self):
        """Test retrieving projects for a list of groups.

        Test Plan:

        - Create two domains, four projects, seven groups and seven roles
        - Project1-3 are in Domain1, Project4 is in Domain2
        - Domain2/Project4 are spoilers
        - Project1 and 2 have direct group roles, Project3 has no direct
          roles but should inherit a group role from Domain1
        - Get the projects for the group roles that are assigned to Project1
          Project2 and the inherited one on Domain1. Depending on whether we
          have enabled inheritance, we should either get back just the projects
          with direct roles (Project 1 and 2) or also Project3 due to its
          inherited role from Domain1.

        """
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        project1 = PROVIDERS.resource_api.create_project(
            project1['id'], project1
        )
        project2 = unit.new_project_ref(domain_id=domain1['id'])
        project2 = PROVIDERS.resource_api.create_project(
            project2['id'], project2
        )
        project3 = unit.new_project_ref(domain_id=domain1['id'])
        project3 = PROVIDERS.resource_api.create_project(
            project3['id'], project3
        )
        project4 = unit.new_project_ref(domain_id=domain2['id'])
        project4 = PROVIDERS.resource_api.create_project(
            project4['id'], project4
        )
        group_list = []
        role_list = []
        for _ in range(7):
            group = unit.new_group_ref(domain_id=domain1['id'])
            group = PROVIDERS.identity_api.create_group(group)
            group_list.append(group)

            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one inherited and one non-inherited on Domain1,
        # plus one on Project1 and Project2
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[0]['id'], domain_id=domain1['id'],
            role_id=role_list[0]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[1]['id'], domain_id=domain1['id'],
            role_id=role_list[1]['id'], inherited_to_projects=True
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[2]['id'], project_id=project1['id'],
            role_id=role_list[2]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[3]['id'], project_id=project2['id'],
            role_id=role_list[3]['id']
        )

        # ...and a few of spoiler assignments to Domain2/Project4
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[4]['id'], domain_id=domain2['id'],
            role_id=role_list[4]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[5]['id'], domain_id=domain2['id'],
            role_id=role_list[5]['id'], inherited_to_projects=True
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group_list[6]['id'], project_id=project4['id'],
            role_id=role_list[6]['id']
        )

        group_id_list = [group_list[1]['id'], group_list[2]['id'],
                         group_list[3]['id']]

        # With inheritance on, we should also get back the Project3 due to the
        # inherited role from its owning domain.
        project_refs = (
            PROVIDERS.assignment_api.list_projects_for_groups(group_id_list))

        self.assertThat(project_refs, matchers.HasLength(3))
        self.assertIn(project1, project_refs)
        self.assertIn(project2, project_refs)
        self.assertIn(project3, project_refs)

    def test_update_role_no_name(self):
        # A user can update a role and not include the name.

        # description is picked just because it's not name.
        PROVIDERS.role_api.update_role(
            self.role_member['id'], {'description': uuid.uuid4().hex}
        )
        # If the previous line didn't raise an exception then the test passes.

    def test_update_role_same_name(self):
        # A user can update a role and set the name to be the same as it was.

        PROVIDERS.role_api.update_role(
            self.role_member['id'], {'name': self.role_member['name']}
        )
        # If the previous line didn't raise an exception then the test passes.

    def _test_list_role_assignment_containing_names(self, domain_role=False):
        # Create Refs
        new_domain = self._get_domain_fixture()
        if domain_role:
            new_role = unit.new_role_ref(domain_id=new_domain['id'])
        else:
            new_role = unit.new_role_ref()
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        # Create entities
        new_role = PROVIDERS.role_api.create_role(new_role['id'], new_role)
        new_user = PROVIDERS.identity_api.create_user(new_user)
        new_group = PROVIDERS.identity_api.create_group(new_group)
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'], project_id=new_project['id'],
            role_id=new_role['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'], project_id=new_project['id'],
            role_id=new_role['id']
        )
        PROVIDERS.assignment_api.create_grant(
            domain_id=new_domain['id'], user_id=new_user['id'],
            role_id=new_role['id']
        )
        # Get the created assignments with the include_names flag
        _asgmt_prj = PROVIDERS.assignment_api.list_role_assignments(
            user_id=new_user['id'],
            project_id=new_project['id'],
            include_names=True)
        _asgmt_grp = PROVIDERS.assignment_api.list_role_assignments(
            group_id=new_group['id'],
            project_id=new_project['id'],
            include_names=True)
        _asgmt_dmn = PROVIDERS.assignment_api.list_role_assignments(
            domain_id=new_domain['id'],
            user_id=new_user['id'],
            include_names=True)
        # Make sure we can get back the correct number of assignments
        self.assertThat(_asgmt_prj, matchers.HasLength(1))
        self.assertThat(_asgmt_grp, matchers.HasLength(1))
        self.assertThat(_asgmt_dmn, matchers.HasLength(1))
        # get the first assignment
        first_asgmt_prj = _asgmt_prj[0]
        first_asgmt_grp = _asgmt_grp[0]
        first_asgmt_dmn = _asgmt_dmn[0]
        # Assert the names are correct in the project response
        self.assertEqual(new_project['name'],
                         first_asgmt_prj['project_name'])
        self.assertEqual(new_project['domain_id'],
                         first_asgmt_prj['project_domain_id'])
        self.assertEqual(new_user['name'],
                         first_asgmt_prj['user_name'])
        self.assertEqual(new_user['domain_id'],
                         first_asgmt_prj['user_domain_id'])
        self.assertEqual(new_role['name'],
                         first_asgmt_prj['role_name'])
        if domain_role:
            self.assertEqual(new_role['domain_id'],
                             first_asgmt_prj['role_domain_id'])
        # Assert the names are correct in the group response
        self.assertEqual(new_group['name'],
                         first_asgmt_grp['group_name'])
        self.assertEqual(new_group['domain_id'],
                         first_asgmt_grp['group_domain_id'])
        self.assertEqual(new_project['name'],
                         first_asgmt_grp['project_name'])
        self.assertEqual(new_project['domain_id'],
                         first_asgmt_grp['project_domain_id'])
        self.assertEqual(new_role['name'],
                         first_asgmt_grp['role_name'])
        if domain_role:
            self.assertEqual(new_role['domain_id'],
                             first_asgmt_grp['role_domain_id'])
        # Assert the names are correct in the domain response
        self.assertEqual(new_domain['name'],
                         first_asgmt_dmn['domain_name'])
        self.assertEqual(new_user['name'],
                         first_asgmt_dmn['user_name'])
        self.assertEqual(new_user['domain_id'],
                         first_asgmt_dmn['user_domain_id'])
        self.assertEqual(new_role['name'],
                         first_asgmt_dmn['role_name'])
        if domain_role:
            self.assertEqual(new_role['domain_id'],
                             first_asgmt_dmn['role_domain_id'])

    def test_list_role_assignment_containing_names_global_role(self):
        self._test_list_role_assignment_containing_names()

    def test_list_role_assignment_containing_names_domain_role(self):
        self._test_list_role_assignment_containing_names(domain_role=True)

    def test_list_role_assignment_does_not_contain_names(self):
        """Test names are not included with list role assignments.

        Scenario:
            - names are NOT included by default
            - names are NOT included when include_names=False

        """
        def assert_does_not_contain_names(assignment):
            first_asgmt_prj = assignment[0]
            self.assertNotIn('project_name', first_asgmt_prj)
            self.assertNotIn('project_domain_id', first_asgmt_prj)
            self.assertNotIn('user_name', first_asgmt_prj)
            self.assertNotIn('user_domain_id', first_asgmt_prj)
            self.assertNotIn('role_name', first_asgmt_prj)
            self.assertNotIn('role_domain_id', first_asgmt_prj)

        # Create Refs
        new_role = unit.new_role_ref()
        new_domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        # Create entities
        new_role = PROVIDERS.role_api.create_role(new_role['id'], new_role)
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'], project_id=new_project['id'],
            role_id=new_role['id']
        )
        # Get the created assignments with NO include_names flag
        role_assign_without_names = (
            PROVIDERS.assignment_api.list_role_assignments(
                user_id=new_user['id'], project_id=new_project['id']
            )
        )
        assert_does_not_contain_names(role_assign_without_names)
        # Get the created assignments with include_names=False
        role_assign_without_names = (
            PROVIDERS.assignment_api.list_role_assignments(
                user_id=new_user['id'],
                project_id=new_project['id'],
                include_names=False
            )
        )
        assert_does_not_contain_names(role_assign_without_names)

    def test_delete_user_assignments_user_same_id_as_group(self):
        """Test deleting user assignments when user_id == group_id.

        In this scenario, only user assignments must be deleted (i.e.
        USER_DOMAIN or USER_PROJECT).

        Test plan:
        * Create a user and a group with the same ID;
        * Create four roles and assign them to both user and group;
        * Delete all user assignments;
        * Group assignments must stay intact.
        """
        # Create a common ID
        common_id = uuid.uuid4().hex
        # Create a project
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        # Create a user
        user = unit.new_user_ref(id=common_id,
                                 domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.driver.create_user(common_id, user)
        self.assertEqual(common_id, user['id'])
        # Create a group
        group = unit.new_group_ref(id=common_id,
                                   domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.driver.create_group(common_id, group)
        self.assertEqual(common_id, group['id'])
        # Create four roles
        roles = []
        for _ in range(4):
            role = unit.new_role_ref()
            roles.append(PROVIDERS.role_api.create_role(role['id'], role))
        # Assign roles for user
        PROVIDERS.assignment_api.driver.create_grant(
            user_id=user['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[0]['id'])
        PROVIDERS.assignment_api.driver.create_grant(
            user_id=user['id'], project_id=project['id'],
            role_id=roles[1]['id']
        )
        # Assign roles for group
        PROVIDERS.assignment_api.driver.create_grant(
            group_id=group['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[2]['id'])
        PROVIDERS.assignment_api.driver.create_grant(
            group_id=group['id'], project_id=project['id'],
            role_id=roles[3]['id']
        )
        # Make sure they were assigned
        user_assignments = PROVIDERS.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(2))
        group_assignments = PROVIDERS.assignment_api.list_role_assignments(
            group_id=group['id'])
        self.assertThat(group_assignments, matchers.HasLength(2))
        # Delete user assignments
        PROVIDERS.assignment_api.delete_user_assignments(user_id=user['id'])
        # Assert only user assignments were deleted
        user_assignments = PROVIDERS.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(0))
        group_assignments = PROVIDERS.assignment_api.list_role_assignments(
            group_id=group['id'])
        self.assertThat(group_assignments, matchers.HasLength(2))
        # Make sure these remaining assignments are group-related
        for assignment in group_assignments:
            self.assertThat(assignment.keys(), matchers.Contains('group_id'))

    def test_delete_group_assignments_group_same_id_as_user(self):
        """Test deleting group assignments when group_id == user_id.

        In this scenario, only group assignments must be deleted (i.e.
        GROUP_DOMAIN or GROUP_PROJECT).

        Test plan:
        * Create a group and a user with the same ID;
        * Create four roles and assign them to both group and user;
        * Delete all group assignments;
        * User assignments must stay intact.
        """
        # Create a common ID
        common_id = uuid.uuid4().hex
        # Create a project
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        # Create a user
        user = unit.new_user_ref(id=common_id,
                                 domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.driver.create_user(common_id, user)
        self.assertEqual(common_id, user['id'])
        # Create a group
        group = unit.new_group_ref(id=common_id,
                                   domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.driver.create_group(common_id, group)
        self.assertEqual(common_id, group['id'])
        # Create four roles
        roles = []
        for _ in range(4):
            role = unit.new_role_ref()
            roles.append(PROVIDERS.role_api.create_role(role['id'], role))
        # Assign roles for user
        PROVIDERS.assignment_api.driver.create_grant(
            user_id=user['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[0]['id'])
        PROVIDERS.assignment_api.driver.create_grant(
            user_id=user['id'], project_id=project['id'],
            role_id=roles[1]['id']
        )
        # Assign roles for group
        PROVIDERS.assignment_api.driver.create_grant(
            group_id=group['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[2]['id'])
        PROVIDERS.assignment_api.driver.create_grant(
            group_id=group['id'], project_id=project['id'],
            role_id=roles[3]['id']
        )
        # Make sure they were assigned
        user_assignments = PROVIDERS.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(2))
        group_assignments = PROVIDERS.assignment_api.list_role_assignments(
            group_id=group['id'])
        self.assertThat(group_assignments, matchers.HasLength(2))
        # Delete group assignments
        PROVIDERS.assignment_api.delete_group_assignments(group_id=group['id'])
        # Assert only group assignments were deleted
        group_assignments = PROVIDERS.assignment_api.list_role_assignments(
            group_id=group['id'])
        self.assertThat(group_assignments, matchers.HasLength(0))
        user_assignments = PROVIDERS.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(2))
        # Make sure these remaining assignments are user-related
        for assignment in group_assignments:
            self.assertThat(assignment.keys(), matchers.Contains('user_id'))

    def test_remove_foreign_assignments_when_deleting_a_domain(self):
        # A user and a group are in default domain and have assigned a role on
        # two new domains. This test makes sure that when one of the new
        # domains is deleted, the role assignments for the user and the group
        # from the default domain are deleted only on that domain.
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        role = unit.new_role_ref()
        role = PROVIDERS.role_api.create_role(role['id'], role)

        new_domains = [unit.new_domain_ref(), unit.new_domain_ref()]
        for new_domain in new_domains:
            PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)

            PROVIDERS.assignment_api.create_grant(
                group_id=group['id'], domain_id=new_domain['id'],
                role_id=role['id']
            )
            PROVIDERS.assignment_api.create_grant(
                user_id=self.user_two['id'], domain_id=new_domain['id'],
                role_id=role['id']
            )

        # Check there are 4 role assignments for that role
        role_assignments = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id'])
        self.assertThat(role_assignments, matchers.HasLength(4))

        # Delete first new domain and check only 2 assignments were left
        PROVIDERS.resource_api.update_domain(
            new_domains[0]['id'], {'enabled': False}
        )
        PROVIDERS.resource_api.delete_domain(new_domains[0]['id'])

        role_assignments = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id'])
        self.assertThat(role_assignments, matchers.HasLength(2))

        # Delete second new domain and check no assignments were left
        PROVIDERS.resource_api.update_domain(
            new_domains[1]['id'], {'enabled': False}
        )
        PROVIDERS.resource_api.delete_domain(new_domains[1]['id'])

        role_assignments = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id'])
        self.assertEqual([], role_assignments)


class InheritanceTests(AssignmentTestHelperMixin):

    def test_role_assignments_user_domain_to_project_inheritance(self):
        test_plan = {
            'entities': {'domains': {'users': 2, 'projects': 1},
                         'roles': 3},
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'user': 0, 'role': 1, 'project': 0},
                            {'user': 0, 'role': 2, 'domain': 0,
                             'inherited_to_projects': True},
                            {'user': 1, 'role': 1, 'project': 0}],
            'tests': [
                # List all direct assignments for user[0]
                {'params': {'user': 0},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'project': 0},
                             {'user': 0, 'role': 2, 'domain': 0,
                              'inherited_to_projects': 'projects'}]},
                # Now the effective ones - so the domain role should turn into
                # a project role
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'project': 0},
                             {'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'domain': 0}}]},
                # Narrow down to effective roles for user[0] and project[0]
                {'params': {'user': 0, 'project': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 1, 'project': 0},
                             {'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'domain': 0}}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def _test_crud_inherited_and_direct_assignment(self, **kwargs):
        """Test inherited and direct assignments for the actor and target.

        Ensure it is possible to create both inherited and direct role
        assignments for the same actor on the same target. The actor and the
        target are specified in the kwargs as ('user_id' or 'group_id') and
        ('project_id' or 'domain_id'), respectively.

        """
        # Create a new role to avoid assignments loaded from default fixtures
        role = unit.new_role_ref()
        role = PROVIDERS.role_api.create_role(role['id'], role)

        # Define the common assignment entity
        assignment_entity = {'role_id': role['id']}
        assignment_entity.update(kwargs)

        # Define assignments under test
        direct_assignment_entity = assignment_entity.copy()
        inherited_assignment_entity = assignment_entity.copy()
        inherited_assignment_entity['inherited_to_projects'] = 'projects'

        # Create direct assignment and check grants
        PROVIDERS.assignment_api.create_grant(
            inherited_to_projects=False, **assignment_entity
        )

        grants = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id']
        )
        self.assertThat(grants, matchers.HasLength(1))
        self.assertIn(direct_assignment_entity, grants)

        # Now add inherited assignment and check grants
        PROVIDERS.assignment_api.create_grant(
            inherited_to_projects=True, **assignment_entity
        )

        grants = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id']
        )
        self.assertThat(grants, matchers.HasLength(2))
        self.assertIn(direct_assignment_entity, grants)
        self.assertIn(inherited_assignment_entity, grants)

        # Delete both and check grants
        PROVIDERS.assignment_api.delete_grant(
            inherited_to_projects=False, **assignment_entity
        )
        PROVIDERS.assignment_api.delete_grant(
            inherited_to_projects=True, **assignment_entity
        )

        grants = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id']
        )
        self.assertEqual([], grants)

    def test_crud_inherited_and_direct_assignment_for_user_on_domain(self):
        self._test_crud_inherited_and_direct_assignment(
            user_id=self.user_foo['id'],
            domain_id=CONF.identity.default_domain_id)

    def test_crud_inherited_and_direct_assignment_for_group_on_domain(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        self._test_crud_inherited_and_direct_assignment(
            group_id=group['id'], domain_id=CONF.identity.default_domain_id)

    def test_crud_inherited_and_direct_assignment_for_user_on_project(self):
        self._test_crud_inherited_and_direct_assignment(
            user_id=self.user_foo['id'], project_id=self.project_baz['id'])

    def test_crud_inherited_and_direct_assignment_for_group_on_project(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        self._test_crud_inherited_and_direct_assignment(
            group_id=group['id'], project_id=self.project_baz['id'])

    def test_inherited_role_grants_for_user(self):
        """Test inherited user roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create 3 roles
        - Create a domain, with a project and a user
        - Check no roles yet exit
        - Assign a direct user role to the project and a (non-inherited)
          user role to the domain
        - Get a list of effective roles - should only get the one direct role
        - Now add an inherited user role to the domain
        - Get a list of effective roles - should have two roles, one
          direct and one by virtue of the inherited user role
        - Also get effective roles for the domain - the role marked as
          inherited should not show up

        """
        role_list = []
        for _ in range(3):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)

        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))

        # Create the first two roles - the domain one is not inherited
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'],
            role_id=role_list[0]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'],
            role_id=role_list[1]['id']
        )

        # Now get the effective roles for the user and project, this
        # should only include the direct role assignment on the project
        combined_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user1['id'], project1['id']
            )
        )
        self.assertEqual(1, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)

        # Now add an inherited role on the domain
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'],
            role_id=role_list[2]['id'], inherited_to_projects=True
        )

        # Now get the effective roles for the user and project again, this
        # should now include the inherited role on the domain
        combined_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user1['id'], project1['id']
            )
        )
        self.assertEqual(2, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)
        self.assertIn(role_list[2]['id'], combined_list)

        # Finally, check that the inherited role does not appear as a valid
        # directly assigned role on the domain itself
        combined_role_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_domain(
                user1['id'], domain1['id']
            )
        )
        self.assertEqual(1, len(combined_role_list))
        self.assertIn(role_list[1]['id'], combined_role_list)

        # TODO(henry-nash): The test above uses get_roles_for_user_and_project
        # and get_roles_for_user_and_domain, which will, in a subsequent patch,
        # be re-implemented to simply call list_role_assignments (see blueprint
        # remove-role-metadata).
        #
        # The test plan below therefore mirrors this test, to ensure that
        # list_role_assignments works the same. Once get_roles_for_user_and
        # project/domain have been re-implemented then the manual tests above
        # can be refactored to simply ensure it gives the same answers.
        test_plan = {
            # A domain with a user & project, plus 3 roles.
            'entities': {'domains': {'users': 1, 'projects': 1},
                         'roles': 3},
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'user': 0, 'role': 1, 'domain': 0},
                            {'user': 0, 'role': 2, 'domain': 0,
                             'inherited_to_projects': True}],
            'tests': [
                # List all effective assignments for user[0] on project[0].
                # Should get one direct role and one inherited role.
                {'params': {'user': 0, 'project': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'domain': 0}}]},
                # Ensure effective mode on the domain does not list the
                # inherited role on that domain
                {'params': {'user': 0, 'domain': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 1, 'domain': 0}]},
                # Ensure non-inherited mode also only returns the non-inherited
                # role on the domain
                {'params': {'user': 0, 'domain': 0, 'inherited': False},
                 'results': [{'user': 0, 'role': 1, 'domain': 0}]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_inherited_role_grants_for_group(self):
        """Test inherited group roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create 4 roles
        - Create a domain, with a project, user and two groups
        - Make the user a member of both groups
        - Check no roles yet exit
        - Assign a direct user role to the project and a (non-inherited)
          group role on the domain
        - Get a list of effective roles - should only get the one direct role
        - Now add two inherited group roles to the domain
        - Get a list of effective roles - should have three roles, one
          direct and two by virtue of inherited group roles

        """
        role_list = []
        for _ in range(4):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain1['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)

        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group2['id']
        )

        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))

        # Create two roles - the domain one is not inherited
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'],
            role_id=role_list[0]['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain1['id'],
            role_id=role_list[1]['id']
        )

        # Now get the effective roles for the user and project, this
        # should only include the direct role assignment on the project
        combined_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user1['id'], project1['id']
            )
        )
        self.assertEqual(1, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)

        # Now add to more group roles, both inherited, to the domain
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], domain_id=domain1['id'],
            role_id=role_list[2]['id'], inherited_to_projects=True
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], domain_id=domain1['id'],
            role_id=role_list[3]['id'], inherited_to_projects=True
        )

        # Now get the effective roles for the user and project again, this
        # should now include the inherited roles on the domain
        combined_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user1['id'], project1['id']
            )
        )
        self.assertEqual(3, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)
        self.assertIn(role_list[2]['id'], combined_list)
        self.assertIn(role_list[3]['id'], combined_list)

        # TODO(henry-nash): The test above uses get_roles_for_user_and_project
        # which will, in a subsequent patch, be re-implemented to simply call
        # list_role_assignments (see blueprint remove-role-metadata).
        #
        # The test plan below therefore mirrors this test, to ensure that
        # list_role_assignments works the same. Once
        # get_roles_for_user_and_project has been re-implemented then the
        # manual tests above can be refactored to simply ensure it gives
        # the same answers.
        test_plan = {
            # A domain with a user and project, 2 groups, plus 4 roles.
            'entities': {'domains': {'users': 1, 'projects': 1, 'groups': 2},
                         'roles': 4},
            'group_memberships': [{'group': 0, 'users': [0]},
                                  {'group': 1, 'users': [0]}],
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'group': 0, 'role': 1, 'domain': 0},
                            {'group': 1, 'role': 2, 'domain': 0,
                             'inherited_to_projects': True},
                            {'group': 1, 'role': 3, 'domain': 0,
                             'inherited_to_projects': True}],
            'tests': [
                # List all effective assignments for user[0] on project[0].
                # Should get one direct role and both inherited roles, but
                # not the direct one on domain[0], even though user[0] is
                # in group[0].
                {'params': {'user': 0, 'project': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'domain': 0, 'group': 1}},
                             {'user': 0, 'role': 3, 'project': 0,
                              'indirect': {'domain': 0, 'group': 1}}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_projects_for_user_with_inherited_grants(self):
        """Test inherited user roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create a domain, with two projects and a user
        - Assign an inherited user role on the domain, as well as a direct
          user role to a separate project in a different domain
        - Get a list of projects for user, should return all three projects

        """
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)

        # Create 2 grants, one on a project and one inherited grant
        # on the domain
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain['id'],
            role_id=self.role_admin['id'], inherited_to_projects=True
        )
        # Should get back all three projects, one by virtue of the direct
        # grant, plus both projects in the domain
        user_projects = (
            PROVIDERS.assignment_api.list_projects_for_user(user1['id'])
        )
        self.assertEqual(3, len(user_projects))

        # TODO(henry-nash): The test above uses list_projects_for_user
        # which may, in a subsequent patch, be re-implemented to call
        # list_role_assignments and then report only the distinct projects.
        #
        # The test plan below therefore mirrors this test, to ensure that
        # list_role_assignments works the same. Once list_projects_for_user
        # has been re-implemented then the manual tests above can be
        # refactored.
        test_plan = {
            # A domain with 1 project, plus a second domain with 2 projects,
            # as well as a user. Also, create 2 roles.
            'entities': {'domains': [{'projects': 1},
                                     {'users': 1, 'projects': 2}],
                         'roles': 2},
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'user': 0, 'role': 1, 'domain': 1,
                             'inherited_to_projects': True}],
            'tests': [
                # List all effective assignments for user[0]
                # Should get one direct role plus one inherited role for each
                # project in domain
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 1, 'project': 1,
                              'indirect': {'domain': 1}},
                             {'user': 0, 'role': 1, 'project': 2,
                              'indirect': {'domain': 1}}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_projects_for_user_with_inherited_user_project_grants(self):
        """Test inherited role assignments for users on nested projects.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create a hierarchy of projects with one root and one leaf project
        - Assign an inherited user role on root project
        - Assign a non-inherited user role on root project
        - Get a list of projects for user, should return both projects
        - Disable OS-INHERIT extension
        - Get a list of projects for user, should return only root project

        """
        # Enable OS-INHERIT extension
        root_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        root_project = PROVIDERS.resource_api.create_project(
            root_project['id'], root_project
        )
        leaf_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=root_project['id'])
        leaf_project = PROVIDERS.resource_api.create_project(
            leaf_project['id'], leaf_project
        )

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)

        # Grant inherited user role
        PROVIDERS.assignment_api.create_grant(
            user_id=user['id'], project_id=root_project['id'],
            role_id=self.role_admin['id'], inherited_to_projects=True
        )
        # Grant non-inherited user role
        PROVIDERS.assignment_api.create_grant(
            user_id=user['id'], project_id=root_project['id'],
            role_id=self.role_member['id']
        )
        # Should get back both projects: because the direct role assignment for
        # the root project and inherited role assignment for leaf project
        user_projects = (
            PROVIDERS.assignment_api.list_projects_for_user(user['id'])
        )
        self.assertEqual(2, len(user_projects))
        self.assertIn(root_project, user_projects)
        self.assertIn(leaf_project, user_projects)

        # TODO(henry-nash): The test above uses list_projects_for_user
        # which may, in a subsequent patch, be re-implemented to call
        # list_role_assignments and then report only the distinct projects.
        #
        # The test plan below therefore mirrors this test, to ensure that
        # list_role_assignments works the same. Once list_projects_for_user
        # has been re-implemented then the manual tests above can be
        # refactored.
        test_plan = {
            # A domain with a project and sub-project, plus a user.
            # Also, create 2 roles.
            'entities': {
                'domains': {'id': CONF.identity.default_domain_id, 'users': 1,
                            'projects': {'project': 1}},
                'roles': 2},
            # A direct role and an inherited role on the parent
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'user': 0, 'role': 1, 'project': 0,
                             'inherited_to_projects': True}],
            'tests': [
                # List all effective assignments for user[0] - should get back
                # one direct role plus one inherited role.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 1, 'project': 1,
                              'indirect': {'project': 0}}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_projects_for_user_with_inherited_group_grants(self):
        """Test inherited group roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create two domains, each with two projects
        - Create a user and group
        - Make the user a member of the group
        - Assign a user role two projects, an inherited
          group role to one domain and an inherited regular role on
          the other domain
        - Get a list of projects for user, should return both pairs of projects
          from the domain, plus the one separate project

        """
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        project3 = unit.new_project_ref(domain_id=domain2['id'])
        PROVIDERS.resource_api.create_project(project3['id'], project3)
        project4 = unit.new_project_ref(domain_id=domain2['id'])
        PROVIDERS.resource_api.create_project(project4['id'], project4)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        PROVIDERS.identity_api.add_user_to_group(user1['id'], group1['id'])

        # Create 4 grants:
        # - one user grant on a project in domain2
        # - one user grant on a project in the default domain
        # - one inherited user grant on domain
        # - one inherited group grant on domain2
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project3['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain['id'],
            role_id=self.role_admin['id'], inherited_to_projects=True
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain2['id'],
            role_id=self.role_admin['id'], inherited_to_projects=True
        )
        # Should get back all five projects, but without a duplicate for
        # project3 (since it has both a direct user role and an inherited role)
        user_projects = (
            PROVIDERS.assignment_api.list_projects_for_user(user1['id'])
        )
        self.assertEqual(5, len(user_projects))

        # TODO(henry-nash): The test above uses list_projects_for_user
        # which may, in a subsequent patch, be re-implemented to call
        # list_role_assignments and then report only the distinct projects.
        #
        # The test plan below therefore mirrors this test, to ensure that
        # list_role_assignments works the same. Once list_projects_for_user
        # has been re-implemented then the manual tests above can be
        # refactored.
        test_plan = {
            # A domain with a 1 project, plus a second domain with 2 projects,
            # as well as a user & group and a 3rd domain with 2 projects.
            # Also, created 2 roles.
            'entities': {'domains': [{'projects': 1},
                                     {'users': 1, 'groups': 1, 'projects': 2},
                                     {'projects': 2}],
                         'roles': 2},
            'group_memberships': [{'group': 0, 'users': [0]}],
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'user': 0, 'role': 0, 'project': 3},
                            {'user': 0, 'role': 1, 'domain': 1,
                             'inherited_to_projects': True},
                            {'user': 0, 'role': 1, 'domain': 2,
                             'inherited_to_projects': True}],
            'tests': [
                # List all effective assignments for user[0]
                # Should get back both direct roles plus roles on both projects
                # from each domain. Duplicates should not be filtered out.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 3},
                             {'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 1, 'project': 1,
                              'indirect': {'domain': 1}},
                             {'user': 0, 'role': 1, 'project': 2,
                              'indirect': {'domain': 1}},
                             {'user': 0, 'role': 1, 'project': 3,
                              'indirect': {'domain': 2}},
                             {'user': 0, 'role': 1, 'project': 4,
                              'indirect': {'domain': 2}}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_projects_for_user_with_inherited_group_project_grants(self):
        """Test inherited role assignments for groups on nested projects.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create a hierarchy of projects with one root and one leaf project
        - Assign an inherited group role on root project
        - Assign a non-inherited group role on root project
        - Get a list of projects for user, should return both projects
        - Disable OS-INHERIT extension
        - Get a list of projects for user, should return only root project

        """
        root_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        root_project = PROVIDERS.resource_api.create_project(
            root_project['id'], root_project
        )
        leaf_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=root_project['id'])
        leaf_project = PROVIDERS.resource_api.create_project(
            leaf_project['id'], leaf_project
        )

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        # Grant inherited group role
        PROVIDERS.assignment_api.create_grant(
            group_id=group['id'], project_id=root_project['id'],
            role_id=self.role_admin['id'], inherited_to_projects=True
        )
        # Grant non-inherited group role
        PROVIDERS.assignment_api.create_grant(
            group_id=group['id'], project_id=root_project['id'],
            role_id=self.role_member['id']
        )
        # Should get back both projects: because the direct role assignment for
        # the root project and inherited role assignment for leaf project
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user['id']
        )
        self.assertEqual(2, len(user_projects))
        self.assertIn(root_project, user_projects)
        self.assertIn(leaf_project, user_projects)

        # TODO(henry-nash): The test above uses list_projects_for_user
        # which may, in a subsequent patch, be re-implemented to call
        # list_role_assignments and then report only the distinct projects.
        #
        # The test plan below therefore mirrors this test, to ensure that
        # list_role_assignments works the same. Once list_projects_for_user
        # has been re-implemented then the manual tests above can be
        # refactored.
        test_plan = {
            # A domain with a project and sub-project, plus a user.
            # Also, create 2 roles.
            'entities': {
                'domains': {'id': CONF.identity.default_domain_id, 'users': 1,
                            'groups': 1,
                            'projects': {'project': 1}},
                'roles': 2},
            'group_memberships': [{'group': 0, 'users': [0]}],
            # A direct role and an inherited role on the parent
            'assignments': [{'group': 0, 'role': 0, 'project': 0},
                            {'group': 0, 'role': 1, 'project': 0,
                             'inherited_to_projects': True}],
            'tests': [
                # List all effective assignments for user[0] - should get back
                # one direct role plus one inherited role.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0,
                              'indirect': {'group': 0}},
                             {'user': 0, 'role': 1, 'project': 1,
                              'indirect': {'group': 0, 'project': 0}}]}
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_list_assignments_for_tree(self):
        """Test we correctly list direct assignments for a tree."""
        # Enable OS-INHERIT extension

        test_plan = {
            # Create a domain with a project hierarchy 3 levels deep:
            #
            #                      project 0
            #             ____________|____________
            #            |                         |
            #         project 1                 project 4
            #      ______|_____              ______|_____
            #     |            |            |            |
            #  project 2    project 3    project 5    project 6
            #
            # Also, create 1 user and 4 roles.
            'entities': {
                'domains': {
                    'projects': {'project': [{'project': 2},
                                             {'project': 2}]},
                    'users': 1},
                'roles': 4},
            'assignments': [
                # Direct assignment to projects 1 and 2
                {'user': 0, 'role': 0, 'project': 1},
                {'user': 0, 'role': 1, 'project': 2},
                # Also an inherited assignment on project 1
                {'user': 0, 'role': 2, 'project': 1,
                 'inherited_to_projects': True},
                # ...and two spoiler assignments, one to the root and one
                # to project 4
                {'user': 0, 'role': 0, 'project': 0},
                {'user': 0, 'role': 3, 'project': 4}],
            'tests': [
                # List all assignments for project 1 and its subtree.
                {'params': {'project': 1, 'include_subtree': True},
                 'results': [
                     # Only the actual assignments should be returned, no
                     # expansion of inherited assignments
                     {'user': 0, 'role': 0, 'project': 1},
                     {'user': 0, 'role': 1, 'project': 2},
                     {'user': 0, 'role': 2, 'project': 1,
                      'inherited_to_projects': 'projects'}]}
            ]
        }

        self.execute_assignment_plan(test_plan)

    def test_list_effective_assignments_for_tree(self):
        """Test we correctly list effective assignments for a tree."""
        test_plan = {
            # Create a domain with a project hierarchy 3 levels deep:
            #
            #                      project 0
            #             ____________|____________
            #            |                         |
            #         project 1                 project 4
            #      ______|_____              ______|_____
            #     |            |            |            |
            #  project 2    project 3    project 5    project 6
            #
            # Also, create 1 user and 4 roles.
            'entities': {
                'domains': {
                    'projects': {'project': [{'project': 2},
                                             {'project': 2}]},
                    'users': 1},
                'roles': 4},
            'assignments': [
                # An inherited assignment on project 1
                {'user': 0, 'role': 1, 'project': 1,
                 'inherited_to_projects': True},
                # A direct assignment to project 2
                {'user': 0, 'role': 2, 'project': 2},
                # ...and two spoiler assignments, one to the root and one
                # to project 4
                {'user': 0, 'role': 0, 'project': 0},
                {'user': 0, 'role': 3, 'project': 4}],
            'tests': [
                # List all effective assignments for project 1 and its subtree.
                {'params': {'project': 1, 'effective': True,
                            'include_subtree': True},
                 'results': [
                     # The inherited assignment on project 1 should appear only
                     # on its children
                     {'user': 0, 'role': 1, 'project': 2,
                      'indirect': {'project': 1}},
                     {'user': 0, 'role': 1, 'project': 3,
                      'indirect': {'project': 1}},
                     # And finally the direct assignment on project 2
                     {'user': 0, 'role': 2, 'project': 2}]}
            ]
        }

        self.execute_assignment_plan(test_plan)

    def test_list_effective_assignments_for_tree_with_mixed_assignments(self):
        """Test that we correctly combine assignments for a tree.

        In this test we want to ensure that when asking for a list of
        assignments in a subtree, any assignments inherited from above the
        subtree are correctly combined with any assignments within the subtree
        itself.

        """
        test_plan = {
            # Create a domain with a project hierarchy 3 levels deep:
            #
            #                      project 0
            #             ____________|____________
            #            |                         |
            #         project 1                 project 4
            #      ______|_____              ______|_____
            #     |            |            |            |
            #  project 2    project 3    project 5    project 6
            #
            # Also, create 2 users, 1 group and 4 roles.
            'entities': {
                'domains': {
                    'projects': {'project': [{'project': 2},
                                             {'project': 2}]},
                    'users': 2, 'groups': 1},
                'roles': 4},
            # Both users are part of the same group
            'group_memberships': [{'group': 0, 'users': [0, 1]}],
            # We are going to ask for listing of assignment on project 1 and
            # it's subtree. So first we'll add two inherited assignments above
            # this (one user and one for a group that contains this user).
            'assignments': [{'user': 0, 'role': 0, 'project': 0,
                             'inherited_to_projects': True},
                            {'group': 0, 'role': 1, 'project': 0,
                             'inherited_to_projects': True},
                            # Now an inherited assignment on project 1 itself,
                            # which should ONLY show up on its children
                            {'user': 0, 'role': 2, 'project': 1,
                             'inherited_to_projects': True},
                            # ...and a direct assignment on one of those
                            # children
                            {'user': 0, 'role': 3, 'project': 2},
                            # The rest are spoiler assignments
                            {'user': 0, 'role': 2, 'project': 5},
                            {'user': 0, 'role': 3, 'project': 4}],
            'tests': [
                # List all effective assignments for project 1 and its subtree.
                {'params': {'project': 1, 'user': 0, 'effective': True,
                            'include_subtree': True},
                 'results': [
                     # First, we should see the inherited user assignment from
                     # project 0 on all projects in the subtree
                     {'user': 0, 'role': 0, 'project': 1,
                      'indirect': {'project': 0}},
                     {'user': 0, 'role': 0, 'project': 2,
                      'indirect': {'project': 0}},
                     {'user': 0, 'role': 0, 'project': 3,
                      'indirect': {'project': 0}},
                     # Also the inherited group assignment from project 0 on
                     # the subtree
                     {'user': 0, 'role': 1, 'project': 1,
                      'indirect': {'project': 0, 'group': 0}},
                     {'user': 0, 'role': 1, 'project': 2,
                      'indirect': {'project': 0, 'group': 0}},
                     {'user': 0, 'role': 1, 'project': 3,
                      'indirect': {'project': 0, 'group': 0}},
                     # The inherited assignment on project 1 should appear only
                     # on its children
                     {'user': 0, 'role': 2, 'project': 2,
                      'indirect': {'project': 1}},
                     {'user': 0, 'role': 2, 'project': 3,
                      'indirect': {'project': 1}},
                     # And finally the direct assignment on project 2
                     {'user': 0, 'role': 3, 'project': 2}]}
            ]
        }

        self.execute_assignment_plan(test_plan)

    def test_list_effective_assignments_for_tree_with_domain_assignments(self):
        """Test we correctly honor domain inherited assignments on the tree."""
        test_plan = {
            # Create a domain with a project hierarchy 3 levels deep:
            #
            #                      project 0
            #             ____________|____________
            #            |                         |
            #         project 1                 project 4
            #      ______|_____              ______|_____
            #     |            |            |            |
            #  project 2    project 3    project 5    project 6
            #
            # Also, create 1 user and 4 roles.
            'entities': {
                'domains': {
                    'projects': {'project': [{'project': 2},
                                             {'project': 2}]},
                    'users': 1},
                'roles': 4},
            'assignments': [
                # An inherited assignment on the domain (which should be
                # applied to all the projects)
                {'user': 0, 'role': 1, 'domain': 0,
                 'inherited_to_projects': True},
                # A direct assignment to project 2
                {'user': 0, 'role': 2, 'project': 2},
                # ...and two spoiler assignments, one to the root and one
                # to project 4
                {'user': 0, 'role': 0, 'project': 0},
                {'user': 0, 'role': 3, 'project': 4}],
            'tests': [
                # List all effective assignments for project 1 and its subtree.
                {'params': {'project': 1, 'effective': True,
                            'include_subtree': True},
                 'results': [
                     # The inherited assignment from the domain should appear
                     # only on the part of the subtree we are interested in
                     {'user': 0, 'role': 1, 'project': 1,
                      'indirect': {'domain': 0}},
                     {'user': 0, 'role': 1, 'project': 2,
                      'indirect': {'domain': 0}},
                     {'user': 0, 'role': 1, 'project': 3,
                      'indirect': {'domain': 0}},
                     # And finally the direct assignment on project 2
                     {'user': 0, 'role': 2, 'project': 2}]}
            ]
        }

        self.execute_assignment_plan(test_plan)

    def test_list_user_ids_for_project_with_inheritance(self):
        test_plan = {
            # A domain with a project and sub-project, plus four users,
            # two groups, as well as 4 roles.
            'entities': {
                'domains': {'id': CONF.identity.default_domain_id, 'users': 4,
                            'groups': 2,
                            'projects': {'project': 1}},
                'roles': 4},
            # Each group has a unique user member
            'group_memberships': [{'group': 0, 'users': [1]},
                                  {'group': 1, 'users': [3]}],
            # Set up assignments so that there should end up with four
            # effective assignments on project 1 - one direct, one due to
            # group membership and one user assignment inherited from the
            # parent and one group assignment inherited from the parent.
            'assignments': [{'user': 0, 'role': 0, 'project': 1},
                            {'group': 0, 'role': 1, 'project': 1},
                            {'user': 2, 'role': 2, 'project': 0,
                             'inherited_to_projects': True},
                            {'group': 1, 'role': 3, 'project': 0,
                             'inherited_to_projects': True}],
        }
        # Use assignment plan helper to create all the entities and
        # assignments - then we'll run our own tests using the data
        test_data = self.execute_assignment_plan(test_plan)
        user_ids = PROVIDERS.assignment_api.list_user_ids_for_project(
            test_data['projects'][1]['id'])
        self.assertThat(user_ids, matchers.HasLength(4))
        for x in range(0, 4):
            self.assertIn(test_data['users'][x]['id'], user_ids)

    def test_list_role_assignment_using_inherited_sourced_groups(self):
        """Test listing inherited assignments when restricted by groups."""
        test_plan = {
            # A domain with 3 users, 3 groups, 3 projects, a second domain,
            # plus 3 roles.
            'entities': {'domains': [{'users': 3, 'groups': 3, 'projects': 3},
                                     1],
                         'roles': 3},
            # Users 0 & 1 are in the group 0, User 0 also in group 1
            'group_memberships': [{'group': 0, 'users': [0, 1]},
                                  {'group': 1, 'users': [0]}],
            # Spread the assignments around - we want to be able to show that
            # if sourced by group, assignments from other sources are excluded
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'group': 0, 'role': 1, 'domain': 1},
                            {'group': 1, 'role': 2, 'domain': 0,
                             'inherited_to_projects': True},
                            {'group': 1, 'role': 2, 'project': 1},
                            {'user': 2, 'role': 1, 'project': 1,
                             'inherited_to_projects': True},
                            {'group': 2, 'role': 2, 'project': 2}
                            ],
            'tests': [
                # List all effective assignments sourced from groups 0 and 1.
                # We should see the inherited group assigned on the 3 projects
                # from domain 0, as well as the direct assignments.
                {'params': {'source_from_group_ids': [0, 1],
                            'effective': True},
                 'results': [{'group': 0, 'role': 1, 'domain': 1},
                             {'group': 1, 'role': 2, 'project': 0,
                              'indirect': {'domain': 0}},
                             {'group': 1, 'role': 2, 'project': 1,
                              'indirect': {'domain': 0}},
                             {'group': 1, 'role': 2, 'project': 2,
                              'indirect': {'domain': 0}},
                             {'group': 1, 'role': 2, 'project': 1}
                             ]},
            ]
        }
        self.execute_assignment_plan(test_plan)


class ImpliedRoleTests(AssignmentTestHelperMixin):

    def test_implied_role_crd(self):
        prior_role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(prior_role_ref['id'], prior_role_ref)
        implied_role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            implied_role_ref['id'], implied_role_ref
        )

        PROVIDERS.role_api.create_implied_role(
            prior_role_ref['id'],
            implied_role_ref['id'])
        implied_role = PROVIDERS.role_api.get_implied_role(
            prior_role_ref['id'],
            implied_role_ref['id'])
        expected_implied_role_ref = {
            'prior_role_id': prior_role_ref['id'],
            'implied_role_id': implied_role_ref['id']}
        self.assertLessEqual(
            expected_implied_role_ref.items(),
            implied_role.items())

        PROVIDERS.role_api.delete_implied_role(
            prior_role_ref['id'],
            implied_role_ref['id'])
        self.assertRaises(exception.ImpliedRoleNotFound,
                          PROVIDERS.role_api.get_implied_role,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_delete_implied_role_returns_not_found(self):
        self.assertRaises(exception.ImpliedRoleNotFound,
                          PROVIDERS.role_api.delete_implied_role,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_role_assignments_simple_tree_of_implied_roles(self):
        """Test that implied roles are expanded out."""
        test_plan = {
            'entities': {'domains': {'users': 1, 'projects': 1},
                         'roles': 4},
            # Three level tree of implied roles
            'implied_roles': [{'role': 0, 'implied_roles': 1},
                              {'role': 1, 'implied_roles': [2, 3]}],
            'assignments': [{'user': 0, 'role': 0, 'project': 0}],
            'tests': [
                # List all direct assignments for user[0], this should just
                # show the one top level role assignment
                {'params': {'user': 0},
                 'results': [{'user': 0, 'role': 0, 'project': 0}]},
                # Listing in effective mode should show the implied roles
                # expanded out
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 1, 'project': 0,
                              'indirect': {'role': 0}},
                             {'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'role': 1}},
                             {'user': 0, 'role': 3, 'project': 0,
                              'indirect': {'role': 1}}]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_circular_inferences(self):
        """Test that implied roles are expanded out."""
        test_plan = {
            'entities': {'domains': {'users': 1, 'projects': 1},
                         'roles': 4},
            # Three level tree of implied roles
            'implied_roles': [{'role': 0, 'implied_roles': [1]},
                              {'role': 1, 'implied_roles': [2, 3]},
                              {'role': 3, 'implied_roles': [0]}],
            'assignments': [{'user': 0, 'role': 0, 'project': 0}],
            'tests': [
                # List all direct assignments for user[0], this should just
                # show the one top level role assignment
                {'params': {'user': 0},
                 'results': [{'user': 0, 'role': 0, 'project': 0}]},
                # Listing in effective mode should show the implied roles
                # expanded out
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 0, 'project': 0,
                              'indirect': {'role': 3}},
                             {'user': 0, 'role': 1, 'project': 0,
                              'indirect': {'role': 0}},
                             {'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'role': 1}},
                             {'user': 0, 'role': 3, 'project': 0,
                              'indirect': {'role': 1}}]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_role_assignments_directed_graph_of_implied_roles(self):
        """Test that a role can have multiple, different prior roles."""
        test_plan = {
            'entities': {'domains': {'users': 1, 'projects': 1},
                         'roles': 6},
            # Three level tree of implied roles, where one of the roles at the
            # bottom is implied by more than one top level role
            'implied_roles': [{'role': 0, 'implied_roles': [1, 2]},
                              {'role': 1, 'implied_roles': [3, 4]},
                              {'role': 5, 'implied_roles': 4}],
            # The user gets both top level roles
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'user': 0, 'role': 5, 'project': 0}],
            'tests': [
                # The implied roles should be expanded out and there should be
                # two entries for the role that had two different prior roles.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0},
                             {'user': 0, 'role': 5, 'project': 0},
                             {'user': 0, 'role': 1, 'project': 0,
                              'indirect': {'role': 0}},
                             {'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'role': 0}},
                             {'user': 0, 'role': 3, 'project': 0,
                              'indirect': {'role': 1}},
                             {'user': 0, 'role': 4, 'project': 0,
                              'indirect': {'role': 1}},
                             {'user': 0, 'role': 4, 'project': 0,
                              'indirect': {'role': 5}}]},
            ]
        }
        test_data = self.execute_assignment_plan(test_plan)

        # We should also be able to get a similar (yet summarized) answer to
        # the above by calling get_roles_for_user_and_project(), which should
        # list the role_ids, yet remove any duplicates
        role_ids = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            test_data['users'][0]['id'], test_data['projects'][0]['id'])
        # We should see 6 entries, not 7, since role index 5 appeared twice in
        # the answer from list_role_assignments
        self.assertThat(role_ids, matchers.HasLength(6))
        for x in range(0, 5):
            self.assertIn(test_data['roles'][x]['id'], role_ids)

    def test_role_assignments_implied_roles_filtered_by_role(self):
        """Test that you can filter by role even if roles are implied."""
        test_plan = {
            'entities': {'domains': {'users': 1, 'projects': 2},
                         'roles': 4},
            # Three level tree of implied roles
            'implied_roles': [{'role': 0, 'implied_roles': 1},
                              {'role': 1, 'implied_roles': [2, 3]}],
            'assignments': [{'user': 0, 'role': 0, 'project': 0},
                            {'user': 0, 'role': 3, 'project': 1}],
            'tests': [
                # List effective roles filtering by one of the implied roles,
                # showing that the filter was implied post expansion of
                # implied roles (and that non implied roles are included in
                # the filter
                {'params': {'role': 3, 'effective': True},
                 'results': [{'user': 0, 'role': 3, 'project': 0,
                              'indirect': {'role': 1}},
                             {'user': 0, 'role': 3, 'project': 1}]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_role_assignments_simple_tree_of_implied_roles_on_domain(self):
        """Test that implied roles are expanded out when placed on a domain."""
        test_plan = {
            'entities': {'domains': {'users': 1},
                         'roles': 4},
            # Three level tree of implied roles
            'implied_roles': [{'role': 0, 'implied_roles': 1},
                              {'role': 1, 'implied_roles': [2, 3]}],
            'assignments': [{'user': 0, 'role': 0, 'domain': 0}],
            'tests': [
                # List all direct assignments for user[0], this should just
                # show the one top level role assignment
                {'params': {'user': 0},
                 'results': [{'user': 0, 'role': 0, 'domain': 0}]},
                # Listing in effective mode should how the implied roles
                # expanded out
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'domain': 0,
                              'indirect': {'role': 0}},
                             {'user': 0, 'role': 2, 'domain': 0,
                              'indirect': {'role': 1}},
                             {'user': 0, 'role': 3, 'domain': 0,
                              'indirect': {'role': 1}}]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_role_assignments_inherited_implied_roles(self):
        """Test that you can intermix inherited and implied roles."""
        test_plan = {
            'entities': {'domains': {'users': 1, 'projects': 1},
                         'roles': 4},
            # Simply one level of implied roles
            'implied_roles': [{'role': 0, 'implied_roles': 1}],
            # Assign to top level role as an inherited assignment to the
            # domain
            'assignments': [{'user': 0, 'role': 0, 'domain': 0,
                             'inherited_to_projects': True}],
            'tests': [
                # List all direct assignments for user[0], this should just
                # show the one top level role assignment
                {'params': {'user': 0},
                 'results': [{'user': 0, 'role': 0, 'domain': 0,
                              'inherited_to_projects': 'projects'}]},
                # List in effective mode - we should only see the initial and
                # implied role on the project (since inherited roles are not
                # active on their anchor point).
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0,
                              'indirect': {'domain': 0}},
                             {'user': 0, 'role': 1, 'project': 0,
                              'indirect': {'domain': 0, 'role': 0}}]},
            ]
        }
        self.execute_assignment_plan(test_plan)

    def test_role_assignments_domain_specific_with_implied_roles(self):
        test_plan = {
            'entities': {'domains': {'users': 1, 'projects': 1, 'roles': 2},
                         'roles': 2},
            # Two level tree of implied roles, with the top and 1st level being
            # domain specific roles, and the bottom level being inferred global
            # roles.
            'implied_roles': [{'role': 0, 'implied_roles': [1]},
                              {'role': 1, 'implied_roles': [2, 3]}],
            'assignments': [{'user': 0, 'role': 0, 'project': 0}],
            'tests': [
                # List all direct assignments for user[0], this should just
                # show the one top level role assignment, even though this is a
                # domain specific role (since we are in non-effective mode and
                # we show any direct role assignment in that mode).
                {'params': {'user': 0},
                 'results': [{'user': 0, 'role': 0, 'project': 0}]},
                # Now the effective ones - so the implied roles should be
                # expanded out, as well as any domain specific roles should be
                # removed.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 2, 'project': 0,
                              'indirect': {'role': 1}},
                             {'user': 0, 'role': 3, 'project': 0,
                              'indirect': {'role': 1}}]},
            ]
        }
        self.execute_assignment_plan(test_plan)


class SystemAssignmentTests(AssignmentTestHelperMixin):
    def test_create_system_grant_for_user(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']
        role_ref = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user_id, role_ref['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            user_id
        )
        self.assertEqual(len(system_roles), 1)
        self.assertIsNone(system_roles[0]['domain_id'])
        self.assertEqual(system_roles[0]['id'], role_ref['id'])
        self.assertEqual(system_roles[0]['name'], role_ref['name'])

    def test_list_system_grants_for_user(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']
        first_role = self._create_role()
        second_role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user_id, first_role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            user_id
        )
        self.assertEqual(len(system_roles), 1)

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user_id, second_role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            user_id
        )
        self.assertEqual(len(system_roles), 2)

    def test_check_system_grant_for_user(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']
        role = self._create_role()

        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.check_system_grant_for_user,
            user_id,
            role['id']
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user_id, role['id']
        )
        PROVIDERS.assignment_api.check_system_grant_for_user(
            user_id, role['id']
        )

    def test_delete_system_grant_for_user(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']
        role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user_id, role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            user_id
        )
        self.assertEqual(len(system_roles), 1)

        PROVIDERS.assignment_api.delete_system_grant_for_user(
            user_id, role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            user_id
        )
        self.assertEqual(len(system_roles), 0)

    def test_check_system_grant_for_user_with_invalid_role_fails(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']

        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.check_system_grant_for_user,
            user_id,
            uuid.uuid4().hex
        )

    def test_check_system_grant_for_user_with_invalid_user_fails(self):
        role = self._create_role()

        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.check_system_grant_for_user,
            uuid.uuid4().hex,
            role['id']
        )

    def test_delete_system_grant_for_user_with_invalid_role_fails(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']
        role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user_id, role['id']
        )
        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.delete_system_grant_for_user,
            user_id,
            uuid.uuid4().hex
        )

    def test_delete_system_grant_for_user_with_invalid_user_fails(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']
        role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user_id, role['id']
        )
        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.delete_system_grant_for_user,
            uuid.uuid4().hex,
            role['id']
        )

    def test_list_system_grants_for_user_returns_empty_list(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']

        system_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            user_id
        )
        self.assertFalse(system_roles)

    def test_create_system_grant_for_user_fails_with_domain_role(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_id = PROVIDERS.identity_api.create_user(user_ref)['id']
        role = self._create_role(domain_id=CONF.identity.default_domain_id)

        self.assertRaises(
            exception.ValidationError,
            PROVIDERS.assignment_api.create_system_grant_for_user,
            user_id,
            role['id']
        )

    def test_create_system_grant_for_group(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']
        role_ref = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, role_ref['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_group(
            group_id
        )
        self.assertEqual(len(system_roles), 1)
        self.assertIsNone(system_roles[0]['domain_id'])
        self.assertEqual(system_roles[0]['id'], role_ref['id'])
        self.assertEqual(system_roles[0]['name'], role_ref['name'])

    def test_list_system_grants_for_group(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']
        first_role = self._create_role()
        second_role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, first_role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_group(
            group_id
        )
        self.assertEqual(len(system_roles), 1)

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, second_role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_group(
            group_id
        )
        self.assertEqual(len(system_roles), 2)

    def test_check_system_grant_for_group(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']
        role = self._create_role()

        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.check_system_grant_for_group,
            group_id,
            role['id']
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, role['id']
        )
        PROVIDERS.assignment_api.check_system_grant_for_group(
            group_id, role['id']
        )

    def test_delete_system_grant_for_group(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']
        role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_group(
            group_id
        )
        self.assertEqual(len(system_roles), 1)

        PROVIDERS.assignment_api.delete_system_grant_for_group(
            group_id, role['id']
        )
        system_roles = PROVIDERS.assignment_api.list_system_grants_for_group(
            group_id
        )
        self.assertEqual(len(system_roles), 0)

    def test_check_system_grant_for_group_with_invalid_role_fails(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']

        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.check_system_grant_for_group,
            group_id,
            uuid.uuid4().hex
        )

    def test_check_system_grant_for_group_with_invalid_group_fails(self):
        role = self._create_role()

        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.check_system_grant_for_group,
            uuid.uuid4().hex,
            role['id']
        )

    def test_delete_system_grant_for_group_with_invalid_role_fails(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']
        role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, role['id']
        )
        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.delete_system_grant_for_group,
            group_id,
            uuid.uuid4().hex
        )

    def test_delete_system_grant_for_group_with_invalid_group_fails(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']
        role = self._create_role()

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group_id, role['id']
        )
        self.assertRaises(
            exception.RoleAssignmentNotFound,
            PROVIDERS.assignment_api.delete_system_grant_for_group,
            uuid.uuid4().hex,
            role['id']
        )

    def test_list_system_grants_for_group_returns_empty_list(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']

        system_roles = PROVIDERS.assignment_api.list_system_grants_for_group(
            group_id
        )
        self.assertFalse(system_roles)

    def test_create_system_grant_for_group_fails_with_domain_role(self):
        group_ref = unit.new_group_ref(CONF.identity.default_domain_id)
        group_id = PROVIDERS.identity_api.create_group(group_ref)['id']
        role = self._create_role(CONF.identity.default_domain_id)

        self.assertRaises(
            exception.ValidationError,
            PROVIDERS.assignment_api.create_system_grant_for_group,
            group_id,
            role['id']
        )

    def test_delete_role_with_system_assignments(self):
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user = unit.new_user_ref(domain_id=domain['id'])
        user = PROVIDERS.identity_api.create_user(user)

        # creating a system grant for user
        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], role['id']
        )
        # deleting the role user has on system
        PROVIDERS.role_api.delete_role(role['id'])
        system_roles = PROVIDERS.assignment_api.list_role_assignments(
            role_id=role['id']
        )
        self.assertEqual(len(system_roles), 0)
