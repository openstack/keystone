# Copyright 2012 OpenStack Foundation
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

import copy
import datetime
import hashlib
import uuid

from keystoneclient.common import cms
import mock
from oslo_config import cfg
from oslo_utils import timeutils
import six
from six.moves import range
from testtools import matchers

from keystone.catalog import core
from keystone.common import driver_hints
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import filtering
from keystone.tests.unit import utils as test_utils
from keystone.token import provider


CONF = cfg.CONF
NULL_OBJECT = object()


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
            new_project = self.resource_api.create_project(new_project['id'],
                                                           new_project)
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
        return self.role_api.create_role(new_role['id'], new_role)

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
                self.resource_api.create_domain(new_domain['id'],
                                                new_domain)
                return new_domain
            else:
                # The test plan specified an existing domain to use
                return self.resource_api.get_domain(domain_id)

        def _create_entity_in_domain(entity_type, domain_id):
            """Create a user or group entity in the domain."""
            if entity_type == 'users':
                new_entity = unit.new_user_ref(domain_id=domain_id)
                new_entity = self.identity_api.create_user(new_entity)
            elif entity_type == 'groups':
                new_entity = unit.new_group_ref(domain_id=domain_id)
                new_entity = self.identity_api.create_group(new_entity)
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
                    self.role_api.create_implied_role(prior_role, implied_role)
            else:
                implied_role = (
                    test_data['roles'][implied_spec['implied_roles']]['id'])
                self.role_api.create_implied_role(prior_role, implied_role)

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
                self.identity_api.add_user_to_group(user_value, group_value)
        return test_data

    def create_assignments(self, assignment_pattern, test_data):
        """Create the assignments specified in the test plan."""
        # First store how many assignments are already in the system,
        # so during the tests we can check the number of new assignments
        # created.
        test_data['initial_assignment_count'] = (
            len(self.assignment_api.list_role_assignments()))

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
            self.assignment_api.create_grant(**args)
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
            results = self.assignment_api.list_role_assignments(**args)
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


class IdentityTests(AssignmentTestHelperMixin):

    domain_count = len(default_fixtures.DOMAINS)

    def _get_domain_fixture(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        return domain

    def _set_domain_scope(self, domain_id):
        # We only provide a domain scope if we have multiple drivers
        if CONF.identity.domain_specific_drivers_enabled:
            return domain_id

    def test_project_add_and_remove_user_role(self):
        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_bar['id'])
        self.assertNotIn(self.user_two['id'], user_ids)

        self.assignment_api.add_role_to_user_and_project(
            tenant_id=self.tenant_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])
        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_bar['id'])
        self.assertIn(self.user_two['id'], user_ids)

        self.assignment_api.remove_role_from_user_and_project(
            tenant_id=self.tenant_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])

        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_bar['id'])
        self.assertNotIn(self.user_two['id'], user_ids)

    def test_remove_user_role_not_assigned(self):
        # Expect failure if attempt to remove a role that was never assigned to
        # the user.
        self.assertRaises(exception.RoleNotFound,
                          self.assignment_api.
                          remove_role_from_user_and_project,
                          tenant_id=self.tenant_bar['id'],
                          user_id=self.user_two['id'],
                          role_id=self.role_other['id'])

    def test_authenticate_bad_user(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=uuid.uuid4().hex,
                          password=self.user_foo['password'])

    def test_authenticate_bad_password(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=self.user_foo['id'],
                          password=uuid.uuid4().hex)

    def test_authenticate(self):
        user_ref = self.identity_api.authenticate(
            context={},
            user_id=self.user_sna['id'],
            password=self.user_sna['password'])
        # NOTE(termie): the password field is left in user_sna to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_sna.pop('password')
        self.user_sna['enabled'] = True
        self.assertDictEqual(self.user_sna, user_ref)

    def test_authenticate_and_get_roles_no_metadata(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        # Remove user id. It is ignored by create_user() and will break the
        # subset test below.
        del user['id']

        new_user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                new_user['id'])
        user_ref = self.identity_api.authenticate(
            context={},
            user_id=new_user['id'],
            password=user['password'])
        self.assertNotIn('password', user_ref)
        # NOTE(termie): the password field is left in user_sna to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        user.pop('password')
        self.assertDictContainsSubset(user, user_ref)
        role_list = self.assignment_api.get_roles_for_user_and_project(
            new_user['id'], self.tenant_baz['id'])
        self.assertEqual(1, len(role_list))
        self.assertIn(CONF.member_role_id, role_list)

    def test_authenticate_if_no_password_set(self):
        id_ = uuid.uuid4().hex
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user)

        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=id_,
                          password='password')

    def test_create_unicode_user_name(self):
        unicode_name = u'name \u540d\u5b57'
        user = unit.new_user_ref(name=unicode_name,
                                 domain_id=CONF.identity.default_domain_id)
        ref = self.identity_api.create_user(user)
        self.assertEqual(unicode_name, ref['name'])

    def test_get_project(self):
        tenant_ref = self.resource_api.get_project(self.tenant_bar['id'])
        self.assertDictEqual(self.tenant_bar, tenant_ref)

    def test_get_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          uuid.uuid4().hex)

    def test_get_project_by_name(self):
        tenant_ref = self.resource_api.get_project_by_name(
            self.tenant_bar['name'],
            CONF.identity.default_domain_id)
        self.assertDictEqual(self.tenant_bar, tenant_ref)

    @unit.skip_if_no_multiple_domains_support
    def test_get_project_by_name_for_project_acting_as_a_domain(self):
        """Tests get_project_by_name works when the domain_id is None."""
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, is_domain=False)
        project = self.resource_api.create_project(project['id'], project)

        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project_by_name,
                          project['name'],
                          None)

        # Test that querying with domain_id as None will find the project
        # acting as a domain, even if it's name is the same as the regular
        # project above.
        project2 = unit.new_project_ref(is_domain=True,
                                        name=project['name'])
        project2 = self.resource_api.create_project(project2['id'], project2)

        project_ref = self.resource_api.get_project_by_name(
            project2['name'], None)

        self.assertEqual(project2, project_ref)

    def test_get_project_by_name_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    def test_list_user_ids_for_project(self):
        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_baz['id'])
        self.assertEqual(2, len(user_ids))
        self.assertIn(self.user_two['id'], user_ids)
        self.assertIn(self.user_badguy['id'], user_ids)

    def test_list_user_ids_for_project_no_duplicates(self):
        # Create user
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_ref = self.identity_api.create_user(user_ref)
        # Create project
        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(
            project_ref['id'], project_ref)
        # Create 2 roles and give user each role in project
        for i in range(2):
            role_ref = unit.new_role_ref()
            self.role_api.create_role(role_ref['id'], role_ref)
            self.assignment_api.add_role_to_user_and_project(
                user_id=user_ref['id'],
                tenant_id=project_ref['id'],
                role_id=role_ref['id'])
        # Get the list of user_ids in project
        user_ids = self.assignment_api.list_user_ids_for_project(
            project_ref['id'])
        # Ensure the user is only returned once
        self.assertEqual(1, len(user_ids))

    def test_get_project_user_ids_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.list_user_ids_for_project,
                          uuid.uuid4().hex)

    def test_get_user(self):
        user_ref = self.identity_api.get_user(self.user_foo['id'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(self.user_foo, user_ref)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        # cache the result.
        self.identity_api.get_user(ref['id'])
        # delete bypassing identity api
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(ref['id']))
        driver.delete_user(entity_id)

        self.assertDictEqual(ref, self.identity_api.get_user(ref['id']))
        self.identity_api.get_user.invalidate(self.identity_api, ref['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user, ref['id'])
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        user['description'] = uuid.uuid4().hex
        # cache the result.
        self.identity_api.get_user(ref['id'])
        # update using identity api and get back updated user.
        user_updated = self.identity_api.update_user(ref['id'], user)
        self.assertDictContainsSubset(self.identity_api.get_user(ref['id']),
                                      user_updated)
        self.assertDictContainsSubset(
            self.identity_api.get_user_by_name(ref['name'], ref['domain_id']),
            user_updated)

    def test_get_user_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          uuid.uuid4().hex)

    def test_get_user_by_name(self):
        user_ref = self.identity_api.get_user_by_name(
            self.user_foo['name'], CONF.identity.default_domain_id)
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(self.user_foo, user_ref)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user_by_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        # delete bypassing the identity api.
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(ref['id']))
        driver.delete_user(entity_id)

        self.assertDictEqual(ref, self.identity_api.get_user_by_name(
            user['name'], CONF.identity.default_domain_id))
        self.identity_api.get_user_by_name.invalidate(
            self.identity_api, user['name'], CONF.identity.default_domain_id)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          user['name'], CONF.identity.default_domain_id)
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        user['description'] = uuid.uuid4().hex
        user_updated = self.identity_api.update_user(ref['id'], user)
        self.assertDictContainsSubset(self.identity_api.get_user(ref['id']),
                                      user_updated)
        self.assertDictContainsSubset(
            self.identity_api.get_user_by_name(ref['name'], ref['domain_id']),
            user_updated)

    def test_get_user_by_name_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    def test_create_duplicate_user_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_user,
                          user)

    def test_create_duplicate_user_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        user1 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user2 = unit.new_user_ref(name=user1['name'],
                                  domain_id=new_domain['id'])

        self.identity_api.create_user(user1)
        self.identity_api.create_user(user2)

    def test_move_user_between_domains(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        user = unit.new_user_ref(domain_id=domain1['id'])
        user = self.identity_api.create_user(user)
        user['domain_id'] = domain2['id']
        # Update the user asserting that a deprecation warning is emitted
        with mock.patch(
                'oslo_log.versionutils.report_deprecated_feature') as mock_dep:
            self.identity_api.update_user(user['id'], user)
            self.assertTrue(mock_dep.called)

        updated_user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(domain2['id'], updated_user_ref['domain_id'])

    def test_move_user_between_domains_with_clashing_names_fails(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a user in domain1
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        # Now create a user in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        user2 = unit.new_user_ref(name=user1['name'],
                                  domain_id=domain2['id'])
        user2 = self.identity_api.create_user(user2)
        # Now try and move user1 into the 2nd domain - which should
        # fail since the names clash
        user1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          user1['id'],
                          user1)

    def test_rename_duplicate_user_name_fails(self):
        user1 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user2 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user1)
        user2 = self.identity_api.create_user(user2)
        user2['name'] = user1['name']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          user2['id'],
                          user2)

    def test_update_user_id_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        original_id = user['id']
        user['id'] = 'fake2'
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          original_id,
                          user)
        user_ref = self.identity_api.get_user(original_id)
        self.assertEqual(original_id, user_ref['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          'fake2')

    def test_create_duplicate_project_id_fails(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        self.resource_api.create_project(project_id, project)
        project['name'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.resource_api.create_project,
                          project_id,
                          project)

    def test_create_duplicate_project_name_fails(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        self.resource_api.create_project(project_id, project)
        project['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_duplicate_project_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project2 = unit.new_project_ref(name=project1['name'],
                                        domain_id=new_domain['id'])
        self.resource_api.create_project(project1['id'], project1)
        self.resource_api.create_project(project2['id'], project2)

    def test_move_project_between_domains(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        project = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project['id'], project)
        project['domain_id'] = domain2['id']
        # Update the project asserting that a deprecation warning is emitted
        with mock.patch(
                'oslo_log.versionutils.report_deprecated_feature') as mock_dep:
            self.resource_api.update_project(project['id'], project)
            self.assertTrue(mock_dep.called)

        updated_project_ref = self.resource_api.get_project(project['id'])
        self.assertEqual(domain2['id'], updated_project_ref['domain_id'])

    def test_move_project_between_domains_with_clashing_names_fails(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a project in domain1
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        # Now create a project in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        project2 = unit.new_project_ref(name=project1['name'],
                                        domain_id=domain2['id'])
        self.resource_api.create_project(project2['id'], project2)
        # Now try and move project1 into the 2nd domain - which should
        # fail since the names clash
        project1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.resource_api.update_project,
                          project1['id'],
                          project1)

    @unit.skip_if_no_multiple_domains_support
    def test_move_project_with_children_between_domains_fails(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        project = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project['id'], project)
        child_project = unit.new_project_ref(domain_id=domain1['id'],
                                             parent_id=project['id'])
        self.resource_api.create_project(child_project['id'], child_project)
        project['domain_id'] = domain2['id']

        # Update is not allowed, since updating the whole subtree would be
        # necessary
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

    @unit.skip_if_no_multiple_domains_support
    def test_move_project_not_root_between_domains_fails(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        project = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project['id'], project)
        child_project = unit.new_project_ref(domain_id=domain1['id'],
                                             parent_id=project['id'])
        self.resource_api.create_project(child_project['id'], child_project)
        child_project['domain_id'] = domain2['id']

        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          child_project['id'],
                          child_project)

    @unit.skip_if_no_multiple_domains_support
    def test_move_root_project_between_domains_succeeds(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        root_project = unit.new_project_ref(domain_id=domain1['id'])
        root_project = self.resource_api.create_project(root_project['id'],
                                                        root_project)

        root_project['domain_id'] = domain2['id']
        self.resource_api.update_project(root_project['id'], root_project)
        project_from_db = self.resource_api.get_project(root_project['id'])

        self.assertEqual(domain2['id'], project_from_db['domain_id'])

    @unit.skip_if_no_multiple_domains_support
    def test_update_domain_id_project_is_domain_fails(self):
        other_domain = unit.new_domain_ref()
        self.resource_api.create_domain(other_domain['id'], other_domain)
        project = unit.new_project_ref(is_domain=True)
        self.resource_api.create_project(project['id'], project)
        project['domain_id'] = other_domain['id']

        # Update of domain_id of projects acting as domains is not allowed
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

    def test_rename_duplicate_project_name_fails(self):
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project1['id'], project1)
        self.resource_api.create_project(project2['id'], project2)
        project2['name'] = project1['name']
        self.assertRaises(exception.Error,
                          self.resource_api.update_project,
                          project2['id'],
                          project2)

    def test_update_project_id_does_nothing(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        self.resource_api.create_project(project['id'], project)
        project['id'] = 'fake2'
        self.resource_api.update_project(project_id, project)
        project_ref = self.resource_api.get_project(project_id)
        self.assertEqual(project_id, project_ref['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          'fake2')

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
        assignment_list = self.assignment_api.list_role_assignments(
            role_id=uuid.uuid4().hex)
        self.assertEqual([], assignment_list)

    def test_add_duplicate_role_grant(self):
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], self.role_admin['id'])
        self.assertRaises(exception.Conflict,
                          self.assignment_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          self.role_admin['id'])

    def test_get_role_by_user_and_project_with_user_in_group(self):
        """Test for get role by user and project, user was added into a group.

        Test Plan:

        - Create a user, a project & a group, add this user to group
        - Create roles and grant them to user and project
        - Check the role list get by the user and project was as expected

        """
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_ref = self.identity_api.create_user(user_ref)

        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_id = self.identity_api.create_group(group)['id']
        self.identity_api.add_user_to_group(user_ref['id'], group_id)

        role_ref_list = []
        for i in range(2):
            role_ref = unit.new_role_ref()
            self.role_api.create_role(role_ref['id'], role_ref)
            role_ref_list.append(role_ref)

            self.assignment_api.add_role_to_user_and_project(
                user_id=user_ref['id'],
                tenant_id=project_ref['id'],
                role_id=role_ref['id'])

        role_list = self.assignment_api.get_roles_for_user_and_project(
            user_ref['id'],
            project_ref['id'])

        self.assertEqual(set([r['id'] for r in role_ref_list]),
                         set(role_list))

    def test_get_role_by_user_and_project(self):
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], self.role_admin['id'])
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'], roles_ref)
        self.assertNotIn('member', roles_ref)

        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'], roles_ref)
        self.assertIn('member', roles_ref)

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
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_user1 = unit.new_user_ref(domain_id=new_domain['id'])
        new_user1 = self.identity_api.create_user(new_user1)
        new_user2 = unit.new_user_ref(domain_id=new_domain['id'])
        new_user2 = self.identity_api.create_user(new_user2)
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user1['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        # Now create the grants (roles are defined in default_fixtures)
        self.assignment_api.create_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        self.assignment_api.create_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='other')
        self.assignment_api.create_grant(user_id=new_user2['id'],
                                         domain_id=new_domain['id'],
                                         role_id='admin')
        # Read back the roles for user1 on domain
        roles_ids = self.assignment_api.get_roles_for_user_and_domain(
            new_user1['id'], new_domain['id'])
        self.assertEqual(2, len(roles_ids))
        self.assertIn(self.role_member['id'], roles_ids)
        self.assertIn(self.role_other['id'], roles_ids)

        # Now delete both grants for user1
        self.assignment_api.delete_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        self.assignment_api.delete_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='other')
        roles_ref = self.assignment_api.list_grants(
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
        new_user1 = self.identity_api.create_user(new_user1)

        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.get_roles_for_user_and_domain,
                          uuid.uuid4().hex,
                          new_domain['id'])

        self.assertRaises(exception.DomainNotFound,
                          self.assignment_api.get_roles_for_user_and_domain,
                          new_user1['id'],
                          uuid.uuid4().hex)

    def test_get_roles_for_user_and_project_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.get_roles_for_user_and_project,
                          uuid.uuid4().hex,
                          self.tenant_bar['id'])

        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_roles_for_user_and_project,
                          self.user_foo['id'],
                          uuid.uuid4().hex)

    def test_add_role_to_user_and_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          uuid.uuid4().hex,
                          self.role_admin['id'])

        self.assertRaises(exception.RoleNotFound,
                          self.assignment_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          uuid.uuid4().hex)

    def test_add_role_to_user_and_project_no_user(self):
        # If add_role_to_user_and_project and the user doesn't exist, then
        # no error.
        user_id_not_exist = uuid.uuid4().hex
        self.assignment_api.add_role_to_user_and_project(
            user_id_not_exist, self.tenant_bar['id'], self.role_admin['id'])

    def test_remove_role_from_user_and_project(self):
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        self.assignment_api.remove_role_from_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn('member', roles_ref)
        self.assertRaises(exception.NotFound,
                          self.assignment_api.
                          remove_role_from_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          'member')

    def test_get_role_grant_by_user_and_project(self):
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])
        self.assertEqual(1, len(roles_ref))
        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_admin['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'],
                      [role_ref['id'] for role_ref in roles_ref])

        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(self.role_admin['id'], roles_ref_ids)
        self.assertIn('member', roles_ref_ids)

    def test_remove_role_grant_from_user_and_project(self):
        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_baz['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        self.assignment_api.delete_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_baz['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_get_role_assignment_by_project_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          group_id=uuid.uuid4().hex,
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_get_role_assignment_by_domain_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          user_id=self.user_foo['id'],
                          domain_id=self.domain_default['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          group_id=uuid.uuid4().hex,
                          domain_id=self.domain_default['id'],
                          role_id='member')

    def test_del_role_assignment_by_project_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=uuid.uuid4().hex,
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_del_role_assignment_by_domain_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          domain_id=self.domain_default['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=uuid.uuid4().hex,
                          domain_id=self.domain_default['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_project(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        self.assignment_api.delete_grant(group_id=new_group['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          project_id=self.tenant_bar['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_domain(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])

        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))

        self.assignment_api.create_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')

        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        self.assignment_api.delete_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_correct_role_grant_from_a_mix(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        self.resource_api.create_project(new_project['id'], new_project)
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_group2 = unit.new_group_ref(domain_id=new_domain['id'])
        new_group2 = self.identity_api.create_group(new_group2)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = self.identity_api.create_user(new_user)
        new_user2 = unit.new_user_ref(domain_id=new_domain['id'])
        new_user2 = self.identity_api.create_user(new_user2)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        # First check we have no grants
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        # Now add the grant we are going to test for, and some others as
        # well just to make sure we get back the right one
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')

        self.assignment_api.create_grant(group_id=new_group2['id'],
                                         domain_id=new_domain['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(user_id=new_user2['id'],
                                         domain_id=new_domain['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=new_project['id'],
                                         role_id=self.role_admin['id'])

        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        self.assignment_api.delete_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_user_and_domain(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_user = self.identity_api.create_user(new_user)
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(self.role_member, roles_ref[0])

        self.assignment_api.delete_grant(user_id=new_user['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=new_user['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_cross_domain(self):
        group1_domain1_role = unit.new_role_ref()
        self.role_api.create_role(group1_domain1_role['id'],
                                  group1_domain1_role)
        group1_domain2_role = unit.new_role_ref()
        self.role_api.create_role(group1_domain2_role['id'],
                                  group1_domain2_role)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=group1_domain1_role['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain2['id'],
                                         role_id=group1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(group1_domain1_role, roles_ref[0])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(group1_domain2_role, roles_ref[0])

        self.assignment_api.delete_grant(group_id=group1['id'],
                                         domain_id=domain2['id'],
                                         role_id=group1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=group1['id'],
                          domain_id=domain2['id'],
                          role_id=group1_domain2_role['id'])

    def test_get_and_remove_role_grant_by_user_and_cross_domain(self):
        user1_domain1_role = unit.new_role_ref()
        self.role_api.create_role(user1_domain1_role['id'], user1_domain1_role)
        user1_domain2_role = unit.new_role_ref()
        self.role_api.create_role(user1_domain2_role['id'], user1_domain2_role)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=user1_domain1_role['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain2['id'],
                                         role_id=user1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(user1_domain1_role, roles_ref[0])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(user1_domain2_role, roles_ref[0])

        self.assignment_api.delete_grant(user_id=user1['id'],
                                         domain_id=domain2['id'],
                                         role_id=user1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=user1['id'],
                          domain_id=domain2['id'],
                          role_id=user1_domain2_role['id'])

    def test_role_grant_by_group_and_cross_domain_project(self):
        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref()
        self.role_api.create_role(role2['id'], role2)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        project1 = unit.new_project_ref(domain_id=domain2['id'])
        self.resource_api.create_project(project1['id'], project1)
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role2['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        self.assignment_api.delete_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        self.assertDictEqual(role2, roles_ref[0])

    def test_role_grant_by_user_and_cross_domain_project(self):
        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref()
        self.role_api.create_role(role2['id'], role2)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        project1 = unit.new_project_ref(domain_id=domain2['id'])
        self.resource_api.create_project(project1['id'], project1)
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role2['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        self.assignment_api.delete_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        self.assertDictEqual(role2, roles_ref[0])

    def test_delete_user_grant_no_user(self):
        # Can delete a grant where the user doesn't exist.
        role = unit.new_role_ref()
        role_id = role['id']
        self.role_api.create_role(role_id, role)

        user_id = uuid.uuid4().hex

        self.assignment_api.create_grant(role_id, user_id=user_id,
                                         project_id=self.tenant_bar['id'])

        self.assignment_api.delete_grant(role_id, user_id=user_id,
                                         project_id=self.tenant_bar['id'])

    def test_delete_group_grant_no_group(self):
        # Can delete a grant where the group doesn't exist.
        role = unit.new_role_ref()
        role_id = role['id']
        self.role_api.create_role(role_id, role)

        group_id = uuid.uuid4().hex

        self.assignment_api.create_grant(role_id, group_id=group_id,
                                         project_id=self.tenant_bar['id'])

        self.assignment_api.delete_grant(role_id, group_id=group_id,
                                         project_id=self.tenant_bar['id'])

    def test_grant_crud_throws_exception_if_invalid_role(self):
        """Ensure RoleNotFound thrown if role does not exist."""
        def assert_role_not_found_exception(f, **kwargs):
            self.assertRaises(exception.RoleNotFound, f,
                              role_id=uuid.uuid4().hex, **kwargs)

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_resp = self.identity_api.create_user(user)
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_resp = self.identity_api.create_group(group)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_resp = self.resource_api.create_project(project['id'], project)

        for manager_call in [self.assignment_api.create_grant,
                             self.assignment_api.get_grant,
                             self.assignment_api.delete_grant]:
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

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        role_list = []
        for _ in range(10):
            role = unit.new_role_ref()
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain1['id'])
        group2 = self.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user1['id'],
                                            group2['id'])

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[3]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[4]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[5]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[6]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[7]['id'])
        roles_ref = self.assignment_api.list_grants(user_id=user1['id'],
                                                    domain_id=domain1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[0], roles_ref)
        self.assertIn(role_list[1], roles_ref)
        roles_ref = self.assignment_api.list_grants(group_id=group1['id'],
                                                    domain_id=domain1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[2], roles_ref)
        self.assertIn(role_list[3], roles_ref)
        roles_ref = self.assignment_api.list_grants(user_id=user1['id'],
                                                    project_id=project1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[4], roles_ref)
        self.assertIn(role_list[5], roles_ref)
        roles_ref = self.assignment_api.list_grants(group_id=group1['id'],
                                                    project_id=project1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[6], roles_ref)
        self.assertIn(role_list[7], roles_ref)

        # Now test the alternate way of getting back lists of grants,
        # where user and group roles are combined.  These should match
        # the above results.
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(4, len(combined_list))
        self.assertIn(role_list[4]['id'], combined_list)
        self.assertIn(role_list[5]['id'], combined_list)
        self.assertIn(role_list[6]['id'], combined_list)
        self.assertIn(role_list[7]['id'], combined_list)

        combined_role_list = self.assignment_api.get_roles_for_user_and_domain(
            user1['id'], domain1['id'])
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
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain1['id'])
        group2 = self.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user1['id'],
                                            group2['id'])

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[3]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[4]['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[5]['id'])

        # Read by the roles, ensuring we get the correct 3 roles for
        # both project and domain
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(3, len(combined_list))
        self.assertIn(role_list[3]['id'], combined_list)
        self.assertIn(role_list[4]['id'], combined_list)
        self.assertIn(role_list[5]['id'], combined_list)

        combined_role_list = self.assignment_api.get_roles_for_user_and_domain(
            user1['id'], domain1['id'])
        self.assertEqual(3, len(combined_role_list))
        self.assertIn(role_list[0]['id'], combined_role_list)
        self.assertIn(role_list[1]['id'], combined_role_list)
        self.assertIn(role_list[2]['id'], combined_role_list)

    def test_delete_role_with_user_and_group_grants(self):
        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        self.role_api.delete_role(role1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))

    def test_delete_user_with_group_project_domain_links(self):
        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        self.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        self.identity_api.delete_user(user1['id'])
        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          user1['id'],
                          group1['id'])

    def test_delete_group_with_user_project_domain_links(self):
        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)

        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group1['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        self.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        self.identity_api.delete_group(group1['id'])
        self.identity_api.get_user(user1['id'])

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
        group = self.identity_api.create_group(group)
        self.assertRaises(exception.UnexpectedError,
                          self.assignment_api.list_role_assignments,
                          effective=True,
                          user_id=self.user_foo['id'],
                          source_from_group_ids=[group['id']])

    def test_delete_domain_with_user_group_project_links(self):
        # TODO(chungg):add test case once expected behaviour defined
        pass

    def test_add_user_to_project(self):
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        tenants = self.assignment_api.list_projects_for_user(
            self.user_foo['id'])
        self.assertIn(self.tenant_baz, tenants)

    def test_add_user_to_project_missing_default_role(self):
        self.role_api.delete_role(CONF.member_role_id)
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          CONF.member_role_id)
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        tenants = (
            self.assignment_api.list_projects_for_user(self.user_foo['id']))
        self.assertIn(self.tenant_baz, tenants)
        default_role = self.role_api.get_role(CONF.member_role_id)
        self.assertIsNotNone(default_role)

    def test_add_user_to_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.add_user_to_project,
                          uuid.uuid4().hex,
                          self.user_foo['id'])

    def test_add_user_to_project_no_user(self):
        # If add_user_to_project and the user doesn't exist, then
        # no error.
        user_id_not_exist = uuid.uuid4().hex
        self.assignment_api.add_user_to_project(self.tenant_bar['id'],
                                                user_id_not_exist)

    def test_remove_user_from_project(self):
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        self.assignment_api.remove_user_from_project(self.tenant_baz['id'],
                                                     self.user_foo['id'])
        tenants = self.assignment_api.list_projects_for_user(
            self.user_foo['id'])
        self.assertNotIn(self.tenant_baz, tenants)

    def test_remove_user_from_project_race_delete_role(self):
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        self.assignment_api.add_role_to_user_and_project(
            tenant_id=self.tenant_baz['id'],
            user_id=self.user_foo['id'],
            role_id=self.role_other['id'])

        # Mock a race condition, delete a role after
        # get_roles_for_user_and_project() is called in
        # remove_user_from_project().
        roles = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_baz['id'])
        self.role_api.delete_role(self.role_other['id'])
        self.assignment_api.get_roles_for_user_and_project = mock.Mock(
            return_value=roles)
        self.assignment_api.remove_user_from_project(self.tenant_baz['id'],
                                                     self.user_foo['id'])
        tenants = self.assignment_api.list_projects_for_user(
            self.user_foo['id'])
        self.assertNotIn(self.tenant_baz, tenants)

    def test_remove_user_from_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.remove_user_from_project,
                          uuid.uuid4().hex,
                          self.user_foo['id'])

        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.remove_user_from_project,
                          self.tenant_bar['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.NotFound,
                          self.assignment_api.remove_user_from_project,
                          self.tenant_baz['id'],
                          self.user_foo['id'])

    def test_list_user_project_ids_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          uuid.uuid4().hex)

    def test_update_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.update_project,
                          uuid.uuid4().hex,
                          dict())

    def test_delete_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.delete_project,
                          uuid.uuid4().hex)

    def test_update_user_returns_not_found(self):
        user_id = uuid.uuid4().hex
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.update_user,
                          user_id,
                          {'id': user_id,
                           'domain_id': CONF.identity.default_domain_id})

    def test_delete_user_with_project_association(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_bar['id'],
                                                user['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          user['id'])

    def test_delete_user_with_project_roles(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.assignment_api.add_role_to_user_and_project(
            user['id'],
            self.tenant_bar['id'],
            self.role_member['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          user['id'])

    def test_delete_user_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.delete_user,
                          uuid.uuid4().hex)

    def test_delete_role_returns_not_found(self):
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.delete_role,
                          uuid.uuid4().hex)

    def test_create_update_delete_unicode_project(self):
        unicode_project_name = u'name \u540d\u5b57'
        project = unit.new_project_ref(
            name=unicode_project_name,
            domain_id=CONF.identity.default_domain_id)
        project = self.resource_api.create_project(project['id'], project)
        self.resource_api.update_project(project['id'], project)
        self.resource_api.delete_project(project['id'])

    def test_create_project_with_no_enabled_field(self):
        ref = unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        del ref['enabled']
        self.resource_api.create_project(ref['id'], ref)

        project = self.resource_api.get_project(ref['id'])
        self.assertIs(project['enabled'], True)

    def test_create_project_long_name_fails(self):
        project = unit.new_project_ref(
            name='a' * 65, domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_project_blank_name_fails(self):
        project = unit.new_project_ref(
            name='', domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_project_invalid_name_fails(self):
        project = unit.new_project_ref(
            name=None, domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'],
                          project)
        project = unit.new_project_ref(
            name=123, domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_update_project_blank_name_fails(self):
        project = unit.new_project_ref(
            name='fake1', domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)
        project['name'] = ''
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

    def test_update_project_long_name_fails(self):
        project = unit.new_project_ref(
            name='fake1', domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)
        project['name'] = 'a' * 65
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

    def test_update_project_invalid_name_fails(self):
        project = unit.new_project_ref(
            name='fake1', domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)
        project['name'] = None
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

        project['name'] = 123
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

    def test_create_user_long_name_fails(self):
        user = unit.new_user_ref(name='a' * 256,
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_create_user_blank_name_fails(self):
        user = unit.new_user_ref(name='',
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_create_user_missed_password(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.identity_api.get_user(user['id'])
        # Make sure  the user is not allowed to login
        # with a password that  is empty string or None
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password='')
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password=None)

    def test_create_user_none_password(self):
        user = unit.new_user_ref(password=None,
                                 domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.identity_api.get_user(user['id'])
        # Make sure  the user is not allowed to login
        # with a password that  is empty string or None
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password='')
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password=None)

    def test_create_user_invalid_name_fails(self):
        user = unit.new_user_ref(name=None,
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

        user = unit.new_user_ref(name=123,
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_update_project_invalid_enabled_type_string(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertTrue(project_ref['enabled'])

        # Strings are not valid boolean values
        project['enabled'] = "false"
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

    def test_create_project_invalid_enabled_type_string(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            # invalid string value
            enabled="true")
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_project_invalid_domain_id(self):
        project = unit.new_project_ref(domain_id=uuid.uuid4().hex)
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_user_invalid_enabled_type_string(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 # invalid string value
                                 enabled='true')
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_update_user_long_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user['name'] = 'a' * 256
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_user_blank_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user['name'] = ''
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_user_invalid_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)

        user['name'] = None
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

        user['name'] = 123
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_list_users(self):
        users = self.identity_api.list_users(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(len(default_fixtures.USERS), len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['id'])['id']
                                for user in default_fixtures.USERS)
        for user_ref in users:
            self.assertNotIn('password', user_ref)
        self.assertEqual(expected_user_ids, user_ids)

    def test_list_groups(self):
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group1 = self.identity_api.create_group(group1)
        group2 = self.identity_api.create_group(group2)
        groups = self.identity_api.list_groups(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(2, len(groups))
        group_ids = []
        for group in groups:
            group_ids.append(group.get('id'))
        self.assertIn(group1['id'], group_ids)
        self.assertIn(group2['id'], group_ids)

    def test_list_domains(self):
        domain1 = unit.new_domain_ref()
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        self.resource_api.create_domain(domain2['id'], domain2)
        domains = self.resource_api.list_domains()
        self.assertEqual(3, len(domains))
        domain_ids = []
        for domain in domains:
            domain_ids.append(domain.get('id'))
        self.assertIn(CONF.identity.default_domain_id, domain_ids)
        self.assertIn(domain1['id'], domain_ids)
        self.assertIn(domain2['id'], domain_ids)

    def test_list_projects(self):
        project_refs = self.resource_api.list_projects()
        project_count = len(default_fixtures.TENANTS) + self.domain_count
        self.assertEqual(project_count, len(project_refs))
        for project in default_fixtures.TENANTS:
            self.assertIn(project, project_refs)

    def test_list_projects_with_multiple_filters(self):
        # Create a project
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project = self.resource_api.create_project(project['id'], project)

        # Build driver hints with the project's name and inexistent description
        hints = driver_hints.Hints()
        hints.add_filter('name', project['name'])
        hints.add_filter('description', uuid.uuid4().hex)

        # Retrieve projects based on hints and check an empty list is returned
        projects = self.resource_api.list_projects(hints)
        self.assertEqual([], projects)

        # Build correct driver hints
        hints = driver_hints.Hints()
        hints.add_filter('name', project['name'])
        hints.add_filter('description', project['description'])

        # Retrieve projects based on hints
        projects = self.resource_api.list_projects(hints)

        # Check that the returned list contains only the first project
        self.assertEqual(1, len(projects))
        self.assertEqual(project, projects[0])

    def test_list_projects_for_domain(self):
        project_ids = ([x['id'] for x in
                       self.resource_api.list_projects_in_domain(
                           CONF.identity.default_domain_id)])
        # Only the projects from the default fixtures are expected, since
        # filtering by domain does not include any project that acts as a
        # domain.
        self.assertThat(
            project_ids, matchers.HasLength(len(default_fixtures.TENANTS)))
        self.assertIn(self.tenant_bar['id'], project_ids)
        self.assertIn(self.tenant_baz['id'], project_ids)
        self.assertIn(self.tenant_mtu['id'], project_ids)
        self.assertIn(self.tenant_service['id'], project_ids)

    @unit.skip_if_no_multiple_domains_support
    def test_list_projects_acting_as_domain(self):
        initial_domains = self.resource_api.list_domains()

        # Creating 5 projects that act as domains
        new_projects_acting_as_domains = []
        for i in range(5):
            project = unit.new_project_ref(is_domain=True)
            project = self.resource_api.create_project(project['id'], project)
            new_projects_acting_as_domains.append(project)

        # Creating a few regular project to ensure it doesn't mess with the
        # ones that act as domains
        self._create_projects_hierarchy(hierarchy_size=2)

        projects = self.resource_api.list_projects_acting_as_domain()
        expected_number_projects = (
            len(initial_domains) + len(new_projects_acting_as_domains))
        self.assertEqual(expected_number_projects, len(projects))
        for project in new_projects_acting_as_domains:
            self.assertIn(project, projects)
        for domain in initial_domains:
            self.assertIn(domain['id'], [p['id'] for p in projects])

    @unit.skip_if_no_multiple_domains_support
    def test_list_projects_for_alternate_domain(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project2['id'], project2)
        project_ids = ([x['id'] for x in
                       self.resource_api.list_projects_in_domain(
                           domain1['id'])])
        self.assertEqual(2, len(project_ids))
        self.assertIn(project1['id'], project_ids)
        self.assertIn(project2['id'], project_ids)

    def _create_projects_hierarchy(self, hierarchy_size=2,
                                   domain_id=None,
                                   is_domain=False,
                                   parent_project_id=None):
        """Creates a project hierarchy with specified size.

        :param hierarchy_size: the desired hierarchy size, default is 2 -
                               a project with one child.
        :param domain_id: domain where the projects hierarchy will be created.
        :param is_domain: if the hierarchy will have the is_domain flag active
                          or not.
        :param parent_project_id: if the intention is to create a
            sub-hierarchy, sets the sub-hierarchy root. Defaults to creating
            a new hierarchy, i.e. a new root project.

        :returns projects: a list of the projects in the created hierarchy.

        """
        if domain_id is None:
            domain_id = CONF.identity.default_domain_id
        if parent_project_id:
            project = unit.new_project_ref(parent_id=parent_project_id,
                                           domain_id=domain_id,
                                           is_domain=is_domain)
        else:
            project = unit.new_project_ref(domain_id=domain_id,
                                           is_domain=is_domain)
        project_id = project['id']
        project = self.resource_api.create_project(project_id, project)

        projects = [project]
        for i in range(1, hierarchy_size):
            new_project = unit.new_project_ref(parent_id=project_id,
                                               domain_id=domain_id)

            self.resource_api.create_project(new_project['id'], new_project)
            projects.append(new_project)
            project_id = new_project['id']

        return projects

    @unit.skip_if_no_multiple_domains_support
    def test_create_domain_with_project_api(self):
        project = unit.new_project_ref(is_domain=True)
        ref = self.resource_api.create_project(project['id'], project)
        self.assertTrue(ref['is_domain'])
        self.resource_api.get_domain(ref['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_project_as_a_domain_uniqueness_constraints(self):
        """Tests project uniqueness for those acting as domains.

        If it is a project acting as a domain, we can't have two or more with
        the same name.

        """
        # Create two projects acting as a domain
        project = unit.new_project_ref(is_domain=True)
        project = self.resource_api.create_project(project['id'], project)
        project2 = unit.new_project_ref(is_domain=True)
        project2 = self.resource_api.create_project(project2['id'], project2)

        # All projects acting as domains have a null domain_id, so should not
        # be able to create another with the same name but a different
        # project ID.
        new_project = project.copy()
        new_project['id'] = uuid.uuid4().hex

        self.assertRaises(exception.Conflict,
                          self.resource_api.create_project,
                          new_project['id'],
                          new_project)

        # We also should not be able to update one to have a name clash
        project2['name'] = project['name']
        self.assertRaises(exception.Conflict,
                          self.resource_api.update_project,
                          project2['id'],
                          project2)

        # But updating it to a unique name is OK
        project2['name'] = uuid.uuid4().hex
        self.resource_api.update_project(project2['id'], project2)

        # Finally, it should be OK to create a project with same name as one of
        # these acting as a domain, as long as it is a regular project
        project3 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, name=project2['name'])
        self.resource_api.create_project(project3['id'], project3)
        # In fact, it should be OK to create such a project in the domain which
        # has the matching name.
        # TODO(henry-nash): Once we fully support projects acting as a domain,
        # add a test here to create a sub-project with a name that matches its
        # project acting as a domain

    @unit.skip_if_no_multiple_domains_support
    @test_utils.wip('waiting for sub projects acting as domains support')
    def test_is_domain_sub_project_has_parent_domain_id(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, is_domain=True)
        self.resource_api.create_project(project['id'], project)

        sub_project = unit.new_project_ref(domain_id=project['id'],
                                           parent_id=project['id'],
                                           is_domain=True)

        ref = self.resource_api.create_project(sub_project['id'], sub_project)
        self.assertTrue(ref['is_domain'])
        self.assertEqual(project['id'], ref['parent_id'])
        self.assertEqual(project['id'], ref['domain_id'])

    @unit.skip_if_no_multiple_domains_support
    def test_delete_domain_with_project_api(self):
        project = unit.new_project_ref(domain_id=None,
                                       is_domain=True)
        self.resource_api.create_project(project['id'], project)

        # Check that a corresponding domain was created
        self.resource_api.get_domain(project['id'])

        # Try to delete the enabled project that acts as a domain
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.delete_project,
                          project['id'])

        # Disable the project
        project['enabled'] = False
        self.resource_api.update_project(project['id'], project)

        # Successfully delete the project
        self.resource_api.delete_project(project['id'])

        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project['id'])

        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          project['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_create_subproject_acting_as_domain_fails(self):
        root_project = unit.new_project_ref(is_domain=True)
        self.resource_api.create_project(root_project['id'], root_project)

        sub_project = unit.new_project_ref(is_domain=True,
                                           parent_id=root_project['id'])

        # Creation of sub projects acting as domains is not allowed yet
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          sub_project['id'], sub_project)

    @unit.skip_if_no_multiple_domains_support
    def test_create_domain_under_regular_project_hierarchy_fails(self):
        # Projects acting as domains can't have a regular project as parent
        projects_hierarchy = self._create_projects_hierarchy()
        parent = projects_hierarchy[1]
        project = unit.new_project_ref(domain_id=parent['id'],
                                       parent_id=parent['id'],
                                       is_domain=True)

        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'], project)

    @unit.skip_if_no_multiple_domains_support
    @test_utils.wip('waiting for sub projects acting as domains support')
    def test_create_project_under_domain_hierarchy(self):
        projects_hierarchy = self._create_projects_hierarchy(is_domain=True)
        parent = projects_hierarchy[1]
        project = unit.new_project_ref(domain_id=parent['id'],
                                       parent_id=parent['id'],
                                       is_domain=False)

        ref = self.resource_api.create_project(project['id'], project)
        self.assertFalse(ref['is_domain'])
        self.assertEqual(parent['id'], ref['parent_id'])
        self.assertEqual(parent['id'], ref['domain_id'])

    def test_create_project_without_is_domain_flag(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        del project['is_domain']
        ref = self.resource_api.create_project(project['id'], project)
        # The is_domain flag should be False by default
        self.assertFalse(ref['is_domain'])

    @unit.skip_if_no_multiple_domains_support
    def test_create_project_passing_is_domain_flag_true(self):
        project = unit.new_project_ref(is_domain=True)

        ref = self.resource_api.create_project(project['id'], project)
        self.assertTrue(ref['is_domain'])

    def test_create_project_passing_is_domain_flag_false(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, is_domain=False)

        ref = self.resource_api.create_project(project['id'], project)
        self.assertIs(False, ref['is_domain'])

    @test_utils.wip('waiting for support for parent_id to imply domain_id')
    def test_create_project_with_parent_id_and_without_domain_id(self):
        # First create a domain
        project = unit.new_project_ref(is_domain=True)
        self.resource_api.create_project(project['id'], project)
        # Now create a child by just naming the parent_id
        sub_project = unit.new_project_ref(parent_id=project['id'])
        ref = self.resource_api.create_project(sub_project['id'], sub_project)

        # The domain_id should be set to the parent domain_id
        self.assertEqual(project['domain_id'], ref['domain_id'])

    def test_create_project_with_domain_id_and_without_parent_id(self):
        # First create a domain
        project = unit.new_project_ref(is_domain=True)
        self.resource_api.create_project(project['id'], project)
        # Now create a child by just naming the domain_id
        sub_project = unit.new_project_ref(domain_id=project['id'])
        ref = self.resource_api.create_project(sub_project['id'], sub_project)

        # The parent_id and domain_id should be set to the id of the project
        # acting as a domain
        self.assertEqual(project['id'], ref['parent_id'])
        self.assertEqual(project['id'], ref['domain_id'])

    def test_create_project_with_domain_id_mismatch_to_parent_domain(self):
        # First create a domain
        project = unit.new_project_ref(is_domain=True)
        self.resource_api.create_project(project['id'], project)
        # Now try to create a child with the above as its parent, but
        # specifying a different domain.
        sub_project = unit.new_project_ref(
            parent_id=project['id'], domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          sub_project['id'], sub_project)

    def test_check_leaf_projects(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        self.assertFalse(self.resource_api.is_leaf_project(
            root_project['id']))
        self.assertTrue(self.resource_api.is_leaf_project(
            leaf_project['id']))

        # Delete leaf_project
        self.resource_api.delete_project(leaf_project['id'])

        # Now, root_project should be leaf
        self.assertTrue(self.resource_api.is_leaf_project(
            root_project['id']))

    def test_list_projects_in_subtree(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]
        project4 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project2['id'])
        self.resource_api.create_project(project4['id'], project4)

        subtree = self.resource_api.list_projects_in_subtree(project1['id'])
        self.assertEqual(3, len(subtree))
        self.assertIn(project2, subtree)
        self.assertIn(project3, subtree)
        self.assertIn(project4, subtree)

        subtree = self.resource_api.list_projects_in_subtree(project2['id'])
        self.assertEqual(2, len(subtree))
        self.assertIn(project3, subtree)
        self.assertIn(project4, subtree)

        subtree = self.resource_api.list_projects_in_subtree(project3['id'])
        self.assertEqual(0, len(subtree))

    def test_list_projects_in_subtree_with_circular_reference(self):
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project1 = self.resource_api.create_project(project1['id'], project1)

        project2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project1['id'])
        self.resource_api.create_project(project2['id'], project2)

        project1['parent_id'] = project2['id']  # Adds cyclic reference

        # NOTE(dstanek): The manager does not allow parent_id to be updated.
        # Instead will directly use the driver to create the cyclic
        # reference.
        self.resource_api.driver.update_project(project1['id'], project1)

        subtree = self.resource_api.list_projects_in_subtree(project1['id'])

        # NOTE(dstanek): If a cyclic reference is detected the code bails
        # and returns None instead of falling into the infinite
        # recursion trap.
        self.assertIsNone(subtree)

    def test_list_projects_in_subtree_invalid_project_id(self):
        self.assertRaises(exception.ValidationError,
                          self.resource_api.list_projects_in_subtree,
                          None)

        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.list_projects_in_subtree,
                          uuid.uuid4().hex)

    def test_list_project_parents(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]
        project4 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project2['id'])
        self.resource_api.create_project(project4['id'], project4)

        parents1 = self.resource_api.list_project_parents(project3['id'])
        self.assertEqual(3, len(parents1))
        self.assertIn(project1, parents1)
        self.assertIn(project2, parents1)

        parents2 = self.resource_api.list_project_parents(project4['id'])
        self.assertEqual(parents1, parents2)

        parents = self.resource_api.list_project_parents(project1['id'])
        # It has the default domain as parent
        self.assertEqual(1, len(parents))

    def test_update_project_enabled_cascade(self):
        """Test update_project_cascade

        Ensures the enabled attribute is correctly updated across
        a simple 3-level projects hierarchy.
        """
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        parent = projects_hierarchy[0]

        # Disable in parent project disables the whole subtree
        parent['enabled'] = False
        # Store the ref from backend in another variable so we don't bother
        # to remove other attributes that were not originally provided and
        # were set in the manager, like parent_id and domain_id.
        parent_ref = self.resource_api.update_project(parent['id'],
                                                      parent,
                                                      cascade=True)

        subtree = self.resource_api.list_projects_in_subtree(parent['id'])
        self.assertEqual(2, len(subtree))
        self.assertFalse(parent_ref['enabled'])
        self.assertFalse(subtree[0]['enabled'])
        self.assertFalse(subtree[1]['enabled'])

        # Enable parent project enables the whole subtree
        parent['enabled'] = True
        parent_ref = self.resource_api.update_project(parent['id'],
                                                      parent,
                                                      cascade=True)

        subtree = self.resource_api.list_projects_in_subtree(parent['id'])
        self.assertEqual(2, len(subtree))
        self.assertTrue(parent_ref['enabled'])
        self.assertTrue(subtree[0]['enabled'])
        self.assertTrue(subtree[1]['enabled'])

    def test_cannot_enable_cascade_with_parent_disabled(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        grandparent = projects_hierarchy[0]
        parent = projects_hierarchy[1]

        grandparent['enabled'] = False
        self.resource_api.update_project(grandparent['id'],
                                         grandparent,
                                         cascade=True)
        subtree = self.resource_api.list_projects_in_subtree(parent['id'])
        self.assertFalse(subtree[0]['enabled'])

        parent['enabled'] = True
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.update_project,
                          parent['id'],
                          parent,
                          cascade=True)

    def test_update_cascade_only_accepts_enabled(self):
        # Update cascade does not accept any other attribute but 'enabled'
        new_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(new_project['id'], new_project)

        new_project['name'] = 'project1'
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          new_project['id'],
                          new_project,
                          cascade=True)

    def test_list_project_parents_invalid_project_id(self):
        self.assertRaises(exception.ValidationError,
                          self.resource_api.list_project_parents,
                          None)

        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.list_project_parents,
                          uuid.uuid4().hex)

    def test_delete_project_with_role_assignments(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], project['id'], 'member')
        self.resource_api.delete_project(project['id'])
        self.assertRaises(exception.NotFound,
                          self.resource_api.get_project,
                          project['id'])

    def test_delete_role_check_role_grant(self):
        role = unit.new_role_ref()
        alt_role = unit.new_role_ref()
        self.role_api.create_role(role['id'], role)
        self.role_api.create_role(alt_role['id'], alt_role)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], role['id'])
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], alt_role['id'])
        self.role_api.delete_role(role['id'])
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(role['id'], roles_ref)
        self.assertIn(alt_role['id'], roles_ref)

    def test_create_project_doesnt_modify_passed_in_dict(self):
        new_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        original_project = new_project.copy()
        self.resource_api.create_project(new_project['id'], new_project)
        self.assertDictEqual(original_project, new_project)

    def test_create_user_doesnt_modify_passed_in_dict(self):
        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        original_user = new_user.copy()
        self.identity_api.create_user(new_user)
        self.assertDictEqual(original_user, new_user)

    def test_update_user_enable(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

        user['enabled'] = False
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        # If not present, enabled field should not be updated
        del user['enabled']
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertFalse(user_ref['enabled'])

        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        del user['enabled']
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

        # Integers are valid Python's booleans. Explicitly test it.
        user['enabled'] = 0
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertFalse(user_ref['enabled'])

        # Any integers other than 0 are interpreted as True
        user['enabled'] = -42
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        # NOTE(breton): below, attribute `enabled` is explicitly tested to be
        # equal True. assertTrue should not be used, because it converts
        # the passed value to bool().
        self.assertIs(user_ref['enabled'], True)

    def test_update_user_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['name'], user_ref['name'])

        changed_name = user_ref['name'] + '_changed'
        user_ref['name'] = changed_name
        updated_user = self.identity_api.update_user(user_ref['id'], user_ref)

        # NOTE(dstanek): the SQL backend adds an 'extra' field containing a
        #                dictionary of the extra fields in addition to the
        #                fields in the object. For the details see:
        #                SqlIdentity.test_update_project_returns_extra
        updated_user.pop('extra', None)

        self.assertDictEqual(user_ref, updated_user)

        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertEqual(changed_name, user_ref['name'])

    def test_update_user_enable_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

        # Strings are not valid boolean values
        user['enabled'] = 'false'
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_project_enable(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertTrue(project_ref['enabled'])

        project['enabled'] = False
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertEqual(project['enabled'], project_ref['enabled'])

        # If not present, enabled field should not be updated
        del project['enabled']
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertFalse(project_ref['enabled'])

        project['enabled'] = True
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertEqual(project['enabled'], project_ref['enabled'])

        del project['enabled']
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertTrue(project_ref['enabled'])

    def test_add_user_to_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])

        found = False
        for x in groups:
            if (x['id'] == new_group['id']):
                found = True
        self.assertTrue(found)

    def test_add_user_to_group_returns_not_found(self):
        domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.add_user_to_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.add_user_to_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.NotFound,
                          self.identity_api.add_user_to_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_check_user_in_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        self.identity_api.check_user_in_group(new_user['id'], new_group['id'])

    def test_create_invalid_domain_fails(self):
        new_group = unit.new_group_ref(domain_id="doesnotexist")
        self.assertRaises(exception.DomainNotFound,
                          self.identity_api.create_group,
                          new_group)
        new_user = unit.new_user_ref(domain_id="doesnotexist")
        self.assertRaises(exception.DomainNotFound,
                          self.identity_api.create_user,
                          new_user)

    def test_check_user_not_in_group(self):
        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = self.identity_api.create_group(new_group)

        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_user = self.identity_api.create_user(new_user)

        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          new_user['id'],
                          new_group['id'])

    def test_check_user_in_group_returns_not_found(self):
        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_user = self.identity_api.create_user(new_user)

        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = self.identity_api.create_group(new_group)

        self.assertRaises(exception.UserNotFound,
                          self.identity_api.check_user_in_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.check_user_in_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_list_users_in_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        # Make sure we get an empty list back on a new group, not an error.
        user_refs = self.identity_api.list_users_in_group(new_group['id'])
        self.assertEqual([], user_refs)
        # Make sure we get the correct users back once they have been added
        # to the group.
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        user_refs = self.identity_api.list_users_in_group(new_group['id'])
        found = False
        for x in user_refs:
            if (x['id'] == new_user['id']):
                found = True
            self.assertNotIn('password', x)
        self.assertTrue(found)

    def test_list_users_in_group_returns_not_found(self):
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.list_users_in_group,
                          uuid.uuid4().hex)

    def test_list_groups_for_user(self):
        domain = self._get_domain_fixture()
        test_groups = []
        test_users = []
        GROUP_COUNT = 3
        USER_COUNT = 2

        for x in range(0, USER_COUNT):
            new_user = unit.new_user_ref(domain_id=domain['id'])
            new_user = self.identity_api.create_user(new_user)
            test_users.append(new_user)
        positive_user = test_users[0]
        negative_user = test_users[1]

        for x in range(0, USER_COUNT):
            group_refs = self.identity_api.list_groups_for_user(
                test_users[x]['id'])
            self.assertEqual(0, len(group_refs))

        for x in range(0, GROUP_COUNT):
            before_count = x
            after_count = x + 1
            new_group = unit.new_group_ref(domain_id=domain['id'])
            new_group = self.identity_api.create_group(new_group)
            test_groups.append(new_group)

            # add the user to the group and ensure that the
            # group count increases by one for each
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(before_count, len(group_refs))
            self.identity_api.add_user_to_group(
                positive_user['id'],
                new_group['id'])
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(after_count, len(group_refs))

            # Make sure the group count for the unrelated user did not change
            group_refs = self.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEqual(0, len(group_refs))

        # remove the user from each group and ensure that
        # the group count reduces by one for each
        for x in range(0, 3):
            before_count = GROUP_COUNT - x
            after_count = GROUP_COUNT - x - 1
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(before_count, len(group_refs))
            self.identity_api.remove_user_from_group(
                positive_user['id'],
                test_groups[x]['id'])
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(after_count, len(group_refs))
            # Make sure the group count for the unrelated user
            # did not change
            group_refs = self.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEqual(0, len(group_refs))

    def test_remove_user_from_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])
        self.assertIn(new_group['id'], [x['id'] for x in groups])
        self.identity_api.remove_user_from_group(new_user['id'],
                                                 new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])
        self.assertNotIn(new_group['id'], [x['id'] for x in groups])

    def test_remove_user_from_group_returns_not_found(self):
        domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.remove_user_from_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.UserNotFound,
                          self.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.NotFound,
                          self.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_group_crud(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        group = unit.new_group_ref(domain_id=domain['id'])
        group = self.identity_api.create_group(group)
        group_ref = self.identity_api.get_group(group['id'])
        self.assertDictContainsSubset(group, group_ref)

        group['name'] = uuid.uuid4().hex
        self.identity_api.update_group(group['id'], group)
        group_ref = self.identity_api.get_group(group['id'])
        self.assertDictContainsSubset(group, group_ref)

        self.identity_api.delete_group(group['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group,
                          group['id'])

    def test_get_group_by_name(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_name = group['name']
        group = self.identity_api.create_group(group)
        spoiler = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_group(spoiler)

        group_ref = self.identity_api.get_group_by_name(
            group_name, CONF.identity.default_domain_id)
        self.assertDictEqual(group, group_ref)

    def test_get_group_by_name_returns_not_found(self):
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_group_crud(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)
        # cache the result
        group_ref = self.identity_api.get_group(group['id'])
        # delete the group bypassing identity api.
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(group['id']))
        driver.delete_group(entity_id)

        self.assertEqual(group_ref, self.identity_api.get_group(group['id']))
        self.identity_api.get_group.invalidate(self.identity_api, group['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group, group['id'])

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)
        # cache the result
        self.identity_api.get_group(group['id'])
        group['name'] = uuid.uuid4().hex
        group_ref = self.identity_api.update_group(group['id'], group)
        # after updating through identity api, get updated group
        self.assertDictContainsSubset(self.identity_api.get_group(group['id']),
                                      group_ref)

    def test_create_duplicate_group_name_fails(self):
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id,
                                    name=group1['name'])
        group1 = self.identity_api.create_group(group1)
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_group,
                          group2)

    def test_create_duplicate_group_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=new_domain['id'],
                                    name=group1['name'])
        group1 = self.identity_api.create_group(group1)
        group2 = self.identity_api.create_group(group2)

    def test_move_group_between_domains(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        group = unit.new_group_ref(domain_id=domain1['id'])
        group = self.identity_api.create_group(group)
        group['domain_id'] = domain2['id']
        # Update the group asserting that a deprecation warning is emitted
        with mock.patch(
                'oslo_log.versionutils.report_deprecated_feature') as mock_dep:
            self.identity_api.update_group(group['id'], group)
            self.assertTrue(mock_dep.called)

        updated_group_ref = self.identity_api.get_group(group['id'])
        self.assertEqual(domain2['id'], updated_group_ref['domain_id'])

    def test_move_group_between_domains_with_clashing_names_fails(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a group in domain1
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        # Now create a group in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        group2 = unit.new_group_ref(name=group1['name'],
                                    domain_id=domain2['id'])
        group2 = self.identity_api.create_group(group2)
        # Now try and move group1 into the 2nd domain - which should
        # fail since the names clash
        group1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_group,
                          group1['id'],
                          group1)

    @unit.skip_if_no_multiple_domains_support
    def test_project_crud(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        project = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictContainsSubset(project, project_ref)

        project['name'] = uuid.uuid4().hex
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictContainsSubset(project, project_ref)

        self.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project['id'])

    def test_domain_delete_hierarchy(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)

        # Creating a root and a leaf project inside the domain
        projects_hierarchy = self._create_projects_hierarchy(
            domain_id=domain['id'])
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[0]

        # Disable the domain
        domain['enabled'] = False
        self.resource_api.update_domain(domain['id'], domain)

        # Delete the domain
        self.resource_api.delete_domain(domain['id'])

        # Make sure the domain no longer exists
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])

        # Make sure the root project no longer exists
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          root_project['id'])

        # Make sure the leaf project no longer exists
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          leaf_project['id'])

    def test_delete_projects_from_ids(self):
        """Tests the resource backend call delete_projects_from_ids.

        Tests the normal flow of the delete_projects_from_ids backend call,
        that ensures no project on the list exists after it is succesfully
        called.
        """
        project1_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project2_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        projects = (project1_ref, project2_ref)
        for project in projects:
            self.resource_api.create_project(project['id'], project)

        # Setting up the ID's list
        projects_ids = [p['id'] for p in projects]
        self.resource_api.driver.delete_projects_from_ids(projects_ids)

        # Ensuring projects no longer exist at backend level
        for project_id in projects_ids:
            self.assertRaises(exception.ProjectNotFound,
                              self.resource_api.driver.get_project,
                              project_id)

        # Passing an empty list is silently ignored
        self.resource_api.driver.delete_projects_from_ids([])

    def test_delete_projects_from_ids_with_no_existing_project_id(self):
        """Tests delete_projects_from_ids issues warning if not found.

        Tests the resource backend call delete_projects_from_ids passing a
        non existing ID in project_ids, which is logged and ignored by
        the backend.
        """
        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)

        # Setting up the ID's list
        projects_ids = (project_ref['id'], uuid.uuid4().hex)
        with mock.patch('keystone.resource.backends.sql.LOG') as mock_log:
            self.resource_api.delete_projects_from_ids(projects_ids)
            self.assertTrue(mock_log.warning.called)
        # The existing project was deleted.
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.driver.get_project,
                          project_ref['id'])

        # Even if we only have one project, and it does not exist, it returns
        # no error.
        self.resource_api.driver.delete_projects_from_ids([uuid.uuid4().hex])

    def test_delete_project_cascade(self):
        # create a hierarchy with 3 levels
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        root_project = projects_hierarchy[0]
        project1 = projects_hierarchy[1]
        project2 = projects_hierarchy[2]

        # Disabling all projects before attempting to delete
        for project in (project2, project1, root_project):
            project['enabled'] = False
            self.resource_api.update_project(project['id'], project)

        self.resource_api.delete_project(root_project['id'], cascade=True)

        for project in projects_hierarchy:
            self.assertRaises(exception.ProjectNotFound,
                              self.resource_api.get_project,
                              project['id'])

    def test_delete_large_project_cascade(self):
        """Try delete a large project with cascade true.

        Tree we will create::

               +-p1-+
               |    |
              p5    p2
               |    |
              p6  +-p3-+
                  |    |
                  p7   p4
        """
        # create a hierarchy with 4 levels
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=4)
        p1 = projects_hierarchy[0]
        # Add the left branch to the hierarchy (p5, p6)
        self._create_projects_hierarchy(hierarchy_size=2,
                                        parent_project_id=p1['id'])
        # Add p7 to the hierarchy
        p3_id = projects_hierarchy[2]['id']
        self._create_projects_hierarchy(hierarchy_size=1,
                                        parent_project_id=p3_id)
        # Reverse the hierarchy to disable the leaf first
        prjs_hierarchy = ([p1] + self.resource_api.list_projects_in_subtree(
                          p1['id']))[::-1]

        # Disabling all projects before attempting to delete
        for project in prjs_hierarchy:
            project['enabled'] = False
            self.resource_api.update_project(project['id'], project)

        self.resource_api.delete_project(p1['id'], cascade=True)
        for project in prjs_hierarchy:
            self.assertRaises(exception.ProjectNotFound,
                              self.resource_api.get_project,
                              project['id'])

    def test_cannot_delete_project_cascade_with_enabled_child(self):
        # create a hierarchy with 3 levels
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        root_project = projects_hierarchy[0]
        project1 = projects_hierarchy[1]
        project2 = projects_hierarchy[2]

        project2['enabled'] = False
        self.resource_api.update_project(project2['id'], project2)

        # Cannot cascade delete root_project, since project1 is enabled
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.delete_project,
                          root_project['id'],
                          cascade=True)

        # Ensuring no project was deleted, not even project2
        self.resource_api.get_project(root_project['id'])
        self.resource_api.get_project(project1['id'])
        self.resource_api.get_project(project2['id'])

    def test_hierarchical_projects_crud(self):
        # create a hierarchy with just a root project (which is a leaf as well)
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=1)
        root_project1 = projects_hierarchy[0]

        # create a hierarchy with one root project and one leaf project
        projects_hierarchy = self._create_projects_hierarchy()
        root_project2 = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        # update description from leaf_project
        leaf_project['description'] = 'new description'
        self.resource_api.update_project(leaf_project['id'], leaf_project)
        proj_ref = self.resource_api.get_project(leaf_project['id'])
        self.assertDictEqual(leaf_project, proj_ref)

        # update the parent_id is not allowed
        leaf_project['parent_id'] = root_project1['id']
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.update_project,
                          leaf_project['id'],
                          leaf_project)

        # delete root_project1
        self.resource_api.delete_project(root_project1['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          root_project1['id'])

        # delete root_project2 is not allowed since it is not a leaf project
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.delete_project,
                          root_project2['id'])

    def test_create_project_with_invalid_parent(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, parent_id='fake')
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    @unit.skip_if_no_multiple_domains_support
    def test_create_leaf_project_with_different_domain(self):
        root_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(root_project['id'], root_project)

        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        leaf_project = unit.new_project_ref(domain_id=domain['id'],
                                            parent_id=root_project['id'])

        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          leaf_project['id'],
                          leaf_project)

    def test_delete_hierarchical_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        self.resource_api.delete_project(leaf_project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          leaf_project['id'])

        self.resource_api.delete_project(root_project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          root_project['id'])

    def test_delete_hierarchical_not_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]

        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.delete_project,
                          root_project['id'])

    def test_update_project_parent(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]

        # project2 is the parent from project3
        self.assertEqual(project3.get('parent_id'), project2['id'])

        # try to update project3 parent to parent1
        project3['parent_id'] = project1['id']
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.update_project,
                          project3['id'],
                          project3)

    def test_create_project_under_disabled_one(self):
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, enabled=False)
        self.resource_api.create_project(project1['id'], project1)

        project2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project1['id'])

        # It's not possible to create a project under a disabled one in the
        # hierarchy
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project2['id'],
                          project2)

    def test_disable_hierarchical_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        leaf_project = projects_hierarchy[1]

        leaf_project['enabled'] = False
        self.resource_api.update_project(leaf_project['id'], leaf_project)

        project_ref = self.resource_api.get_project(leaf_project['id'])
        self.assertEqual(leaf_project['enabled'], project_ref['enabled'])

    def test_disable_hierarchical_not_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]

        root_project['enabled'] = False
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.update_project,
                          root_project['id'],
                          root_project)

    def test_enable_project_with_disabled_parent(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        # Disable leaf and root
        leaf_project['enabled'] = False
        self.resource_api.update_project(leaf_project['id'], leaf_project)
        root_project['enabled'] = False
        self.resource_api.update_project(root_project['id'], root_project)

        # Try to enable the leaf project, it's not possible since it has
        # a disabled parent
        leaf_project['enabled'] = True
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.update_project,
                          leaf_project['id'],
                          leaf_project)

    def _get_hierarchy_depth(self, project_id):
        return len(self.resource_api.list_project_parents(project_id)) + 1

    def test_check_hierarchy_depth(self):
        # Should be allowed to have a hierarchy of the max depth specified
        # in the config option plus one (to allow for the additional project
        # acting as a domain after an upgrade)
        projects_hierarchy = self._create_projects_hierarchy(
            CONF.max_project_tree_depth)
        leaf_project = projects_hierarchy[CONF.max_project_tree_depth - 1]

        depth = self._get_hierarchy_depth(leaf_project['id'])
        self.assertEqual(CONF.max_project_tree_depth + 1, depth)

        # Creating another project in the hierarchy shouldn't be allowed
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=leaf_project['id'])
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_project_update_missing_attrs_with_a_value(self):
        # Creating a project with no description attribute.
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        del project['description']
        project = self.resource_api.create_project(project['id'], project)

        # Add a description attribute.
        project['description'] = uuid.uuid4().hex
        self.resource_api.update_project(project['id'], project)

        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project, project_ref)

    def test_project_update_missing_attrs_with_a_falsey_value(self):
        # Creating a project with no description attribute.
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        del project['description']
        project = self.resource_api.create_project(project['id'], project)

        # Add a description attribute.
        project['description'] = ''
        self.resource_api.update_project(project['id'], project)

        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project, project_ref)

    def test_domain_crud(self):
        domain = unit.new_domain_ref()
        domain_ref = self.resource_api.create_domain(domain['id'], domain)
        self.assertDictEqual(domain, domain_ref)
        domain_ref = self.resource_api.get_domain(domain['id'])
        self.assertDictEqual(domain, domain_ref)

        domain['name'] = uuid.uuid4().hex
        domain_ref = self.resource_api.update_domain(domain['id'], domain)
        self.assertDictEqual(domain, domain_ref)
        domain_ref = self.resource_api.get_domain(domain['id'])
        self.assertDictEqual(domain, domain_ref)

        # Ensure an 'enabled' domain cannot be deleted
        self.assertRaises(exception.ForbiddenNotSecurity,
                          self.resource_api.delete_domain,
                          domain_id=domain['id'])

        # Disable the domain
        domain['enabled'] = False
        self.resource_api.update_domain(domain['id'], domain)

        # Delete the domain
        self.resource_api.delete_domain(domain['id'])

        # Make sure the domain no longer exists
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_domain_name_case_sensitivity(self):
        # create a ref with a lowercase name
        domain_name = 'test_domain'
        ref = unit.new_domain_ref(name=domain_name)

        lower_case_domain = self.resource_api.create_domain(ref['id'], ref)

        # assign a new ID to the ref with the same name, but in uppercase
        ref['id'] = uuid.uuid4().hex
        ref['name'] = domain_name.upper()
        upper_case_domain = self.resource_api.create_domain(ref['id'], ref)

        # We can get each domain by name
        lower_case_domain_ref = self.resource_api.get_domain_by_name(
            domain_name)
        self.assertDictEqual(lower_case_domain, lower_case_domain_ref)

        upper_case_domain_ref = self.resource_api.get_domain_by_name(
            domain_name.upper())
        self.assertDictEqual(upper_case_domain, upper_case_domain_ref)

    def test_attribute_update(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)

        # pick a key known to be non-existent
        key = 'description'

        def assert_key_equals(value):
            project_ref = self.resource_api.update_project(
                project['id'], project)
            self.assertEqual(value, project_ref[key])
            project_ref = self.resource_api.get_project(project['id'])
            self.assertEqual(value, project_ref[key])

        def assert_get_key_is(value):
            project_ref = self.resource_api.update_project(
                project['id'], project)
            self.assertIs(project_ref.get(key), value)
            project_ref = self.resource_api.get_project(project['id'])
            self.assertIs(project_ref.get(key), value)

        # add an attribute that doesn't exist, set it to a falsey value
        value = ''
        project[key] = value
        assert_key_equals(value)

        # set an attribute with a falsey value to null
        value = None
        project[key] = value
        assert_get_key_is(value)

        # do it again, in case updating from this situation is handled oddly
        value = None
        project[key] = value
        assert_get_key_is(value)

        # set a possibly-null value to a falsey value
        value = ''
        project[key] = value
        assert_key_equals(value)

        # set a falsey value to a truthy value
        value = uuid.uuid4().hex
        project[key] = value
        assert_key_equals(value)

    def test_user_crud(self):
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        del user_dict['id']
        user = self.identity_api.create_user(user_dict)
        user_ref = self.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertDictContainsSubset(user_dict, user_ref_dict)

        user_dict['password'] = uuid.uuid4().hex
        self.identity_api.update_user(user['id'], user_dict)
        user_ref = self.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertDictContainsSubset(user_dict, user_ref_dict)

        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])

    def test_list_projects_for_user(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = self.identity_api.create_user(user1)
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(0, len(user_projects))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id=self.role_member['id'])
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(2, len(user_projects))

    def test_list_projects_for_user_with_grants(self):
        # Create two groups each with a role on a different project, and
        # make user1 a member of both groups.  Both these new projects
        # should now be included, along with any direct user grants.
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = self.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain['id'])
        group2 = self.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project2['id'], project2)
        self.identity_api.add_user_to_group(user1['id'], group1['id'])
        self.identity_api.add_user_to_group(user1['id'], group2['id'])

        # Create 3 grants, one user grant, the other two as group grants
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         project_id=project2['id'],
                                         role_id=self.role_admin['id'])
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(3, len(user_projects))

    @unit.skip_if_cache_disabled('resource')
    @unit.skip_if_no_multiple_domains_support
    def test_domain_rename_invalidates_get_domain_by_name_cache(self):
        domain = unit.new_domain_ref()
        domain_id = domain['id']
        domain_name = domain['name']
        self.resource_api.create_domain(domain_id, domain)
        domain_ref = self.resource_api.get_domain_by_name(domain_name)
        domain_ref['name'] = uuid.uuid4().hex
        self.resource_api.update_domain(domain_id, domain_ref)
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain_by_name,
                          domain_name)

    @unit.skip_if_cache_disabled('resource')
    def test_cache_layer_domain_crud(self):
        domain = unit.new_domain_ref()
        domain_id = domain['id']
        # Create Domain
        self.resource_api.create_domain(domain_id, domain)
        project_domain_ref = self.resource_api.get_project(domain_id)
        domain_ref = self.resource_api.get_domain(domain_id)
        updated_project_domain_ref = copy.deepcopy(project_domain_ref)
        updated_project_domain_ref['name'] = uuid.uuid4().hex
        updated_domain_ref = copy.deepcopy(domain_ref)
        updated_domain_ref['name'] = updated_project_domain_ref['name']
        # Update domain, bypassing resource api manager
        self.resource_api.driver.update_project(domain_id,
                                                updated_project_domain_ref)
        # Verify get_domain still returns the domain
        self.assertDictContainsSubset(
            domain_ref, self.resource_api.get_domain(domain_id))
        # Invalidate cache
        self.resource_api.get_domain.invalidate(self.resource_api,
                                                domain_id)
        # Verify get_domain returns the updated domain
        self.assertDictContainsSubset(
            updated_domain_ref, self.resource_api.get_domain(domain_id))
        # Update the domain back to original ref, using the assignment api
        # manager
        self.resource_api.update_domain(domain_id, domain_ref)
        self.assertDictContainsSubset(
            domain_ref, self.resource_api.get_domain(domain_id))
        # Make sure domain is 'disabled', bypass resource api manager
        project_domain_ref_disabled = project_domain_ref.copy()
        project_domain_ref_disabled['enabled'] = False
        self.resource_api.driver.update_project(domain_id,
                                                project_domain_ref_disabled)
        self.resource_api.driver.update_project(domain_id, {'enabled': False})
        # Delete domain, bypassing resource api manager
        self.resource_api.driver.delete_project(domain_id)
        # Verify get_domain still returns the domain
        self.assertDictContainsSubset(
            domain_ref, self.resource_api.get_domain(domain_id))
        # Invalidate cache
        self.resource_api.get_domain.invalidate(self.resource_api,
                                                domain_id)
        # Verify get_domain now raises DomainNotFound
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain, domain_id)
        # Recreate Domain
        self.resource_api.create_domain(domain_id, domain)
        self.resource_api.get_domain(domain_id)
        # Make sure domain is 'disabled', bypass resource api manager
        domain['enabled'] = False
        self.resource_api.driver.update_project(domain_id, domain)
        self.resource_api.driver.update_project(domain_id, {'enabled': False})
        # Delete domain
        self.resource_api.delete_domain(domain_id)
        # verify DomainNotFound raised
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain_id)

    @unit.skip_if_cache_disabled('resource')
    @unit.skip_if_no_multiple_domains_support
    def test_project_rename_invalidates_get_project_by_name_cache(self):
        domain = unit.new_domain_ref()
        project = unit.new_project_ref(domain_id=domain['id'])
        project_id = project['id']
        project_name = project['name']
        self.resource_api.create_domain(domain['id'], domain)
        # Create a project
        self.resource_api.create_project(project_id, project)
        self.resource_api.get_project_by_name(project_name, domain['id'])
        project['name'] = uuid.uuid4().hex
        self.resource_api.update_project(project_id, project)
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project_by_name,
                          project_name,
                          domain['id'])

    @unit.skip_if_cache_disabled('resource')
    @unit.skip_if_no_multiple_domains_support
    def test_cache_layer_project_crud(self):
        domain = unit.new_domain_ref()
        project = unit.new_project_ref(domain_id=domain['id'])
        project_id = project['id']
        self.resource_api.create_domain(domain['id'], domain)
        # Create a project
        self.resource_api.create_project(project_id, project)
        self.resource_api.get_project(project_id)
        updated_project = copy.deepcopy(project)
        updated_project['name'] = uuid.uuid4().hex
        # Update project, bypassing resource manager
        self.resource_api.driver.update_project(project_id,
                                                updated_project)
        # Verify get_project still returns the original project_ref
        self.assertDictContainsSubset(
            project, self.resource_api.get_project(project_id))
        # Invalidate cache
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 project_id)
        # Verify get_project now returns the new project
        self.assertDictContainsSubset(
            updated_project,
            self.resource_api.get_project(project_id))
        # Update project using the resource_api manager back to original
        self.resource_api.update_project(project['id'], project)
        # Verify get_project returns the original project_ref
        self.assertDictContainsSubset(
            project, self.resource_api.get_project(project_id))
        # Delete project bypassing resource
        self.resource_api.driver.delete_project(project_id)
        # Verify get_project still returns the project_ref
        self.assertDictContainsSubset(
            project, self.resource_api.get_project(project_id))
        # Invalidate cache
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 project_id)
        # Verify ProjectNotFound now raised
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project_id)
        # recreate project
        self.resource_api.create_project(project_id, project)
        self.resource_api.get_project(project_id)
        # delete project
        self.resource_api.delete_project(project_id)
        # Verify ProjectNotFound is raised
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project_id)

    def test_arbitrary_attributes_are_returned_from_create_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        user = self.identity_api.create_user(user_data)

        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_arbitrary_attributes_are_returned_from_get_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        user_data = self.identity_api.create_user(user_data)

        user = self.identity_api.get_user(user_data['id'])
        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_new_arbitrary_attributes_are_returned_from_update_user(self):
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)

        user = self.identity_api.create_user(user_data)
        attr_value = uuid.uuid4().hex
        user['arbitrary_attr'] = attr_value
        updated_user = self.identity_api.update_user(user['id'], user)

        self.assertEqual(attr_value, updated_user['arbitrary_attr'])

    def test_updated_arbitrary_attributes_are_returned_from_update_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        new_attr_value = uuid.uuid4().hex
        user = self.identity_api.create_user(user_data)
        user['arbitrary_attr'] = new_attr_value
        updated_user = self.identity_api.update_user(user['id'], user)

        self.assertEqual(new_attr_value, updated_user['arbitrary_attr'])

    def test_create_grant_no_user(self):
        # If call create_grant with a user that doesn't exist, doesn't fail.
        self.assignment_api.create_grant(
            self.role_other['id'],
            user_id=uuid.uuid4().hex,
            project_id=self.tenant_bar['id'])

    def test_create_grant_no_group(self):
        # If call create_grant with a group that doesn't exist, doesn't fail.
        self.assignment_api.create_grant(
            self.role_other['id'],
            group_id=uuid.uuid4().hex,
            project_id=self.tenant_bar['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_get_default_domain_by_name(self):
        domain_name = 'default'

        domain = unit.new_domain_ref(name=domain_name)
        self.resource_api.create_domain(domain['id'], domain)

        domain_ref = self.resource_api.get_domain_by_name(domain_name)
        self.assertEqual(domain, domain_ref)

    def test_get_not_default_domain_by_name(self):
        domain_name = 'foo'
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain_by_name,
                          domain_name)

    def test_project_update_and_project_get_return_same_response(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)

        self.resource_api.create_project(project['id'], project)

        updated_project = {'enabled': False}
        updated_project_ref = self.resource_api.update_project(
            project['id'], updated_project)

        # SQL backend adds 'extra' field
        updated_project_ref.pop('extra', None)

        self.assertIs(False, updated_project_ref['enabled'])

        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(updated_project_ref, project_ref)

    def test_user_update_and_user_get_return_same_response(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user = self.identity_api.create_user(user)

        updated_user = {'enabled': False}
        updated_user_ref = self.identity_api.update_user(
            user['id'], updated_user)

        # SQL backend adds 'extra' field
        updated_user_ref.pop('extra', None)

        self.assertIs(False, updated_user_ref['enabled'])

        user_ref = self.identity_api.get_user(user['id'])
        self.assertDictEqual(updated_user_ref, user_ref)

    def test_delete_group_removes_role_assignments(self):
        # When a group is deleted any role assignments for the group are
        # removed.

        MEMBER_ROLE_ID = 'member'

        def get_member_assignments():
            assignments = self.assignment_api.list_role_assignments()
            return [x for x in assignments if x['role_id'] == MEMBER_ROLE_ID]

        orig_member_assignments = get_member_assignments()

        # Create a group.
        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = self.identity_api.create_group(new_group)

        # Create a project.
        new_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(new_project['id'], new_project)

        # Assign a role to the group.
        self.assignment_api.create_grant(
            group_id=new_group['id'], project_id=new_project['id'],
            role_id=MEMBER_ROLE_ID)

        # Delete the group.
        self.identity_api.delete_group(new_group['id'])

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
        self.resource_api.create_domain(domain1['id'], domain1)
        group_list = []
        group_id_list = []
        role_list = []
        for _ in range(3):
            group = unit.new_group_ref(domain_id=domain1['id'])
            group = self.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

            role = unit.new_role_ref()
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one is inherited
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'],
                                         inherited_to_projects=True)

        # Now get the effective roles for the groups on the domain project. We
        # shouldn't get back the inherited role.

        role_refs = self.assignment_api.get_roles_for_groups(
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
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain2['id'])
        self.resource_api.create_project(project2['id'], project2)
        group_list = []
        group_id_list = []
        role_list = []
        for _ in range(6):
            group = unit.new_group_ref(domain_id=domain1['id'])
            group = self.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

            role = unit.new_role_ref()
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one inherited and one non-inherited on Domain1,
        # plus one on Project1
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[2]['id'])

        # ...and a duplicate set of spoiler assignments to Domain2/Project2
        self.assignment_api.create_grant(group_id=group_list[3]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[3]['id'])
        self.assignment_api.create_grant(group_id=group_list[4]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[4]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[5]['id'],
                                         project_id=project2['id'],
                                         role_id=role_list[5]['id'])

        # Now get the effective roles for all groups on the Project1. With
        # inheritance off, we should only get back the direct role.

        self.config_fixture.config(group='os_inherit', enabled=False)
        role_refs = self.assignment_api.get_roles_for_groups(
            group_id_list, project_id=project1['id'])

        self.assertThat(role_refs, matchers.HasLength(1))
        self.assertIn(role_list[2], role_refs)

        # With inheritance on, we should also get back the inherited role from
        # its owning domain.

        self.config_fixture.config(group='os_inherit', enabled=True)
        role_refs = self.assignment_api.get_roles_for_groups(
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
            self.resource_api.create_domain(domain['id'], domain)
            domain_list.append(domain)

            group = unit.new_group_ref(domain_id=domain['id'])
            group = self.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)

        # Assign the roles - one is inherited
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain_list[0]['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain_list[1]['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         domain_id=domain_list[2]['id'],
                                         role_id=role1['id'],
                                         inherited_to_projects=True)

        # Now list the domains that have roles for any of the 3 groups
        # We shouldn't get back domain[2] since that had an inherited role.

        domain_refs = (
            self.assignment_api.list_domains_for_groups(group_id_list))

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
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        project1 = self.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain1['id'])
        project2 = self.resource_api.create_project(project2['id'], project2)
        project3 = unit.new_project_ref(domain_id=domain1['id'])
        project3 = self.resource_api.create_project(project3['id'], project3)
        project4 = unit.new_project_ref(domain_id=domain2['id'])
        project4 = self.resource_api.create_project(project4['id'], project4)
        group_list = []
        role_list = []
        for _ in range(7):
            group = unit.new_group_ref(domain_id=domain1['id'])
            group = self.identity_api.create_group(group)
            group_list.append(group)

            role = unit.new_role_ref()
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one inherited and one non-inherited on Domain1,
        # plus one on Project1 and Project2
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[2]['id'])
        self.assignment_api.create_grant(group_id=group_list[3]['id'],
                                         project_id=project2['id'],
                                         role_id=role_list[3]['id'])

        # ...and a few of spoiler assignments to Domain2/Project4
        self.assignment_api.create_grant(group_id=group_list[4]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[4]['id'])
        self.assignment_api.create_grant(group_id=group_list[5]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[5]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[6]['id'],
                                         project_id=project4['id'],
                                         role_id=role_list[6]['id'])

        # Now get the projects for the groups that have roles on Project1,
        # Project2 and the inherited role on Domain!. With inheritance off,
        # we should only get back the projects with direct role.

        self.config_fixture.config(group='os_inherit', enabled=False)
        group_id_list = [group_list[1]['id'], group_list[2]['id'],
                         group_list[3]['id']]
        project_refs = (
            self.assignment_api.list_projects_for_groups(group_id_list))

        self.assertThat(project_refs, matchers.HasLength(2))
        self.assertIn(project1, project_refs)
        self.assertIn(project2, project_refs)

        # With inheritance on, we should also get back the Project3 due to the
        # inherited role from its owning domain.

        self.config_fixture.config(group='os_inherit', enabled=True)
        project_refs = (
            self.assignment_api.list_projects_for_groups(group_id_list))

        self.assertThat(project_refs, matchers.HasLength(3))
        self.assertIn(project1, project_refs)
        self.assertIn(project2, project_refs)
        self.assertIn(project3, project_refs)

    def test_update_role_no_name(self):
        # A user can update a role and not include the name.

        # description is picked just because it's not name.
        self.role_api.update_role(self.role_member['id'],
                                  {'description': uuid.uuid4().hex})
        # If the previous line didn't raise an exception then the test passes.

    def test_update_role_same_name(self):
        # A user can update a role and set the name to be the same as it was.

        self.role_api.update_role(self.role_member['id'],
                                  {'name': self.role_member['name']})
        # If the previous line didn't raise an exception then the test passes.

    def test_list_role_assignment_containing_names(self):
        # Create Refs
        new_role = unit.new_role_ref()
        new_domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        # Create entities
        new_role = self.role_api.create_role(new_role['id'], new_role)
        new_user = self.identity_api.create_user(new_user)
        new_group = self.identity_api.create_group(new_group)
        self.resource_api.create_project(new_project['id'], new_project)
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=new_project['id'],
                                         role_id=new_role['id'])
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=new_project['id'],
                                         role_id=new_role['id'])
        self.assignment_api.create_grant(domain_id=new_domain['id'],
                                         user_id=new_user['id'],
                                         role_id=new_role['id'])
        # Get the created assignments with the include_names flag
        _asgmt_prj = self.assignment_api.list_role_assignments(
            user_id=new_user['id'],
            project_id=new_project['id'],
            include_names=True)
        _asgmt_grp = self.assignment_api.list_role_assignments(
            group_id=new_group['id'],
            project_id=new_project['id'],
            include_names=True)
        _asgmt_dmn = self.assignment_api.list_role_assignments(
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
        # Assert the names are correct in the domain response
        self.assertEqual(new_domain['name'],
                         first_asgmt_dmn['domain_name'])
        self.assertEqual(new_user['name'],
                         first_asgmt_dmn['user_name'])
        self.assertEqual(new_user['domain_id'],
                         first_asgmt_dmn['user_domain_id'])
        self.assertEqual(new_role['name'],
                         first_asgmt_dmn['role_name'])

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

        # Create Refs
        new_role = unit.new_role_ref()
        new_domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=new_domain['id'])
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        # Create entities
        new_role = self.role_api.create_role(new_role['id'], new_role)
        new_user = self.identity_api.create_user(new_user)
        self.resource_api.create_project(new_project['id'], new_project)
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=new_project['id'],
                                         role_id=new_role['id'])
        # Get the created assignments with NO include_names flag
        role_assign_without_names = self.assignment_api.list_role_assignments(
            user_id=new_user['id'],
            project_id=new_project['id'])
        assert_does_not_contain_names(role_assign_without_names)
        # Get the created assignments with include_names=False
        role_assign_without_names = self.assignment_api.list_role_assignments(
            user_id=new_user['id'],
            project_id=new_project['id'],
            include_names=False)
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
        project = self.resource_api.create_project(project['id'], project)
        # Create a user
        user = unit.new_user_ref(id=common_id,
                                 domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.driver.create_user(common_id, user)
        self.assertEqual(common_id, user['id'])
        # Create a group
        group = unit.new_group_ref(id=common_id,
                                   domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.driver.create_group(common_id, group)
        self.assertEqual(common_id, group['id'])
        # Create four roles
        roles = []
        for _ in range(4):
            role = unit.new_role_ref()
            roles.append(self.role_api.create_role(role['id'], role))
        # Assign roles for user
        self.assignment_api.driver.create_grant(
            user_id=user['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[0]['id'])
        self.assignment_api.driver.create_grant(user_id=user['id'],
                                                project_id=project['id'],
                                                role_id=roles[1]['id'])
        # Assign roles for group
        self.assignment_api.driver.create_grant(
            group_id=group['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[2]['id'])
        self.assignment_api.driver.create_grant(group_id=group['id'],
                                                project_id=project['id'],
                                                role_id=roles[3]['id'])
        # Make sure they were assigned
        user_assignments = self.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(2))
        group_assignments = self.assignment_api.list_role_assignments(
            group_id=group['id'])
        self.assertThat(group_assignments, matchers.HasLength(2))
        # Delete user assignments
        self.assignment_api.delete_user_assignments(user_id=user['id'])
        # Assert only user assignments were deleted
        user_assignments = self.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(0))
        group_assignments = self.assignment_api.list_role_assignments(
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
        project = self.resource_api.create_project(project['id'], project)
        # Create a user
        user = unit.new_user_ref(id=common_id,
                                 domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.driver.create_user(common_id, user)
        self.assertEqual(common_id, user['id'])
        # Create a group
        group = unit.new_group_ref(id=common_id,
                                   domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.driver.create_group(common_id, group)
        self.assertEqual(common_id, group['id'])
        # Create four roles
        roles = []
        for _ in range(4):
            role = unit.new_role_ref()
            roles.append(self.role_api.create_role(role['id'], role))
        # Assign roles for user
        self.assignment_api.driver.create_grant(
            user_id=user['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[0]['id'])
        self.assignment_api.driver.create_grant(user_id=user['id'],
                                                project_id=project['id'],
                                                role_id=roles[1]['id'])
        # Assign roles for group
        self.assignment_api.driver.create_grant(
            group_id=group['id'], domain_id=CONF.identity.default_domain_id,
            role_id=roles[2]['id'])
        self.assignment_api.driver.create_grant(group_id=group['id'],
                                                project_id=project['id'],
                                                role_id=roles[3]['id'])
        # Make sure they were assigned
        user_assignments = self.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(2))
        group_assignments = self.assignment_api.list_role_assignments(
            group_id=group['id'])
        self.assertThat(group_assignments, matchers.HasLength(2))
        # Delete group assignments
        self.assignment_api.delete_group_assignments(group_id=group['id'])
        # Assert only group assignments were deleted
        group_assignments = self.assignment_api.list_role_assignments(
            group_id=group['id'])
        self.assertThat(group_assignments, matchers.HasLength(0))
        user_assignments = self.assignment_api.list_role_assignments(
            user_id=user['id'])
        self.assertThat(user_assignments, matchers.HasLength(2))
        # Make sure these remaining assignments are user-related
        for assignment in group_assignments:
            self.assertThat(assignment.keys(), matchers.Contains('user_id'))


class TokenTests(object):
    def _create_token_id(self):
        # Use a token signed by the cms module
        token_id = ""
        for i in range(1, 20):
            token_id += uuid.uuid4().hex
        return cms.cms_sign_token(token_id,
                                  CONF.signing.certfile,
                                  CONF.signing.keyfile)

    def _assert_revoked_token_list_matches_token_persistence(
            self, revoked_token_id_list):
        # Assert that the list passed in matches the list returned by the
        # token persistence service
        persistence_list = [
            x['id']
            for x in self.token_provider_api.list_revoked_tokens()
        ]
        self.assertEqual(persistence_list, revoked_token_id_list)

    def test_token_crud(self):
        token_id = self._create_token_id()
        data = {'id': token_id, 'a': 'b',
                'trust_id': None,
                'user': {'id': 'testuserid'},
                'token_data': {'access': {'token': {
                    'audit_ids': [uuid.uuid4().hex]}}}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        expires = data_ref.pop('expires')
        data_ref.pop('user_id')
        self.assertIsInstance(expires, datetime.datetime)
        data_ref.pop('id')
        data.pop('id')
        self.assertDictEqual(data, data_ref)

        new_data_ref = self.token_provider_api._persistence.get_token(token_id)
        expires = new_data_ref.pop('expires')
        self.assertIsInstance(expires, datetime.datetime)
        new_data_ref.pop('user_id')
        new_data_ref.pop('id')

        self.assertEqual(data, new_data_ref)

        self.token_provider_api._persistence.delete_token(token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.get_token, token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.delete_token, token_id)

    def create_token_sample_data(self, token_id=None, tenant_id=None,
                                 trust_id=None, user_id=None, expires=None):
        if token_id is None:
            token_id = self._create_token_id()
        if user_id is None:
            user_id = 'testuserid'
        # FIXME(morganfainberg): These tokens look nothing like "Real" tokens.
        # This should be fixed when token issuance is cleaned up.
        data = {'id': token_id, 'a': 'b',
                'user': {'id': user_id},
                'access': {'token': {'audit_ids': [uuid.uuid4().hex]}}}
        if tenant_id is not None:
            data['tenant'] = {'id': tenant_id, 'name': tenant_id}
        if tenant_id is NULL_OBJECT:
            data['tenant'] = None
        if expires is not None:
            data['expires'] = expires
        if trust_id is not None:
            data['trust_id'] = trust_id
            data['access'].setdefault('trust', {})
            # Testuserid2 is used here since a trustee will be different in
            # the cases of impersonation and therefore should not match the
            # token's user_id.
            data['access']['trust']['trustee_user_id'] = 'testuserid2'
        data['token_version'] = provider.V2
        # Issue token stores a copy of all token data at token['token_data'].
        # This emulates that assumption as part of the test.
        data['token_data'] = copy.deepcopy(data)
        new_token = self.token_provider_api._persistence.create_token(token_id,
                                                                      data)
        return new_token['id'], data

    def test_delete_tokens(self):
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data(
            tenant_id='testtenantid')
        token_id2, data = self.create_token_sample_data(
            tenant_id='testtenantid')
        token_id3, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            user_id='testuserid1')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(2, len(tokens))
        self.assertIn(token_id2, tokens)
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_tokens(
            user_id='testuserid',
            tenant_id='testtenantid')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(0, len(tokens))
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id1)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id2)

        self.token_provider_api._persistence.get_token(token_id3)

    def test_delete_tokens_trust(self):
        tokens = self.token_provider_api._persistence._list_tokens(
            user_id='testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            trust_id='testtrustid')
        token_id2, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            user_id='testuserid1',
            trust_id='testtrustid1')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_tokens(
            user_id='testuserid',
            tenant_id='testtenantid',
            trust_id='testtrustid')
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id1)
        self.token_provider_api._persistence.get_token(token_id2)

    def _test_token_list(self, token_list_fn):
        tokens = token_list_fn('testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data()
        tokens = token_list_fn('testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id1, tokens)
        token_id2, data = self.create_token_sample_data()
        tokens = token_list_fn('testuserid')
        self.assertEqual(2, len(tokens))
        self.assertIn(token_id2, tokens)
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_token(token_id1)
        tokens = token_list_fn('testuserid')
        self.assertIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_token(token_id2)
        tokens = token_list_fn('testuserid')
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)

        # tenant-specific tokens
        tenant1 = uuid.uuid4().hex
        tenant2 = uuid.uuid4().hex
        token_id3, data = self.create_token_sample_data(tenant_id=tenant1)
        token_id4, data = self.create_token_sample_data(tenant_id=tenant2)
        # test for existing but empty tenant (LP:1078497)
        token_id5, data = self.create_token_sample_data(tenant_id=NULL_OBJECT)
        tokens = token_list_fn('testuserid')
        self.assertEqual(3, len(tokens))
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)
        self.assertIn(token_id5, tokens)
        tokens = token_list_fn('testuserid', tenant2)
        self.assertEqual(1, len(tokens))
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)

    def test_token_list(self):
        self._test_token_list(
            self.token_provider_api._persistence._list_tokens)

    def test_token_list_trust(self):
        trust_id = uuid.uuid4().hex
        token_id5, data = self.create_token_sample_data(trust_id=trust_id)
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid', trust_id=trust_id)
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id5, tokens)

    def test_get_token_returns_not_found(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          uuid.uuid4().hex)

    def test_delete_token_returns_not_found(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.delete_token,
                          uuid.uuid4().hex)

    def test_expired_token(self):
        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() - datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data, data_ref)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id)

    def test_null_expires_token(self):
        token_id = uuid.uuid4().hex
        data = {'id': token_id, 'id_hash': token_id, 'a': 'b', 'expires': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        self.assertIsNotNone(data_ref['expires'])
        new_data_ref = self.token_provider_api._persistence.get_token(token_id)

        # MySQL doesn't store microseconds, so discard them before testing
        data_ref['expires'] = data_ref['expires'].replace(microsecond=0)
        new_data_ref['expires'] = new_data_ref['expires'].replace(
            microsecond=0)

        self.assertEqual(data_ref, new_data_ref)

    def check_list_revoked_tokens(self, token_infos):
        revocation_list = self.token_provider_api.list_revoked_tokens()
        revoked_ids = [x['id'] for x in revocation_list]
        revoked_audit_ids = [x['audit_id'] for x in revocation_list]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        for token_id, audit_id in token_infos:
            self.assertIn(token_id, revoked_ids)
            self.assertIn(audit_id, revoked_audit_ids)

    def delete_token(self):
        token_id = uuid.uuid4().hex
        audit_id = uuid.uuid4().hex
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'user': {'id': 'testuserid'},
                'token_data': {'token': {'audit_ids': [audit_id]}}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        self.token_provider_api._persistence.delete_token(token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.get_token,
            data_ref['id'])
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.delete_token,
            data_ref['id'])
        return (token_id, audit_id)

    def test_list_revoked_tokens_returns_empty_list(self):
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertEqual([], revoked_ids)

    def test_list_revoked_tokens_for_single_token(self):
        self.check_list_revoked_tokens([self.delete_token()])

    def test_list_revoked_tokens_for_multiple_tokens(self):
        self.check_list_revoked_tokens([self.delete_token()
                                        for x in range(2)])

    def test_flush_expired_token(self):
        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() - datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data, data_ref)

        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() + datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data, data_ref)

        self.token_provider_api._persistence.flush_expired_tokens()
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id, tokens)

    @unit.skip_if_cache_disabled('token')
    def test_revocation_list_cache(self):
        expire_time = timeutils.utcnow() + datetime.timedelta(minutes=10)
        token_id = uuid.uuid4().hex
        token_data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                      'expires': expire_time,
                      'trust_id': None,
                      'user': {'id': 'testuserid'},
                      'token_data': {'token': {
                          'audit_ids': [uuid.uuid4().hex]}}}
        token2_id = uuid.uuid4().hex
        token2_data = {'id_hash': token2_id, 'id': token2_id, 'a': 'b',
                       'expires': expire_time,
                       'trust_id': None,
                       'user': {'id': 'testuserid'},
                       'token_data': {'token': {
                           'audit_ids': [uuid.uuid4().hex]}}}
        # Create 2 Tokens.
        self.token_provider_api._persistence.create_token(token_id,
                                                          token_data)
        self.token_provider_api._persistence.create_token(token2_id,
                                                          token2_data)
        # Verify the revocation list is empty.
        self.assertEqual(
            [], self.token_provider_api._persistence.list_revoked_tokens())
        self.assertEqual([], self.token_provider_api.list_revoked_tokens())
        # Delete a token directly, bypassing the manager.
        self.token_provider_api._persistence.driver.delete_token(token_id)
        # Verify the revocation list is still empty.
        self.assertEqual(
            [], self.token_provider_api._persistence.list_revoked_tokens())
        self.assertEqual([], self.token_provider_api.list_revoked_tokens())
        # Invalidate the revocation list.
        self.token_provider_api._persistence.invalidate_revocation_list()
        # Verify the deleted token is in the revocation list.
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id, revoked_ids)
        # Delete the second token, through the manager
        self.token_provider_api._persistence.delete_token(token2_id)
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        # Verify both tokens are in the revocation list.
        self.assertIn(token_id, revoked_ids)
        self.assertIn(token2_id, revoked_ids)

    def _test_predictable_revoked_pki_token_id(self, hash_fn):
        token_id = self._create_token_id()
        token_id_hash = hash_fn(token_id.encode('utf-8')).hexdigest()
        token = {'user': {'id': uuid.uuid4().hex},
                 'token_data': {'token': {'audit_ids': [uuid.uuid4().hex]}}}

        self.token_provider_api._persistence.create_token(token_id, token)
        self.token_provider_api._persistence.delete_token(token_id)

        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id_hash, revoked_ids)
        self.assertNotIn(token_id, revoked_ids)
        for t in self.token_provider_api._persistence.list_revoked_tokens():
            self.assertIn('expires', t)

    def test_predictable_revoked_pki_token_id_default(self):
        self._test_predictable_revoked_pki_token_id(hashlib.md5)

    def test_predictable_revoked_pki_token_id_sha256(self):
        self.config_fixture.config(group='token', hash_algorithm='sha256')
        self._test_predictable_revoked_pki_token_id(hashlib.sha256)

    def test_predictable_revoked_uuid_token_id(self):
        token_id = uuid.uuid4().hex
        token = {'user': {'id': uuid.uuid4().hex},
                 'token_data': {'token': {'audit_ids': [uuid.uuid4().hex]}}}

        self.token_provider_api._persistence.create_token(token_id, token)
        self.token_provider_api._persistence.delete_token(token_id)

        revoked_tokens = self.token_provider_api.list_revoked_tokens()
        revoked_ids = [x['id'] for x in revoked_tokens]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id, revoked_ids)
        for t in revoked_tokens:
            self.assertIn('expires', t)

    def test_create_unicode_token_id(self):
        token_id = six.text_type(self._create_token_id())
        self.create_token_sample_data(token_id=token_id)
        self.token_provider_api._persistence.get_token(token_id)

    def test_create_unicode_user_id(self):
        user_id = six.text_type(uuid.uuid4().hex)
        token_id, data = self.create_token_sample_data(user_id=user_id)
        self.token_provider_api._persistence.get_token(token_id)

    def test_token_expire_timezone(self):

        @test_utils.timezone
        def _create_token(expire_time):
            token_id = uuid.uuid4().hex
            user_id = six.text_type(uuid.uuid4().hex)
            return self.create_token_sample_data(token_id=token_id,
                                                 user_id=user_id,
                                                 expires=expire_time)

        for d in ['+0', '-11', '-8', '-5', '+5', '+8', '+14']:
            test_utils.TZ = 'UTC' + d
            expire_time = timeutils.utcnow() + datetime.timedelta(minutes=1)
            token_id, data_in = _create_token(expire_time)
            data_get = self.token_provider_api._persistence.get_token(token_id)

            self.assertEqual(data_in['id'], data_get['id'],
                             'TZ=%s' % test_utils.TZ)

            expire_time_expired = (
                timeutils.utcnow() + datetime.timedelta(minutes=-1))
            token_id, data_in = _create_token(expire_time_expired)
            self.assertRaises(exception.TokenNotFound,
                              self.token_provider_api._persistence.get_token,
                              data_in['id'])


class TokenCacheInvalidation(object):
    def _create_test_data(self):
        self.user = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.tenant = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)

        # Create an equivalent of a scoped token
        token_dict = {'user': self.user, 'tenant': self.tenant,
                      'metadata': {}, 'id': 'placeholder'}
        token_id, data = self.token_provider_api.issue_v2_token(token_dict)
        self.scoped_token_id = token_id

        # ..and an un-scoped one
        token_dict = {'user': self.user, 'tenant': None,
                      'metadata': {}, 'id': 'placeholder'}
        token_id, data = self.token_provider_api.issue_v2_token(token_dict)
        self.unscoped_token_id = token_id

        # Validate them, in the various ways possible - this will load the
        # responses into the token cache.
        self._check_scoped_tokens_are_valid()
        self._check_unscoped_tokens_are_valid()

    def _check_unscoped_tokens_are_invalid(self):
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_token,
            self.unscoped_token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_v2_token,
            self.unscoped_token_id)

    def _check_scoped_tokens_are_invalid(self):
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_token,
            self.scoped_token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_token,
            self.scoped_token_id,
            self.tenant['id'])
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_v2_token,
            self.scoped_token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_v2_token,
            self.scoped_token_id,
            self.tenant['id'])

    def _check_scoped_tokens_are_valid(self):
        self.token_provider_api.validate_token(self.scoped_token_id)
        self.token_provider_api.validate_token(
            self.scoped_token_id, belongs_to=self.tenant['id'])
        self.token_provider_api.validate_v2_token(self.scoped_token_id)
        self.token_provider_api.validate_v2_token(
            self.scoped_token_id, belongs_to=self.tenant['id'])

    def _check_unscoped_tokens_are_valid(self):
        self.token_provider_api.validate_token(self.unscoped_token_id)
        self.token_provider_api.validate_v2_token(self.unscoped_token_id)

    def test_delete_unscoped_token(self):
        self.token_provider_api._persistence.delete_token(
            self.unscoped_token_id)
        self._check_unscoped_tokens_are_invalid()
        self._check_scoped_tokens_are_valid()

    def test_delete_scoped_token_by_id(self):
        self.token_provider_api._persistence.delete_token(self.scoped_token_id)
        self._check_scoped_tokens_are_invalid()
        self._check_unscoped_tokens_are_valid()

    def test_delete_scoped_token_by_user(self):
        self.token_provider_api._persistence.delete_tokens(self.user['id'])
        # Since we are deleting all tokens for this user, they should all
        # now be invalid.
        self._check_scoped_tokens_are_invalid()
        self._check_unscoped_tokens_are_invalid()

    def test_delete_scoped_token_by_user_and_tenant(self):
        self.token_provider_api._persistence.delete_tokens(
            self.user['id'],
            tenant_id=self.tenant['id'])
        self._check_scoped_tokens_are_invalid()
        self._check_unscoped_tokens_are_valid()


class TrustTests(object):
    def create_sample_trust(self, new_id, remaining_uses=None):
        self.trustor = self.user_foo
        self.trustee = self.user_two
        expires_at = datetime.datetime.utcnow().replace(year=2032)
        trust_data = (self.trust_api.create_trust
                      (new_id,
                       {'trustor_user_id': self.trustor['id'],
                        'trustee_user_id': self.user_two['id'],
                        'project_id': self.tenant_bar['id'],
                        'expires_at': expires_at,
                        'impersonation': True,
                        'remaining_uses': remaining_uses},
                       roles=[{"id": "member"},
                              {"id": "other"},
                              {"id": "browser"}]))
        return trust_data

    def test_delete_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        trust_id = trust_data['id']
        self.assertIsNotNone(trust_data)
        trust_data = self.trust_api.get_trust(trust_id)
        self.assertEqual(new_id, trust_data['id'])
        self.trust_api.delete_trust(trust_id)
        self.assertRaises(exception.TrustNotFound,
                          self.trust_api.get_trust,
                          trust_id)

    def test_delete_trust_not_found(self):
        trust_id = uuid.uuid4().hex
        self.assertRaises(exception.TrustNotFound,
                          self.trust_api.delete_trust,
                          trust_id)

    def test_get_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        trust_id = trust_data['id']
        self.assertIsNotNone(trust_data)
        trust_data = self.trust_api.get_trust(trust_id)
        self.assertEqual(new_id, trust_data['id'])
        self.trust_api.delete_trust(trust_data['id'])

    def test_get_deleted_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        self.assertIsNotNone(trust_data)
        self.assertIsNone(trust_data['deleted_at'])
        self.trust_api.delete_trust(new_id)
        self.assertRaises(exception.TrustNotFound,
                          self.trust_api.get_trust,
                          new_id)
        deleted_trust = self.trust_api.get_trust(trust_data['id'],
                                                 deleted=True)
        self.assertEqual(trust_data['id'], deleted_trust['id'])
        self.assertIsNotNone(deleted_trust.get('deleted_at'))

    def test_create_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)

        self.assertEqual(new_id, trust_data['id'])
        self.assertEqual(self.trustee['id'], trust_data['trustee_user_id'])
        self.assertEqual(self.trustor['id'], trust_data['trustor_user_id'])
        self.assertTrue(timeutils.normalize_time(trust_data['expires_at']) >
                        timeutils.utcnow())

        self.assertEqual([{'id': 'member'},
                          {'id': 'other'},
                          {'id': 'browser'}], trust_data['roles'])

    def test_list_trust_by_trustee(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts_for_trustee(self.trustee['id'])
        self.assertEqual(3, len(trusts))
        self.assertEqual(trusts[0]["trustee_user_id"], self.trustee['id'])
        trusts = self.trust_api.list_trusts_for_trustee(self.trustor['id'])
        self.assertEqual(0, len(trusts))

    def test_list_trust_by_trustor(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts_for_trustor(self.trustor['id'])
        self.assertEqual(3, len(trusts))
        self.assertEqual(trusts[0]["trustor_user_id"], self.trustor['id'])
        trusts = self.trust_api.list_trusts_for_trustor(self.trustee['id'])
        self.assertEqual(0, len(trusts))

    def test_list_trusts(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts()
        self.assertEqual(3, len(trusts))

    def test_trust_has_remaining_uses_positive(self):
        # create a trust with limited uses, check that we have uses left
        trust_data = self.create_sample_trust(uuid.uuid4().hex,
                                              remaining_uses=5)
        self.assertEqual(5, trust_data['remaining_uses'])
        # create a trust with unlimited uses, check that we have uses left
        trust_data = self.create_sample_trust(uuid.uuid4().hex)
        self.assertIsNone(trust_data['remaining_uses'])

    def test_trust_has_remaining_uses_negative(self):
        # try to create a trust with no remaining uses, check that it fails
        self.assertRaises(exception.ValidationError,
                          self.create_sample_trust,
                          uuid.uuid4().hex,
                          remaining_uses=0)
        # try to create a trust with negative remaining uses,
        # check that it fails
        self.assertRaises(exception.ValidationError,
                          self.create_sample_trust,
                          uuid.uuid4().hex,
                          remaining_uses=-12)

    def test_consume_use(self):
        # consume a trust repeatedly until it has no uses anymore
        trust_data = self.create_sample_trust(uuid.uuid4().hex,
                                              remaining_uses=2)
        self.trust_api.consume_use(trust_data['id'])
        t = self.trust_api.get_trust(trust_data['id'])
        self.assertEqual(1, t['remaining_uses'])
        self.trust_api.consume_use(trust_data['id'])
        # This was the last use, the trust isn't available anymore
        self.assertRaises(exception.TrustNotFound,
                          self.trust_api.get_trust,
                          trust_data['id'])

    def test_duplicate_trusts_not_allowed(self):
        self.trustor = self.user_foo
        self.trustee = self.user_two
        trust_data = {'trustor_user_id': self.trustor['id'],
                      'trustee_user_id': self.user_two['id'],
                      'project_id': self.tenant_bar['id'],
                      'expires_at': timeutils.parse_isotime(
                          '2032-02-18T18:10:00Z'),
                      'impersonation': True,
                      'remaining_uses': None}
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        self.trust_api.create_trust(uuid.uuid4().hex, trust_data, roles)
        self.assertRaises(exception.Conflict,
                          self.trust_api.create_trust,
                          uuid.uuid4().hex,
                          trust_data,
                          roles)


class CatalogTests(object):

    _legacy_endpoint_id_in_endpoint = True
    _enabled_default_to_true_when_creating_endpoint = False

    def test_region_crud(self):
        # create
        region_id = '0' * 255
        new_region = unit.new_region_ref(id=region_id)
        res = self.catalog_api.create_region(new_region)

        # Ensure that we don't need to have a
        # parent_region_id in the original supplied
        # ref dict, but that it will be returned from
        # the endpoint, with None value.
        expected_region = new_region.copy()
        expected_region['parent_region_id'] = None
        self.assertDictEqual(expected_region, res)

        # Test adding another region with the one above
        # as its parent. We will check below whether deleting
        # the parent successfully deletes any child regions.
        parent_region_id = region_id
        new_region = unit.new_region_ref(parent_region_id=parent_region_id)
        region_id = new_region['id']
        res = self.catalog_api.create_region(new_region)
        self.assertDictEqual(new_region, res)

        # list
        regions = self.catalog_api.list_regions()
        self.assertThat(regions, matchers.HasLength(2))
        region_ids = [x['id'] for x in regions]
        self.assertIn(parent_region_id, region_ids)
        self.assertIn(region_id, region_ids)

        # update
        region_desc_update = {'description': uuid.uuid4().hex}
        res = self.catalog_api.update_region(region_id, region_desc_update)
        expected_region = new_region.copy()
        expected_region['description'] = region_desc_update['description']
        self.assertDictEqual(expected_region, res)

        # delete
        self.catalog_api.delete_region(parent_region_id)
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.delete_region,
                          parent_region_id)
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          parent_region_id)
        # Ensure the child is also gone...
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_id)

    def _create_region_with_parent_id(self, parent_id=None):
        new_region = unit.new_region_ref(parent_region_id=parent_id)
        self.catalog_api.create_region(new_region)
        return new_region

    def test_list_regions_filtered_by_parent_region_id(self):
        new_region = self._create_region_with_parent_id()
        parent_id = new_region['id']
        new_region = self._create_region_with_parent_id(parent_id)
        new_region = self._create_region_with_parent_id(parent_id)

        # filter by parent_region_id
        hints = driver_hints.Hints()
        hints.add_filter('parent_region_id', parent_id)
        regions = self.catalog_api.list_regions(hints)
        for region in regions:
            self.assertEqual(parent_id, region['parent_region_id'])

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_region_crud(self):
        new_region = unit.new_region_ref()
        region_id = new_region['id']
        self.catalog_api.create_region(new_region.copy())
        updated_region = copy.deepcopy(new_region)
        updated_region['description'] = uuid.uuid4().hex
        # cache the result
        self.catalog_api.get_region(region_id)
        # update the region bypassing catalog_api
        self.catalog_api.driver.update_region(region_id, updated_region)
        self.assertDictContainsSubset(new_region,
                                      self.catalog_api.get_region(region_id))
        self.catalog_api.get_region.invalidate(self.catalog_api, region_id)
        self.assertDictContainsSubset(updated_region,
                                      self.catalog_api.get_region(region_id))
        # delete the region
        self.catalog_api.driver.delete_region(region_id)
        # still get the old region
        self.assertDictContainsSubset(updated_region,
                                      self.catalog_api.get_region(region_id))
        self.catalog_api.get_region.invalidate(self.catalog_api, region_id)
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region, region_id)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_region(self):
        new_region = unit.new_region_ref()
        region_id = new_region['id']
        self.catalog_api.create_region(new_region)

        # cache the region
        self.catalog_api.get_region(region_id)

        # update the region via catalog_api
        new_description = {'description': uuid.uuid4().hex}
        self.catalog_api.update_region(region_id, new_description)

        # assert that we can get the new region
        current_region = self.catalog_api.get_region(region_id)
        self.assertEqual(new_description['description'],
                         current_region['description'])

    def test_create_region_with_duplicate_id(self):
        new_region = unit.new_region_ref()
        self.catalog_api.create_region(new_region)
        # Create region again with duplicate id
        self.assertRaises(exception.Conflict,
                          self.catalog_api.create_region,
                          new_region)

    def test_get_region_returns_not_found(self):
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          uuid.uuid4().hex)

    def test_delete_region_returns_not_found(self):
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.delete_region,
                          uuid.uuid4().hex)

    def test_create_region_invalid_parent_region_returns_not_found(self):
        new_region = unit.new_region_ref(parent_region_id='nonexisting')
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.create_region,
                          new_region)

    def test_avoid_creating_circular_references_in_regions_update(self):
        region_one = self._create_region_with_parent_id()

        # self circle: region_one->region_one
        self.assertRaises(exception.CircularRegionHierarchyError,
                          self.catalog_api.update_region,
                          region_one['id'],
                          {'parent_region_id': region_one['id']})

        # region_one->region_two->region_one
        region_two = self._create_region_with_parent_id(region_one['id'])
        self.assertRaises(exception.CircularRegionHierarchyError,
                          self.catalog_api.update_region,
                          region_one['id'],
                          {'parent_region_id': region_two['id']})

        # region_one region_two->region_three->region_four->region_two
        region_three = self._create_region_with_parent_id(region_two['id'])
        region_four = self._create_region_with_parent_id(region_three['id'])
        self.assertRaises(exception.CircularRegionHierarchyError,
                          self.catalog_api.update_region,
                          region_two['id'],
                          {'parent_region_id': region_four['id']})

    @mock.patch.object(core.CatalogDriverV8,
                       "_ensure_no_circle_in_hierarchical_regions")
    def test_circular_regions_can_be_deleted(self, mock_ensure_on_circle):
        # turn off the enforcement so that cycles can be created for the test
        mock_ensure_on_circle.return_value = None

        region_one = self._create_region_with_parent_id()

        # self circle: region_one->region_one
        self.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_one['id']})
        self.catalog_api.delete_region(region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_one['id'])

        # region_one->region_two->region_one
        region_one = self._create_region_with_parent_id()
        region_two = self._create_region_with_parent_id(region_one['id'])
        self.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_two['id']})
        self.catalog_api.delete_region(region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_two['id'])

        # region_one->region_two->region_three->region_one
        region_one = self._create_region_with_parent_id()
        region_two = self._create_region_with_parent_id(region_one['id'])
        region_three = self._create_region_with_parent_id(region_two['id'])
        self.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_three['id']})
        self.catalog_api.delete_region(region_two['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_two['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_three['id'])

    def test_service_crud(self):
        # create
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        res = self.catalog_api.create_service(service_id, new_service)
        self.assertDictEqual(new_service, res)

        # list
        services = self.catalog_api.list_services()
        self.assertIn(service_id, [x['id'] for x in services])

        # update
        service_name_update = {'name': uuid.uuid4().hex}
        res = self.catalog_api.update_service(service_id, service_name_update)
        expected_service = new_service.copy()
        expected_service['name'] = service_name_update['name']
        self.assertDictEqual(expected_service, res)

        # delete
        self.catalog_api.delete_service(service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.delete_service,
                          service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.get_service,
                          service_id)

    def _create_random_service(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        return self.catalog_api.create_service(service_id, new_service)

    def test_service_filtering(self):
        target_service = self._create_random_service()
        unrelated_service1 = self._create_random_service()
        unrelated_service2 = self._create_random_service()

        # filter by type
        hint_for_type = driver_hints.Hints()
        hint_for_type.add_filter(name="type", value=target_service['type'])
        services = self.catalog_api.list_services(hint_for_type)

        self.assertEqual(1, len(services))
        filtered_service = services[0]
        self.assertEqual(target_service['type'], filtered_service['type'])
        self.assertEqual(target_service['id'], filtered_service['id'])

        # filter should have been removed, since it was already used by the
        # backend
        self.assertEqual(0, len(hint_for_type.filters))

        # the backend shouldn't filter by name, since this is handled by the
        # front end
        hint_for_name = driver_hints.Hints()
        hint_for_name.add_filter(name="name", value=target_service['name'])
        services = self.catalog_api.list_services(hint_for_name)

        self.assertEqual(3, len(services))

        # filter should still be there, since it wasn't used by the backend
        self.assertEqual(1, len(hint_for_name.filters))

        self.catalog_api.delete_service(target_service['id'])
        self.catalog_api.delete_service(unrelated_service1['id'])
        self.catalog_api.delete_service(unrelated_service2['id'])

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_service_crud(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        res = self.catalog_api.create_service(service_id, new_service)
        self.assertDictEqual(new_service, res)
        self.catalog_api.get_service(service_id)
        updated_service = copy.deepcopy(new_service)
        updated_service['description'] = uuid.uuid4().hex
        # update bypassing catalog api
        self.catalog_api.driver.update_service(service_id, updated_service)
        self.assertDictContainsSubset(new_service,
                                      self.catalog_api.get_service(service_id))
        self.catalog_api.get_service.invalidate(self.catalog_api, service_id)
        self.assertDictContainsSubset(updated_service,
                                      self.catalog_api.get_service(service_id))

        # delete bypassing catalog api
        self.catalog_api.driver.delete_service(service_id)
        self.assertDictContainsSubset(updated_service,
                                      self.catalog_api.get_service(service_id))
        self.catalog_api.get_service.invalidate(self.catalog_api, service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.delete_service,
                          service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.get_service,
                          service_id)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_service(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        self.catalog_api.create_service(service_id, new_service)

        # cache the service
        self.catalog_api.get_service(service_id)

        # update the service via catalog api
        new_type = {'type': uuid.uuid4().hex}
        self.catalog_api.update_service(service_id, new_type)

        # assert that we can get the new service
        current_service = self.catalog_api.get_service(service_id)
        self.assertEqual(new_type['type'], current_service['type'])

    def test_delete_service_with_endpoint(self):
        # create a service
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # deleting the service should also delete the endpoint
        self.catalog_api.delete_service(service['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          endpoint['id'])

    def test_cache_layer_delete_service_with_endpoint(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)
        # cache the result
        self.catalog_api.get_service(service['id'])
        self.catalog_api.get_endpoint(endpoint['id'])
        # delete the service bypassing catalog api
        self.catalog_api.driver.delete_service(service['id'])
        self.assertDictContainsSubset(endpoint,
                                      self.catalog_api.
                                      get_endpoint(endpoint['id']))
        self.assertDictContainsSubset(service,
                                      self.catalog_api.
                                      get_service(service['id']))
        self.catalog_api.get_endpoint.invalidate(self.catalog_api,
                                                 endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          endpoint['id'])
        # multiple endpoints associated with a service
        second_endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                                region_id=None)
        self.catalog_api.create_service(service['id'], service)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)
        self.catalog_api.create_endpoint(second_endpoint['id'],
                                         second_endpoint)
        self.catalog_api.delete_service(service['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          second_endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          second_endpoint['id'])

    def test_get_service_returns_not_found(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.get_service,
                          uuid.uuid4().hex)

    def test_delete_service_returns_not_found(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.delete_service,
                          uuid.uuid4().hex)

    def test_create_endpoint_nonexistent_service(self):
        endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex,
                                         region_id=None)
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_service(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_create_endpoint_nonexistent_region(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(service_id=service['id'])
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_region(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_get_endpoint_returns_not_found(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          uuid.uuid4().hex)

    def test_delete_endpoint_returns_not_found(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          uuid.uuid4().hex)

    def test_create_endpoint(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

    def test_update_endpoint(self):
        dummy_service_ref, endpoint_ref, dummy_disabled_endpoint_ref = (
            self._create_endpoints())
        res = self.catalog_api.update_endpoint(endpoint_ref['id'],
                                               {'interface': 'private'})
        expected_endpoint = endpoint_ref.copy()
        expected_endpoint['enabled'] = True
        expected_endpoint['interface'] = 'private'
        if self._legacy_endpoint_id_in_endpoint:
            expected_endpoint['legacy_endpoint_id'] = None
        if self._enabled_default_to_true_when_creating_endpoint:
            expected_endpoint['enabled'] = True
        self.assertDictEqual(expected_endpoint, res)

    def _create_endpoints(self):
        # Creates a service and 2 endpoints for the service in the same region.
        # The 'public' interface is enabled and the 'internal' interface is
        # disabled.

        def create_endpoint(service_id, region, **kwargs):
            ref = unit.new_endpoint_ref(
                service_id=service_id,
                region_id=region,
                url='http://localhost/%s' % uuid.uuid4().hex,
                **kwargs)

            self.catalog_api.create_endpoint(ref['id'], ref)
            return ref

        # Create a service for use with the endpoints.
        service_ref = unit.new_service_ref()
        service_id = service_ref['id']
        self.catalog_api.create_service(service_id, service_ref)

        region = unit.new_region_ref()
        self.catalog_api.create_region(region)

        # Create endpoints
        enabled_endpoint_ref = create_endpoint(service_id, region['id'])
        disabled_endpoint_ref = create_endpoint(
            service_id, region['id'], enabled=False, interface='internal')

        return service_ref, enabled_endpoint_ref, disabled_endpoint_ref

    def test_list_endpoints(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        expected_ids = set([uuid.uuid4().hex for _ in range(3)])
        for endpoint_id in expected_ids:
            endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                             id=endpoint_id,
                                             region_id=None)
            self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        endpoints = self.catalog_api.list_endpoints()
        self.assertEqual(expected_ids, set(e['id'] for e in endpoints))

    def test_get_catalog_endpoint_disabled(self):
        """Get back only enabled endpoints when get the v2 catalog."""
        service_ref, enabled_endpoint_ref, dummy_disabled_endpoint_ref = (
            self._create_endpoints())

        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        catalog = self.catalog_api.get_catalog(user_id, project_id)

        exp_entry = {
            'id': enabled_endpoint_ref['id'],
            'name': service_ref['name'],
            'publicURL': enabled_endpoint_ref['url'],
        }

        region = enabled_endpoint_ref['region_id']
        self.assertEqual(exp_entry, catalog[region][service_ref['type']])

    def test_get_v3_catalog_endpoint_disabled(self):
        """Get back only enabled endpoints when get the v3 catalog."""
        enabled_endpoint_ref = self._create_endpoints()[1]

        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        catalog = self.catalog_api.get_v3_catalog(user_id, project_id)

        endpoint_ids = [x['id'] for x in catalog[0]['endpoints']]
        self.assertEqual([enabled_endpoint_ref['id']], endpoint_ids)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_endpoint(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # cache the endpoint
        self.catalog_api.get_endpoint(endpoint['id'])

        # update the endpoint via catalog api
        new_url = {'url': uuid.uuid4().hex}
        self.catalog_api.update_endpoint(endpoint['id'], new_url)

        # assert that we can get the new endpoint
        current_endpoint = self.catalog_api.get_endpoint(endpoint['id'])
        self.assertEqual(new_url['url'], current_endpoint['url'])


class PolicyTests(object):
    def test_create(self):
        ref = unit.new_policy_ref()
        res = self.policy_api.create_policy(ref['id'], ref)
        self.assertDictEqual(ref, res)

    def test_get(self):
        ref = unit.new_policy_ref()
        res = self.policy_api.create_policy(ref['id'], ref)

        res = self.policy_api.get_policy(ref['id'])
        self.assertDictEqual(ref, res)

    def test_list(self):
        ref = unit.new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)

        res = self.policy_api.list_policies()
        res = [x for x in res if x['id'] == ref['id']][0]
        self.assertDictEqual(ref, res)

    def test_update(self):
        ref = unit.new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)
        orig = ref

        ref = unit.new_policy_ref()

        # (cannot change policy ID)
        self.assertRaises(exception.ValidationError,
                          self.policy_api.update_policy,
                          orig['id'],
                          ref)

        ref['id'] = orig['id']
        res = self.policy_api.update_policy(orig['id'], ref)
        self.assertDictEqual(ref, res)

    def test_delete(self):
        ref = unit.new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)

        self.policy_api.delete_policy(ref['id'])
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.delete_policy,
                          ref['id'])
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.get_policy,
                          ref['id'])
        res = self.policy_api.list_policies()
        self.assertFalse(len([x for x in res if x['id'] == ref['id']]))

    def test_get_policy_returns_not_found(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.get_policy,
                          uuid.uuid4().hex)

    def test_update_policy_returns_not_found(self):
        ref = unit.new_policy_ref()
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.update_policy,
                          ref['id'],
                          ref)

    def test_delete_policy_returns_not_found(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.delete_policy,
                          uuid.uuid4().hex)


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
        self.config_fixture.config(group='os_inherit', enabled=True)
        self.execute_assignment_plan(test_plan)

    def test_inherited_role_assignments_excluded_if_os_inherit_false(self):
        test_plan = {
            'entities': {'domains': {'users': 2, 'groups': 1, 'projects': 1},
                         'roles': 4},
            'group_memberships': [{'group': 0, 'users': [0]}],
            'assignments': [{'user': 0, 'role': 0, 'domain': 0},
                            {'user': 0, 'role': 1, 'project': 0},
                            {'user': 0, 'role': 2, 'domain': 0,
                             'inherited_to_projects': True},
                            {'user': 1, 'role': 1, 'project': 0},
                            {'group': 0, 'role': 3, 'project': 0}],
            'tests': [
                # List all direct assignments for user[0], since os-inherit is
                # disabled, we should not see the inherited role
                {'params': {'user': 0},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'project': 0}]},
                # Same in effective mode - inherited roles should not be
                # included or expanded...but the group role should now
                # turn up as a user role, since group expansion is not
                # part of os-inherit.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'domain': 0},
                             {'user': 0, 'role': 1, 'project': 0},
                             {'user': 0, 'role': 3, 'project': 0,
                              'indirect': {'group': 0}}]},
            ]
        }
        self.config_fixture.config(group='os_inherit', enabled=False)
        self.execute_assignment_plan(test_plan)

    def _test_crud_inherited_and_direct_assignment(self, **kwargs):
        """Tests inherited and direct assignments for the actor and target

        Ensure it is possible to create both inherited and direct role
        assignments for the same actor on the same target. The actor and the
        target are specified in the kwargs as ('user_id' or 'group_id') and
        ('project_id' or 'domain_id'), respectively.

        """
        self.config_fixture.config(group='os_inherit', enabled=True)
        # Create a new role to avoid assignments loaded from default fixtures
        role = unit.new_role_ref()
        role = self.role_api.create_role(role['id'], role)

        # Define the common assignment entity
        assignment_entity = {'role_id': role['id']}
        assignment_entity.update(kwargs)

        # Define assignments under test
        direct_assignment_entity = assignment_entity.copy()
        inherited_assignment_entity = assignment_entity.copy()
        inherited_assignment_entity['inherited_to_projects'] = 'projects'

        # Create direct assignment and check grants
        self.assignment_api.create_grant(inherited_to_projects=False,
                                         **assignment_entity)

        grants = self.assignment_api.list_role_assignments(role_id=role['id'])
        self.assertThat(grants, matchers.HasLength(1))
        self.assertIn(direct_assignment_entity, grants)

        # Now add inherited assignment and check grants
        self.assignment_api.create_grant(inherited_to_projects=True,
                                         **assignment_entity)

        grants = self.assignment_api.list_role_assignments(role_id=role['id'])
        self.assertThat(grants, matchers.HasLength(2))
        self.assertIn(direct_assignment_entity, grants)
        self.assertIn(inherited_assignment_entity, grants)

        # Delete both and check grants
        self.assignment_api.delete_grant(inherited_to_projects=False,
                                         **assignment_entity)
        self.assignment_api.delete_grant(inherited_to_projects=True,
                                         **assignment_entity)

        grants = self.assignment_api.list_role_assignments(role_id=role['id'])
        self.assertEqual([], grants)

    def test_crud_inherited_and_direct_assignment_for_user_on_domain(self):
        self._test_crud_inherited_and_direct_assignment(
            user_id=self.user_foo['id'],
            domain_id=CONF.identity.default_domain_id)

    def test_crud_inherited_and_direct_assignment_for_group_on_domain(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)

        self._test_crud_inherited_and_direct_assignment(
            group_id=group['id'], domain_id=CONF.identity.default_domain_id)

    def test_crud_inherited_and_direct_assignment_for_user_on_project(self):
        self._test_crud_inherited_and_direct_assignment(
            user_id=self.user_foo['id'], project_id=self.tenant_baz['id'])

    def test_crud_inherited_and_direct_assignment_for_group_on_project(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)

        self._test_crud_inherited_and_direct_assignment(
            group_id=group['id'], project_id=self.tenant_baz['id'])

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
        self.config_fixture.config(group='os_inherit', enabled=True)
        role_list = []
        for _ in range(3):
            role = unit.new_role_ref()
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))

        # Create the first two roles - the domain one is not inherited
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])

        # Now get the effective roles for the user and project, this
        # should only include the direct role assignment on the project
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(1, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)

        # Now add an inherited role on the domain
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'],
                                         inherited_to_projects=True)

        # Now get the effective roles for the user and project again, this
        # should now include the inherited role on the domain
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(2, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)
        self.assertIn(role_list[2]['id'], combined_list)

        # Finally, check that the inherited role does not appear as a valid
        # directly assigned role on the domain itself
        combined_role_list = self.assignment_api.get_roles_for_user_and_domain(
            user1['id'], domain1['id'])
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
        self.config_fixture.config(group='os_inherit', enabled=True)
        role_list = []
        for _ in range(4):
            role = unit.new_role_ref()
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain1['id'])
        group2 = self.identity_api.create_group(group2)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user1['id'],
                                            group2['id'])

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))

        # Create two roles - the domain one is not inherited
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])

        # Now get the effective roles for the user and project, this
        # should only include the direct role assignment on the project
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(1, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)

        # Now add to more group roles, both inherited, to the domain
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[3]['id'],
                                         inherited_to_projects=True)

        # Now get the effective roles for the user and project again, this
        # should now include the inherited roles on the domain
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
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
        self.config_fixture.config(group='os_inherit', enabled=True)
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = self.identity_api.create_user(user1)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project2['id'], project2)

        # Create 2 grants, one on a project and one inherited grant
        # on the domain
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Should get back all three projects, one by virtue of the direct
        # grant, plus both projects in the domain
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
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
        self.config_fixture.config(group='os_inherit', enabled=True)
        root_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        root_project = self.resource_api.create_project(root_project['id'],
                                                        root_project)
        leaf_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=root_project['id'])
        leaf_project = self.resource_api.create_project(leaf_project['id'],
                                                        leaf_project)

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)

        # Grant inherited user role
        self.assignment_api.create_grant(user_id=user['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Grant non-inherited user role
        self.assignment_api.create_grant(user_id=user['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_member['id'])
        # Should get back both projects: because the direct role assignment for
        # the root project and inherited role assignment for leaf project
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(2, len(user_projects))
        self.assertIn(root_project, user_projects)
        self.assertIn(leaf_project, user_projects)

        # Disable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=False)
        # Should get back just root project - due the direct role assignment
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(1, len(user_projects))
        self.assertIn(root_project, user_projects)

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

        test_plan_with_os_inherit_disabled = {
            'tests': [
                # List all effective assignments for user[0] - should only get
                # back the one direct role.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0}]}
            ]
        }
        self.config_fixture.config(group='os_inherit', enabled=True)
        test_data = self.execute_assignment_plan(test_plan)
        self.config_fixture.config(group='os_inherit', enabled=False)
        # Pass the existing test data in to allow execution of 2nd test plan
        self.execute_assignment_cases(
            test_plan_with_os_inherit_disabled, test_data)

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
        self.config_fixture.config(group='os_inherit', enabled=True)
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        project1 = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project2['id'], project2)
        project3 = unit.new_project_ref(domain_id=domain2['id'])
        self.resource_api.create_project(project3['id'], project3)
        project4 = unit.new_project_ref(domain_id=domain2['id'])
        self.resource_api.create_project(project4['id'], project4)
        user1 = unit.new_user_ref(domain_id=domain['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = self.identity_api.create_group(group1)
        self.identity_api.add_user_to_group(user1['id'], group1['id'])

        # Create 4 grants:
        # - one user grant on a project in domain2
        # - one user grant on a project in the default domain
        # - one inherited user grant on domain
        # - one inherited group grant on domain2
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project3['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain2['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Should get back all five projects, but without a duplicate for
        # project3 (since it has both a direct user role and an inherited role)
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
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
        self.config_fixture.config(group='os_inherit', enabled=True)
        root_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        root_project = self.resource_api.create_project(root_project['id'],
                                                        root_project)
        leaf_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=root_project['id'])
        leaf_project = self.resource_api.create_project(leaf_project['id'],
                                                        leaf_project)

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)
        self.identity_api.add_user_to_group(user['id'], group['id'])

        # Grant inherited group role
        self.assignment_api.create_grant(group_id=group['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Grant non-inherited group role
        self.assignment_api.create_grant(group_id=group['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_member['id'])
        # Should get back both projects: because the direct role assignment for
        # the root project and inherited role assignment for leaf project
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(2, len(user_projects))
        self.assertIn(root_project, user_projects)
        self.assertIn(leaf_project, user_projects)

        # Disable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=False)
        # Should get back just root project - due the direct role assignment
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(1, len(user_projects))
        self.assertIn(root_project, user_projects)

        # TODO(henry-nash): The test above uses list_projects_for_user
        # which may, in a subsequent patch, be re-implemented to call
        # list_role_assignments and then report only the distinct projects.
        #
        # The test plan below therefore mirrors this test, to ensure that
        # list_role_assignments works the same. Once list_projects_for_user
        # has been re-implemented then the manual tests above can be
        # refactored.
        test_plan = {
            # A domain with a project ans sub-project, plus a user.
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

        test_plan_with_os_inherit_disabled = {
            'tests': [
                # List all effective assignments for user[0] - should only get
                # back the one direct role.
                {'params': {'user': 0, 'effective': True},
                 'results': [{'user': 0, 'role': 0, 'project': 0,
                              'indirect': {'group': 0}}]}
            ]
        }
        self.config_fixture.config(group='os_inherit', enabled=True)
        test_data = self.execute_assignment_plan(test_plan)
        self.config_fixture.config(group='os_inherit', enabled=False)
        # Pass the existing test data in to allow execution of 2nd test plan
        self.execute_assignment_cases(
            test_plan_with_os_inherit_disabled, test_data)

    def test_list_assignments_for_tree(self):
        """Test we correctly list direct assignments for a tree"""
        # Enable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=True)

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
        """Test we correctly list effective assignments for a tree"""
        # Enable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=True)

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
        # Enable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=True)

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
        """Test we correctly honor domain inherited assignments on the tree"""
        # Enable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=True)

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
            # parent and one group assignment inhertied from the parent.
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
        self.config_fixture.config(group='os_inherit', enabled=True)
        user_ids = self.assignment_api.list_user_ids_for_project(
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
        self.role_api.create_role(prior_role_ref['id'], prior_role_ref)
        implied_role_ref = unit.new_role_ref()
        self.role_api.create_role(implied_role_ref['id'], implied_role_ref)

        self.role_api.create_implied_role(
            prior_role_ref['id'],
            implied_role_ref['id'])
        implied_role = self.role_api.get_implied_role(
            prior_role_ref['id'],
            implied_role_ref['id'])
        expected_implied_role_ref = {
            'prior_role_id': prior_role_ref['id'],
            'implied_role_id': implied_role_ref['id']}
        self.assertDictContainsSubset(
            expected_implied_role_ref,
            implied_role)

        self.role_api.delete_implied_role(
            prior_role_ref['id'],
            implied_role_ref['id'])
        self.assertRaises(exception.ImpliedRoleNotFound,
                          self.role_api.get_implied_role,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_delete_implied_role_returns_not_found(self):
        self.assertRaises(exception.ImpliedRoleNotFound,
                          self.role_api.delete_implied_role,
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
        role_ids = self.assignment_api.get_roles_for_user_and_project(
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
                # implied roles (and that non impled roles are included in
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
        self.config_fixture.config(group='os_inherit', enabled=True)
        self.execute_assignment_plan(test_plan)

    def test_role_assignments_domain_specific_with_implied_roles(self):
        test_plan = {
            'entities': {'domains': {'users': 1, 'projects': 1, 'roles': 2},
                         'roles': 2},
            # Two level tree of implied roles, with the top and 1st level being
            # domain specific roles, and the bottom level being infered global
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


class FilterTests(filtering.FilterTests):
    def test_list_entities_filtered(self):
        for entity in ['user', 'group', 'project']:
            # Create 20 entities
            entity_list = self._create_test_data(entity, 20)

            # Try filtering to get one an exact item out of the list
            hints = driver_hints.Hints()
            hints.add_filter('name', entity_list[10]['name'])
            entities = self._list_entities(entity)(hints=hints)
            self.assertEqual(1, len(entities))
            self.assertEqual(entity_list[10]['id'], entities[0]['id'])
            # Check the driver has removed the filter from the list hints
            self.assertFalse(hints.get_exact_filter_by_name('name'))
            self._delete_test_data(entity, entity_list)

    def test_list_users_inexact_filtered(self):
        # Create 20 users, some with specific names. We set the names at create
        # time (rather than updating them), since the LDAP driver does not
        # support name updates.
        user_name_data = {
            # user index: name for user
            5: 'The',
            6: 'The Ministry',
            7: 'The Ministry of',
            8: 'The Ministry of Silly',
            9: 'The Ministry of Silly Walks',
            # ...and one for useful case insensitivity testing
            10: 'The ministry of silly walks OF'
        }
        user_list = self._create_test_data(
            'user', 20, domain_id=CONF.identity.default_domain_id,
            name_dict=user_name_data)

        hints = driver_hints.Hints()
        hints.add_filter('name', 'ministry', comparator='contains')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(5, len(users))
        self._match_with_list(users, user_list,
                              list_start=6, list_end=11)
        # TODO(henry-nash) Check inexact filter has been removed.

        hints = driver_hints.Hints()
        hints.add_filter('name', 'The', comparator='startswith')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(6, len(users))
        self._match_with_list(users, user_list,
                              list_start=5, list_end=11)
        # TODO(henry-nash) Check inexact filter has been removed.

        hints = driver_hints.Hints()
        hints.add_filter('name', 'of', comparator='endswith')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(2, len(users))
        # We can't assume we will get back the users in any particular order
        self.assertIn(user_list[7]['id'], [users[0]['id'], users[1]['id']])
        self.assertIn(user_list[10]['id'], [users[0]['id'], users[1]['id']])
        # TODO(henry-nash) Check inexact filter has been removed.

        # TODO(henry-nash): Add some case sensitive tests.  However,
        # these would be hard to validate currently, since:
        #
        # For SQL, the issue is that MySQL 0.7, by default, is installed in
        # case insensitive mode (which is what is run by default for our
        # SQL backend tests).  For production deployments. OpenStack
        # assumes a case sensitive database.  For these tests, therefore, we
        # need to be able to check the sensitivity of the database so as to
        # know whether to run case sensitive tests here.
        #
        # For LDAP/AD, although dependent on the schema being used, attributes
        # are typically configured to be case aware, but not case sensitive.

        self._delete_test_data('user', user_list)

    def _groups_for_user_data(self):
        number_of_groups = 10
        group_name_data = {
            # entity index: name for entity
            5: 'The',
            6: 'The Ministry',
            9: 'The Ministry of Silly Walks',
        }
        group_list = self._create_test_data(
            'group', number_of_groups,
            domain_id=CONF.identity.default_domain_id,
            name_dict=group_name_data)
        user_list = self._create_test_data('user', 2)

        for group in range(7):
            # Create membership, including with two out of the three groups
            # with well know names
            self.identity_api.add_user_to_group(user_list[0]['id'],
                                                group_list[group]['id'])
        # ...and some spoiler memberships
        for group in range(7, number_of_groups):
            self.identity_api.add_user_to_group(user_list[1]['id'],
                                                group_list[group]['id'])

        hints = driver_hints.Hints()
        return group_list, user_list, hints

    def test_groups_for_user_inexact_filtered(self):
        """Test use of filtering doesn't break groups_for_user listing.

        Some backends may use filtering to achieve the list of groups for a
        user, so test that it can combine a second filter.

        Test Plan:

        - Create 10 groups, some with names we can filter on
        - Create 2 users
        - Assign 1 of those users to most of the groups, including some of the
          well known named ones
        - Assign the other user to other groups as spoilers
        - Ensure that when we list groups for users with a filter on the group
          name, both restrictions have been enforced on what is returned.

        """
        group_list, user_list, hints = self._groups_for_user_data()
        hints.add_filter('name', 'The', comparator='startswith')
        groups = self.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back 2 out of the 3 groups that start with 'The'
        # hence showing that both "filters" have been applied
        self.assertThat(len(groups), matchers.Equals(2))
        self.assertIn(group_list[5]['id'], [groups[0]['id'], groups[1]['id']])
        self.assertIn(group_list[6]['id'], [groups[0]['id'], groups[1]['id']])
        self._delete_test_data('user', user_list)
        self._delete_test_data('group', group_list)

    def test_groups_for_user_exact_filtered(self):
        """Test exact filters doesn't break groups_for_user listing."""
        group_list, user_list, hints = self._groups_for_user_data()
        hints.add_filter('name', 'The Ministry', comparator='equals')
        groups = self.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back 1 out of the 3 groups with name 'The
        # Ministry' hence showing that both "filters" have been applied.
        self.assertEqual(1, len(groups))
        self.assertEqual(group_list[6]['id'], groups[0]['id'])
        self._delete_test_data('user', user_list)
        self._delete_test_data('group', group_list)

    def _get_user_name_field_size(self):
        """Return the size of the user name field for the backend.

        Subclasses can override this method to indicate that the user name
        field is limited in length. The user name is the field used in the test
        that validates that a filter value works even if it's longer than a
        field.

        If the backend doesn't limit the value length then return None.

        """
        return None

    def test_filter_value_wider_than_field(self):
        # If a filter value is given that's larger than the field in the
        # backend then no values are returned.

        user_name_field_size = self._get_user_name_field_size()

        if user_name_field_size is None:
            # The backend doesn't limit the size of the user name, so pass this
            # test.
            return

        # Create some users just to make sure would return something if the
        # filter was ignored.
        self._create_test_data('user', 2)

        hints = driver_hints.Hints()
        value = 'A' * (user_name_field_size + 1)
        hints.add_filter('name', value)
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual([], users)

    def _list_users_in_group_data(self):
        number_of_users = 10
        user_name_data = {
            1: 'Arthur Conan Doyle',
            3: 'Arthur Rimbaud',
            9: 'Arthur Schopenhauer',
        }
        user_list = self._create_test_data(
            'user', number_of_users,
            domain_id=CONF.identity.default_domain_id,
            name_dict=user_name_data)
        group = self._create_one_entity(
            'group', CONF.identity.default_domain_id, 'Great Writers')
        for i in range(7):
            self.identity_api.add_user_to_group(user_list[i]['id'],
                                                group['id'])

        hints = driver_hints.Hints()
        return user_list, group, hints

    def test_list_users_in_group_inexact_filtered(self):
        user_list, group, hints = self._list_users_in_group_data()
        hints.add_filter('name', 'Arthur', comparator='startswith')
        users = self.identity_api.list_users_in_group(group['id'], hints=hints)
        self.assertThat(len(users), matchers.Equals(2))
        self.assertIn(user_list[1]['id'], [users[0]['id'], users[1]['id']])
        self.assertIn(user_list[3]['id'], [users[0]['id'], users[1]['id']])
        self._delete_test_data('user', user_list)
        self._delete_entity('group')(group['id'])

    def test_list_users_in_group_exact_filtered(self):
        user_list, group, hints = self._list_users_in_group_data()
        hints.add_filter('name', 'Arthur Rimbaud', comparator='equals')
        users = self.identity_api.list_users_in_group(group['id'], hints=hints)
        self.assertEqual(1, len(users))
        self.assertEqual(user_list[3]['id'], users[0]['id'])
        self._delete_test_data('user', user_list)
        self._delete_entity('group')(group['id'])


class LimitTests(filtering.FilterTests):
    ENTITIES = ['user', 'group', 'project']

    def setUp(self):
        """Setup for Limit Test Cases."""
        self.entity_lists = {}

        for entity in self.ENTITIES:
            # Create 20 entities
            self.entity_lists[entity] = self._create_test_data(entity, 20)
        self.addCleanup(self.clean_up_entities)

    def clean_up_entities(self):
        """Clean up entity test data from Limit Test Cases."""
        for entity in self.ENTITIES:
            self._delete_test_data(entity, self.entity_lists[entity])
        del self.entity_lists

    def _test_list_entity_filtered_and_limited(self, entity):
        self.config_fixture.config(list_limit=10)
        # Should get back just 10 entities
        hints = driver_hints.Hints()
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))
        self.assertTrue(hints.limit['truncated'])

        # Override with driver specific limit
        if entity == 'project':
            self.config_fixture.config(group='resource', list_limit=5)
        else:
            self.config_fixture.config(group='identity', list_limit=5)

        # Should get back just 5 users
        hints = driver_hints.Hints()
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))

        # Finally, let's pretend we want to get the full list of entities,
        # even with the limits set, as part of some internal calculation.
        # Calling the API without a hints list should achieve this, and
        # return at least the 20 entries we created (there may be other
        # entities lying around created by other tests/setup).
        entities = self._list_entities(entity)()
        self.assertTrue(len(entities) >= 20)
        self._match_with_list(self.entity_lists[entity], entities)

    def test_list_users_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('user')

    def test_list_groups_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('group')

    def test_list_projects_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('project')
