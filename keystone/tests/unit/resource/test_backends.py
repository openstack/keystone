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
from unittest import mock
import uuid

from testtools import matchers

from keystone.common import driver_hints
from keystone.common import provider_api
from keystone.common.resource_options import options as ro_opt
import keystone.conf
from keystone import exception
from keystone.resource.backends import sql as resource_sql
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import utils as test_utils


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class ResourceTests(object):

    domain_count = len(default_fixtures.DOMAINS)

    def test_get_project(self):
        project_ref = PROVIDERS.resource_api.get_project(
            self.project_bar['id'])
        self.assertDictEqual(self.project_bar, project_ref)

    def test_get_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          uuid.uuid4().hex)

    def test_get_project_by_name(self):
        project_ref = PROVIDERS.resource_api.get_project_by_name(
            self.project_bar['name'],
            CONF.identity.default_domain_id)
        self.assertDictEqual(self.project_bar, project_ref)

    @unit.skip_if_no_multiple_domains_support
    def test_get_project_by_name_for_project_acting_as_a_domain(self):
        """Test get_project_by_name works when the domain_id is None."""
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, is_domain=False)
        project = PROVIDERS.resource_api.create_project(project['id'], project)

        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project_by_name,
                          project['name'],
                          None)

        # Test that querying with domain_id as None will find the project
        # acting as a domain, even if it's name is the same as the regular
        # project above.
        project2 = unit.new_project_ref(is_domain=True,
                                        name=project['name'])
        project2 = PROVIDERS.resource_api.create_project(
            project2['id'], project2
        )

        project_ref = PROVIDERS.resource_api.get_project_by_name(
            project2['name'], None)

        self.assertEqual(project2, project_ref)

    def test_get_project_by_name_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    def test_create_duplicate_project_id_fails(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        PROVIDERS.resource_api.create_project(project_id, project)
        project['name'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          PROVIDERS.resource_api.create_project,
                          project_id,
                          project)

    def test_create_duplicate_project_name_fails(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        PROVIDERS.resource_api.create_project(project_id, project)
        project['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          PROVIDERS.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_project_name_with_trailing_whitespace(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        project_name = project['name'] = (project['name'] + '    ')
        project_returned = PROVIDERS.resource_api.create_project(
            project_id, project
        )
        self.assertEqual(project_id, project_returned['id'])
        self.assertEqual(project_name.strip(), project_returned['name'])

    def test_create_duplicate_project_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project2 = unit.new_project_ref(name=project1['name'],
                                        domain_id=new_domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        PROVIDERS.resource_api.create_project(project2['id'], project2)

    def test_rename_duplicate_project_name_fails(self):
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        project2['name'] = project1['name']
        self.assertRaises(exception.Error,
                          PROVIDERS.resource_api.update_project,
                          project2['id'],
                          project2)

    def test_update_project_id_does_nothing(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        PROVIDERS.resource_api.create_project(project['id'], project)
        project['id'] = 'fake2'
        PROVIDERS.resource_api.update_project(project_id, project)
        project_ref = PROVIDERS.resource_api.get_project(project_id)
        self.assertEqual(project_id, project_ref['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          'fake2')

    def test_update_project_name_with_trailing_whitespace(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        project_create = PROVIDERS.resource_api.create_project(
            project_id, project
        )
        self.assertEqual(project_id, project_create['id'])
        project_name = project['name'] = (project['name'] + '    ')
        project_update = PROVIDERS.resource_api.update_project(
            project_id, project
        )
        self.assertEqual(project_id, project_update['id'])
        self.assertEqual(project_name.strip(), project_update['name'])

    def test_delete_domain_with_user_group_project_links(self):
        # TODO(chungg):add test case once expected behaviour defined
        pass

    def test_update_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.update_project,
                          uuid.uuid4().hex,
                          dict())

    def test_delete_project_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.delete_project,
                          uuid.uuid4().hex)

    def test_create_update_delete_unicode_project(self):
        unicode_project_name = u'name \u540d\u5b57'
        project = unit.new_project_ref(
            name=unicode_project_name,
            domain_id=CONF.identity.default_domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.resource_api.update_project(project['id'], project)
        PROVIDERS.resource_api.delete_project(project['id'])

    def test_create_project_with_no_enabled_field(self):
        ref = unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        del ref['enabled']
        PROVIDERS.resource_api.create_project(ref['id'], ref)

        project = PROVIDERS.resource_api.get_project(ref['id'])
        self.assertIs(project['enabled'], True)

    def test_create_project_long_name_fails(self):
        project = unit.new_project_ref(
            name='a' * 65, domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_project_invalid_domain_id(self):
        project = unit.new_project_ref(domain_id=uuid.uuid4().hex)
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.create_project,
                          project['id'],
                          project)

    def test_list_domains(self):
        domain1 = unit.new_domain_ref()
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        domains = PROVIDERS.resource_api.list_domains()
        self.assertEqual(3, len(domains))
        domain_ids = []
        for domain in domains:
            domain_ids.append(domain.get('id'))
        self.assertIn(CONF.identity.default_domain_id, domain_ids)
        self.assertIn(domain1['id'], domain_ids)
        self.assertIn(domain2['id'], domain_ids)

    def test_list_projects(self):
        project_refs = PROVIDERS.resource_api.list_projects()
        project_count = len(default_fixtures.PROJECTS) + self.domain_count
        self.assertEqual(project_count, len(project_refs))
        for project in default_fixtures.PROJECTS:
            self.assertIn(project, project_refs)

    def test_list_projects_with_multiple_filters(self):
        # Create a project
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)

        # Build driver hints with the project's name and inexistent description
        hints = driver_hints.Hints()
        hints.add_filter('name', project['name'])
        hints.add_filter('description', uuid.uuid4().hex)

        # Retrieve projects based on hints and check an empty list is returned
        projects = PROVIDERS.resource_api.list_projects(hints)
        self.assertEqual([], projects)

        # Build correct driver hints
        hints = driver_hints.Hints()
        hints.add_filter('name', project['name'])
        hints.add_filter('description', project['description'])

        # Retrieve projects based on hints
        projects = PROVIDERS.resource_api.list_projects(hints)

        # Check that the returned list contains only the first project
        self.assertEqual(1, len(projects))
        self.assertEqual(project, projects[0])

    def test_list_projects_for_domain(self):
        project_ids = ([x['id'] for x in
                       PROVIDERS.resource_api.list_projects_in_domain(
                           CONF.identity.default_domain_id)])
        # Only the projects from the default fixtures are expected, since
        # filtering by domain does not include any project that acts as a
        # domain.
        self.assertThat(
            project_ids, matchers.HasLength(len(default_fixtures.PROJECTS)))
        self.assertIn(self.project_bar['id'], project_ids)
        self.assertIn(self.project_baz['id'], project_ids)
        self.assertIn(self.project_mtu['id'], project_ids)
        self.assertIn(self.project_service['id'], project_ids)

    @unit.skip_if_no_multiple_domains_support
    def test_list_projects_acting_as_domain(self):
        initial_domains = PROVIDERS.resource_api.list_domains()

        # Creating 5 projects that act as domains
        new_projects_acting_as_domains = []
        for i in range(5):
            project = unit.new_project_ref(is_domain=True)
            project = PROVIDERS.resource_api.create_project(
                project['id'], project
            )
            new_projects_acting_as_domains.append(project)

        # Creating a few regular project to ensure it doesn't mess with the
        # ones that act as domains
        self._create_projects_hierarchy(hierarchy_size=2)

        projects = PROVIDERS.resource_api.list_projects_acting_as_domain()
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
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        project_ids = ([x['id'] for x in
                       PROVIDERS.resource_api.list_projects_in_domain(
                           domain1['id'])])
        self.assertEqual(2, len(project_ids))
        self.assertIn(project1['id'], project_ids)
        self.assertIn(project2['id'], project_ids)

    def _create_projects_hierarchy(self, hierarchy_size=2,
                                   domain_id=None,
                                   is_domain=False,
                                   parent_project_id=None):
        """Create a project hierarchy with specified size.

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
        project = PROVIDERS.resource_api.create_project(project_id, project)

        projects = [project]
        for i in range(1, hierarchy_size):
            new_project = unit.new_project_ref(parent_id=project_id,
                                               domain_id=domain_id)

            PROVIDERS.resource_api.create_project(
                new_project['id'], new_project
            )
            projects.append(new_project)
            project_id = new_project['id']

        return projects

    @unit.skip_if_no_multiple_domains_support
    def test_create_domain_with_project_api(self):
        project = unit.new_project_ref(is_domain=True)
        ref = PROVIDERS.resource_api.create_project(project['id'], project)
        self.assertTrue(ref['is_domain'])
        PROVIDERS.resource_api.get_domain(ref['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_project_as_a_domain_uniqueness_constraints(self):
        """Test project uniqueness for those acting as domains.

        If it is a project acting as a domain, we can't have two or more with
        the same name.

        """
        # Create two projects acting as a domain
        project = unit.new_project_ref(is_domain=True)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        project2 = unit.new_project_ref(is_domain=True)
        project2 = PROVIDERS.resource_api.create_project(
            project2['id'], project2
        )

        # All projects acting as domains have a null domain_id, so should not
        # be able to create another with the same name but a different
        # project ID.
        new_project = project.copy()
        new_project['id'] = uuid.uuid4().hex

        self.assertRaises(exception.Conflict,
                          PROVIDERS.resource_api.create_project,
                          new_project['id'],
                          new_project)

        # We also should not be able to update one to have a name clash
        project2['name'] = project['name']
        self.assertRaises(exception.Conflict,
                          PROVIDERS.resource_api.update_project,
                          project2['id'],
                          project2)

        # But updating it to a unique name is OK
        project2['name'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_project(project2['id'], project2)

        # Finally, it should be OK to create a project with same name as one of
        # these acting as a domain, as long as it is a regular project
        project3 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, name=project2['name'])
        PROVIDERS.resource_api.create_project(project3['id'], project3)
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
        PROVIDERS.resource_api.create_project(project['id'], project)

        sub_project = unit.new_project_ref(domain_id=project['id'],
                                           parent_id=project['id'],
                                           is_domain=True)

        ref = PROVIDERS.resource_api.create_project(
            sub_project['id'], sub_project
        )
        self.assertTrue(ref['is_domain'])
        self.assertEqual(project['id'], ref['parent_id'])
        self.assertEqual(project['id'], ref['domain_id'])

    @unit.skip_if_no_multiple_domains_support
    def test_delete_domain_with_project_api(self):
        project = unit.new_project_ref(domain_id=None,
                                       is_domain=True)
        PROVIDERS.resource_api.create_project(project['id'], project)

        # Check that a corresponding domain was created
        PROVIDERS.resource_api.get_domain(project['id'])

        # Try to delete the enabled project that acts as a domain
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.delete_project,
                          project['id'])

        # Disable the project
        project['enabled'] = False
        PROVIDERS.resource_api.update_project(project['id'], project)

        # Successfully delete the project
        PROVIDERS.resource_api.delete_project(project['id'])

        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project['id'])

        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain,
                          project['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_create_subproject_acting_as_domain_fails(self):
        root_project = unit.new_project_ref(is_domain=True)
        PROVIDERS.resource_api.create_project(root_project['id'], root_project)

        sub_project = unit.new_project_ref(is_domain=True,
                                           parent_id=root_project['id'])

        # Creation of sub projects acting as domains is not allowed yet
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.create_project,
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
                          PROVIDERS.resource_api.create_project,
                          project['id'], project)

    @unit.skip_if_no_multiple_domains_support
    @test_utils.wip('waiting for sub projects acting as domains support')
    def test_create_project_under_domain_hierarchy(self):
        projects_hierarchy = self._create_projects_hierarchy(is_domain=True)
        parent = projects_hierarchy[1]
        project = unit.new_project_ref(domain_id=parent['id'],
                                       parent_id=parent['id'],
                                       is_domain=False)

        ref = PROVIDERS.resource_api.create_project(project['id'], project)
        self.assertFalse(ref['is_domain'])
        self.assertEqual(parent['id'], ref['parent_id'])
        self.assertEqual(parent['id'], ref['domain_id'])

    def test_create_project_without_is_domain_flag(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        del project['is_domain']
        ref = PROVIDERS.resource_api.create_project(project['id'], project)
        # The is_domain flag should be False by default
        self.assertFalse(ref['is_domain'])

    @unit.skip_if_no_multiple_domains_support
    def test_create_project_passing_is_domain_flag_true(self):
        project = unit.new_project_ref(is_domain=True)

        ref = PROVIDERS.resource_api.create_project(project['id'], project)
        self.assertTrue(ref['is_domain'])

    def test_create_project_passing_is_domain_flag_false(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, is_domain=False)

        ref = PROVIDERS.resource_api.create_project(project['id'], project)
        self.assertIs(False, ref['is_domain'])

    @test_utils.wip('waiting for support for parent_id to imply domain_id')
    def test_create_project_with_parent_id_and_without_domain_id(self):
        # First create a domain
        project = unit.new_project_ref(is_domain=True)
        PROVIDERS.resource_api.create_project(project['id'], project)
        # Now create a child by just naming the parent_id
        sub_project = unit.new_project_ref(parent_id=project['id'])
        ref = PROVIDERS.resource_api.create_project(
            sub_project['id'], sub_project
        )

        # The domain_id should be set to the parent domain_id
        self.assertEqual(project['domain_id'], ref['domain_id'])

    def test_create_project_with_domain_id_and_without_parent_id(self):
        # First create a domain
        project = unit.new_project_ref(is_domain=True)
        PROVIDERS.resource_api.create_project(project['id'], project)
        # Now create a child by just naming the domain_id
        sub_project = unit.new_project_ref(domain_id=project['id'])
        ref = PROVIDERS.resource_api.create_project(
            sub_project['id'], sub_project
        )

        # The parent_id and domain_id should be set to the id of the project
        # acting as a domain
        self.assertEqual(project['id'], ref['parent_id'])
        self.assertEqual(project['id'], ref['domain_id'])

    def test_create_project_with_domain_id_mismatch_to_parent_domain(self):
        # First create a domain
        project = unit.new_project_ref(is_domain=True)
        PROVIDERS.resource_api.create_project(project['id'], project)
        # Now try to create a child with the above as its parent, but
        # specifying a different domain.
        sub_project = unit.new_project_ref(
            parent_id=project['id'], domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.create_project,
                          sub_project['id'], sub_project)

    def test_check_leaf_projects(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        self.assertFalse(PROVIDERS.resource_api.is_leaf_project(
            root_project['id']))
        self.assertTrue(PROVIDERS.resource_api.is_leaf_project(
            leaf_project['id']))

        # Delete leaf_project
        PROVIDERS.resource_api.delete_project(leaf_project['id'])

        # Now, root_project should be leaf
        self.assertTrue(PROVIDERS.resource_api.is_leaf_project(
            root_project['id']))

    def test_list_projects_in_subtree(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]
        project4 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project2['id'])
        PROVIDERS.resource_api.create_project(project4['id'], project4)

        subtree = PROVIDERS.resource_api.list_projects_in_subtree(
            project1['id']
        )
        self.assertEqual(3, len(subtree))
        self.assertIn(project2, subtree)
        self.assertIn(project3, subtree)
        self.assertIn(project4, subtree)

        subtree = PROVIDERS.resource_api.list_projects_in_subtree(
            project2['id']
        )
        self.assertEqual(2, len(subtree))
        self.assertIn(project3, subtree)
        self.assertIn(project4, subtree)

        subtree = PROVIDERS.resource_api.list_projects_in_subtree(
            project3['id']
        )
        self.assertEqual(0, len(subtree))

    def test_get_projects_in_subtree_as_ids_with_large_tree(self):
        """Check project hierarchy is returned correctly in large tree.

        With a large hierarchy we need to enforce the projects
        are returned in the correct order (illustrated below).

        Tree we will create::

               +------p1------+
               |              |
            +---p3---+      +-p2-+
            |        |      |    |
            p7    +-p6-+   p5    p4
            |     |    |
            p10   p9   p8
                  |
                 p11
        """
        # Create large project hierarchy, of above depiction
        p1, p2, p4 = self._create_projects_hierarchy(hierarchy_size=3)
        p5 = self._create_projects_hierarchy(
            hierarchy_size=1, parent_project_id=p2['id'])[0]
        p3, p6, p8 = self._create_projects_hierarchy(
            hierarchy_size=3, parent_project_id=p1['id'])
        p9, p11 = self._create_projects_hierarchy(
            hierarchy_size=2, parent_project_id=p6['id'])
        p7, p10 = self._create_projects_hierarchy(
            hierarchy_size=2, parent_project_id=p3['id'])

        expected_projects = {
            p2['id']: {
                p5['id']: None,
                p4['id']: None},
            p3['id']: {
                p7['id']: {
                    p10['id']: None},
                p6['id']: {
                    p9['id']: {
                        p11['id']: None},
                    p8['id']: None}}}

        prjs_hierarchy = PROVIDERS.resource_api.get_projects_in_subtree_as_ids(
            p1['id'])

        self.assertDictEqual(expected_projects, prjs_hierarchy)

    def test_list_projects_in_subtree_with_circular_reference(self):
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project1 = PROVIDERS.resource_api.create_project(
            project1['id'], project1
        )

        project2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project1['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)

        project1['parent_id'] = project2['id']  # Adds cyclic reference

        # NOTE(dstanek): The manager does not allow parent_id to be updated.
        # Instead will directly use the driver to create the cyclic
        # reference.
        PROVIDERS.resource_api.driver.update_project(project1['id'], project1)

        subtree = PROVIDERS.resource_api.list_projects_in_subtree(
            project1['id']
        )

        # NOTE(dstanek): If a cyclic reference is detected the code bails
        # and returns None instead of falling into the infinite
        # recursion trap.
        self.assertIsNone(subtree)

    def test_list_projects_in_subtree_invalid_project_id(self):
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.list_projects_in_subtree,
                          None)

        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.list_projects_in_subtree,
                          uuid.uuid4().hex)

    def test_list_project_parents(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]
        project4 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project2['id'])
        PROVIDERS.resource_api.create_project(project4['id'], project4)

        parents1 = PROVIDERS.resource_api.list_project_parents(project3['id'])
        self.assertEqual(3, len(parents1))
        self.assertIn(project1, parents1)
        self.assertIn(project2, parents1)

        parents2 = PROVIDERS.resource_api.list_project_parents(project4['id'])
        self.assertEqual(parents1, parents2)

        parents = PROVIDERS.resource_api.list_project_parents(project1['id'])
        # It has the default domain as parent
        self.assertEqual(1, len(parents))

    def test_update_project_enabled_cascade(self):
        """Test update_project_cascade.

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
        parent_ref = PROVIDERS.resource_api.update_project(
            parent['id'], parent, cascade=True
        )

        subtree = PROVIDERS.resource_api.list_projects_in_subtree(parent['id'])
        self.assertEqual(2, len(subtree))
        self.assertFalse(parent_ref['enabled'])
        self.assertFalse(subtree[0]['enabled'])
        self.assertFalse(subtree[1]['enabled'])

        # Enable parent project enables the whole subtree
        parent['enabled'] = True
        parent_ref = PROVIDERS.resource_api.update_project(
            parent['id'], parent, cascade=True
        )

        subtree = PROVIDERS.resource_api.list_projects_in_subtree(parent['id'])
        self.assertEqual(2, len(subtree))
        self.assertTrue(parent_ref['enabled'])
        self.assertTrue(subtree[0]['enabled'])
        self.assertTrue(subtree[1]['enabled'])

    def test_cannot_enable_cascade_with_parent_disabled(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        grandparent = projects_hierarchy[0]
        parent = projects_hierarchy[1]

        grandparent['enabled'] = False
        PROVIDERS.resource_api.update_project(
            grandparent['id'], grandparent, cascade=True
        )
        subtree = PROVIDERS.resource_api.list_projects_in_subtree(parent['id'])
        self.assertFalse(subtree[0]['enabled'])

        parent['enabled'] = True
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.update_project,
                          parent['id'],
                          parent,
                          cascade=True)

    def test_update_cascade_only_accepts_enabled(self):
        # Update cascade does not accept any other attribute but 'enabled'
        new_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)

        new_project['name'] = 'project1'
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.update_project,
                          new_project['id'],
                          new_project,
                          cascade=True)

    def test_list_project_parents_invalid_project_id(self):
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.list_project_parents,
                          None)

        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.list_project_parents,
                          uuid.uuid4().hex)

    def test_create_project_doesnt_modify_passed_in_dict(self):
        new_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        original_project = new_project.copy()
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)
        self.assertDictEqual(original_project, new_project)

    def test_update_project_enable(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue(project_ref['enabled'])

        project['enabled'] = False
        PROVIDERS.resource_api.update_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertEqual(project['enabled'], project_ref['enabled'])

        # If not present, enabled field should not be updated
        del project['enabled']
        PROVIDERS.resource_api.update_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertFalse(project_ref['enabled'])

        project['enabled'] = True
        PROVIDERS.resource_api.update_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertEqual(project['enabled'], project_ref['enabled'])

        del project['enabled']
        PROVIDERS.resource_api.update_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue(project_ref['enabled'])

    def test_create_invalid_domain_fails(self):
        new_group = unit.new_group_ref(domain_id="doesnotexist")
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.identity_api.create_group,
                          new_group)
        new_user = unit.new_user_ref(domain_id="doesnotexist")
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.identity_api.create_user,
                          new_user)

    @unit.skip_if_no_multiple_domains_support
    def test_project_crud(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertLessEqual(project.items(), project_ref.items())

        project['name'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertLessEqual(project.items(), project_ref.items())

        PROVIDERS.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project['id'])

    def test_domain_delete_hierarchy(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        # Creating a root and a leaf project inside the domain
        projects_hierarchy = self._create_projects_hierarchy(
            domain_id=domain['id'])
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[0]

        # Disable the domain
        domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain['id'], domain)

        # Delete the domain
        PROVIDERS.resource_api.delete_domain(domain['id'])

        # Make sure the domain no longer exists
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain,
                          domain['id'])

        # Make sure the root project no longer exists
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          root_project['id'])

        # Make sure the leaf project no longer exists
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          leaf_project['id'])

    def test_delete_projects_from_ids(self):
        """Test the resource backend call delete_projects_from_ids.

        Tests the normal flow of the delete_projects_from_ids backend call,
        that ensures no project on the list exists after it is successfully
        called.
        """
        project1_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project2_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        projects = (project1_ref, project2_ref)
        for project in projects:
            PROVIDERS.resource_api.create_project(project['id'], project)

        # Setting up the ID's list
        projects_ids = [p['id'] for p in projects]
        PROVIDERS.resource_api.driver.delete_projects_from_ids(projects_ids)

        # Ensuring projects no longer exist at backend level
        for project_id in projects_ids:
            self.assertRaises(exception.ProjectNotFound,
                              PROVIDERS.resource_api.driver.get_project,
                              project_id)

        # Passing an empty list is silently ignored
        PROVIDERS.resource_api.driver.delete_projects_from_ids([])

    def test_delete_projects_from_ids_with_no_existing_project_id(self):
        """Test delete_projects_from_ids issues warning if not found.

        Tests the resource backend call delete_projects_from_ids passing a
        non existing ID in project_ids, which is logged and ignored by
        the backend.
        """
        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)

        # Setting up the ID's list
        projects_ids = (project_ref['id'], uuid.uuid4().hex)
        with mock.patch('keystone.resource.backends.sql.LOG') as mock_log:
            PROVIDERS.resource_api.delete_projects_from_ids(projects_ids)
            self.assertTrue(mock_log.warning.called)
        # The existing project was deleted.
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.driver.get_project,
                          project_ref['id'])

        # Even if we only have one project, and it does not exist, it returns
        # no error.
        PROVIDERS.resource_api.driver.delete_projects_from_ids(
            [uuid.uuid4().hex]
        )

    def test_delete_project_cascade(self):
        # create a hierarchy with 3 levels
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        root_project = projects_hierarchy[0]
        project1 = projects_hierarchy[1]
        project2 = projects_hierarchy[2]

        # Disabling all projects before attempting to delete
        for project in (project2, project1, root_project):
            project['enabled'] = False
            PROVIDERS.resource_api.update_project(project['id'], project)

        PROVIDERS.resource_api.delete_project(root_project['id'], cascade=True)

        for project in projects_hierarchy:
            self.assertRaises(exception.ProjectNotFound,
                              PROVIDERS.resource_api.get_project,
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
        prjs_hierarchy = (
            [p1] + PROVIDERS.resource_api.list_projects_in_subtree(
                p1['id']
            )
        )[::-1]

        # Disabling all projects before attempting to delete
        for project in prjs_hierarchy:
            project['enabled'] = False
            PROVIDERS.resource_api.update_project(project['id'], project)

        PROVIDERS.resource_api.delete_project(p1['id'], cascade=True)
        for project in prjs_hierarchy:
            self.assertRaises(exception.ProjectNotFound,
                              PROVIDERS.resource_api.get_project,
                              project['id'])

    def test_cannot_delete_project_cascade_with_enabled_child(self):
        # create a hierarchy with 3 levels
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        root_project = projects_hierarchy[0]
        project1 = projects_hierarchy[1]
        project2 = projects_hierarchy[2]

        project2['enabled'] = False
        PROVIDERS.resource_api.update_project(project2['id'], project2)

        # Cannot cascade delete root_project, since project1 is enabled
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.delete_project,
                          root_project['id'],
                          cascade=True)

        # Ensuring no project was deleted, not even project2
        PROVIDERS.resource_api.get_project(root_project['id'])
        PROVIDERS.resource_api.get_project(project1['id'])
        PROVIDERS.resource_api.get_project(project2['id'])

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
        PROVIDERS.resource_api.update_project(leaf_project['id'], leaf_project)
        proj_ref = PROVIDERS.resource_api.get_project(leaf_project['id'])
        self.assertDictEqual(leaf_project, proj_ref)

        # update the parent_id is not allowed
        leaf_project['parent_id'] = root_project1['id']
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.update_project,
                          leaf_project['id'],
                          leaf_project)

        # delete root_project1
        PROVIDERS.resource_api.delete_project(root_project1['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          root_project1['id'])

        # delete root_project2 is not allowed since it is not a leaf project
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.delete_project,
                          root_project2['id'])

    def test_create_project_with_invalid_parent(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, parent_id='fake')
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.create_project,
                          project['id'],
                          project)

    @unit.skip_if_no_multiple_domains_support
    def test_create_leaf_project_with_different_domain(self):
        root_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(root_project['id'], root_project)

        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        leaf_project = unit.new_project_ref(domain_id=domain['id'],
                                            parent_id=root_project['id'])

        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.create_project,
                          leaf_project['id'],
                          leaf_project)

    def test_delete_hierarchical_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        PROVIDERS.resource_api.delete_project(leaf_project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          leaf_project['id'])

        PROVIDERS.resource_api.delete_project(root_project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          root_project['id'])

    def test_delete_hierarchical_not_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]

        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.delete_project,
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
                          PROVIDERS.resource_api.update_project,
                          project3['id'],
                          project3)

    def test_create_project_under_disabled_one(self):
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, enabled=False)
        PROVIDERS.resource_api.create_project(project1['id'], project1)

        project2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project1['id'])

        # It's not possible to create a project under a disabled one in the
        # hierarchy
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.create_project,
                          project2['id'],
                          project2)

    def test_disable_hierarchical_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        leaf_project = projects_hierarchy[1]

        leaf_project['enabled'] = False
        PROVIDERS.resource_api.update_project(leaf_project['id'], leaf_project)

        project_ref = PROVIDERS.resource_api.get_project(leaf_project['id'])
        self.assertEqual(leaf_project['enabled'], project_ref['enabled'])

    def test_disable_hierarchical_not_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]

        root_project['enabled'] = False
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.update_project,
                          root_project['id'],
                          root_project)

    def test_enable_project_with_disabled_parent(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        # Disable leaf and root
        leaf_project['enabled'] = False
        PROVIDERS.resource_api.update_project(leaf_project['id'], leaf_project)
        root_project['enabled'] = False
        PROVIDERS.resource_api.update_project(root_project['id'], root_project)

        # Try to enable the leaf project, it's not possible since it has
        # a disabled parent
        leaf_project['enabled'] = True
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.update_project,
                          leaf_project['id'],
                          leaf_project)

    def _get_hierarchy_depth(self, project_id):
        return len(PROVIDERS.resource_api.list_project_parents(project_id)) + 1

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
                          PROVIDERS.resource_api.create_project,
                          project['id'],
                          project)

    def test_project_update_missing_attrs_with_a_value(self):
        # Creating a project with no description attribute.
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        del project['description']
        project = PROVIDERS.resource_api.create_project(project['id'], project)

        # Add a description attribute.
        project['description'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_project(project['id'], project)

        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(project, project_ref)

    def test_project_update_missing_attrs_with_a_falsey_value(self):
        # Creating a project with no description attribute.
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        del project['description']
        project = PROVIDERS.resource_api.create_project(project['id'], project)

        # Add a description attribute.
        project['description'] = ''
        PROVIDERS.resource_api.update_project(project['id'], project)

        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(project, project_ref)

    def test_domain_crud(self):
        domain = unit.new_domain_ref()
        domain_ref = PROVIDERS.resource_api.create_domain(domain['id'], domain)
        self.assertDictEqual(domain, domain_ref)
        domain_ref = PROVIDERS.resource_api.get_domain(domain['id'])
        self.assertDictEqual(domain, domain_ref)

        domain['name'] = uuid.uuid4().hex
        domain_ref = PROVIDERS.resource_api.update_domain(domain['id'], domain)
        self.assertDictEqual(domain, domain_ref)
        domain_ref = PROVIDERS.resource_api.get_domain(domain['id'])
        self.assertDictEqual(domain, domain_ref)

        # Ensure an 'enabled' domain cannot be deleted
        self.assertRaises(exception.ForbiddenNotSecurity,
                          PROVIDERS.resource_api.delete_domain,
                          domain_id=domain['id'])

        # Disable the domain
        domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain['id'], domain)

        # Delete the domain
        PROVIDERS.resource_api.delete_domain(domain['id'])

        # Make sure the domain no longer exists
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain,
                          domain['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_delete_domain_call_db_time(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        # Disable the domain
        domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain['id'], domain)

        domain_ref = PROVIDERS.resource_api.get_project(domain['id'])
        with mock.patch.object(resource_sql.Resource,
                               "get_project") as mock_get_project:

            mock_get_project.return_value = domain_ref
            # Delete the domain
            PROVIDERS.resource_api.delete_domain(domain['id'])
            self.assertEqual(mock_get_project.call_count, 1)

    @unit.skip_if_no_multiple_domains_support
    def test_domain_name_case_sensitivity(self):
        # create a ref with a lowercase name
        domain_name = 'test_domain'
        ref = unit.new_domain_ref(name=domain_name)

        lower_case_domain = PROVIDERS.resource_api.create_domain(
            ref['id'], ref
        )

        # assign a new ID to the ref with the same name, but in uppercase
        ref['id'] = uuid.uuid4().hex
        ref['name'] = domain_name.upper()
        upper_case_domain = PROVIDERS.resource_api.create_domain(
            ref['id'], ref
        )

        # We can get each domain by name
        lower_case_domain_ref = PROVIDERS.resource_api.get_domain_by_name(
            domain_name)
        self.assertDictEqual(lower_case_domain, lower_case_domain_ref)

        upper_case_domain_ref = PROVIDERS.resource_api.get_domain_by_name(
            domain_name.upper())
        self.assertDictEqual(upper_case_domain, upper_case_domain_ref)

    def test_project_attribute_update(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)

        # pick a key known to be non-existent
        key = 'description'

        def assert_key_equals(value):
            project_ref = PROVIDERS.resource_api.update_project(
                project['id'], project)
            self.assertEqual(value, project_ref[key])
            project_ref = PROVIDERS.resource_api.get_project(project['id'])
            self.assertEqual(value, project_ref[key])

        def assert_get_key_is(value):
            project_ref = PROVIDERS.resource_api.update_project(
                project['id'], project)
            self.assertIs(project_ref.get(key), value)
            project_ref = PROVIDERS.resource_api.get_project(project['id'])
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

    @unit.skip_if_cache_disabled('resource')
    @unit.skip_if_no_multiple_domains_support
    def test_domain_rename_invalidates_get_domain_by_name_cache(self):
        domain = unit.new_domain_ref()
        domain_id = domain['id']
        domain_name = domain['name']
        PROVIDERS.resource_api.create_domain(domain_id, domain)
        domain_ref = PROVIDERS.resource_api.get_domain_by_name(domain_name)
        domain_ref['name'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_domain(domain_id, domain_ref)
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain_by_name,
                          domain_name)

    @unit.skip_if_cache_disabled('resource')
    def test_cache_layer_domain_crud(self):
        domain = unit.new_domain_ref()
        domain_id = domain['id']
        # Create Domain
        PROVIDERS.resource_api.create_domain(domain_id, domain)
        project_domain_ref = PROVIDERS.resource_api.get_project(domain_id)
        domain_ref = PROVIDERS.resource_api.get_domain(domain_id)
        updated_project_domain_ref = copy.deepcopy(project_domain_ref)
        updated_project_domain_ref['name'] = uuid.uuid4().hex
        updated_domain_ref = copy.deepcopy(domain_ref)
        updated_domain_ref['name'] = updated_project_domain_ref['name']
        # Update domain, bypassing resource api manager
        PROVIDERS.resource_api.driver.update_project(
            domain_id, updated_project_domain_ref
        )
        # Verify get_domain still returns the domain
        self.assertLessEqual(
            domain_ref.items(),
            PROVIDERS.resource_api.get_domain(domain_id).items())
        # Invalidate cache
        PROVIDERS.resource_api.get_domain.invalidate(
            PROVIDERS.resource_api, domain_id
        )
        # Verify get_domain returns the updated domain
        self.assertLessEqual(
            updated_domain_ref.items(),
            PROVIDERS.resource_api.get_domain(domain_id).items())
        # Update the domain back to original ref, using the assignment api
        # manager
        PROVIDERS.resource_api.update_domain(domain_id, domain_ref)
        self.assertLessEqual(
            domain_ref.items(),
            PROVIDERS.resource_api.get_domain(domain_id).items())
        # Make sure domain is 'disabled', bypass resource api manager
        project_domain_ref_disabled = project_domain_ref.copy()
        project_domain_ref_disabled['enabled'] = False
        PROVIDERS.resource_api.driver.update_project(
            domain_id, project_domain_ref_disabled
        )
        PROVIDERS.resource_api.driver.update_project(
            domain_id, {'enabled': False}
        )
        # Delete domain, bypassing resource api manager
        PROVIDERS.resource_api.driver.delete_project(domain_id)
        # Verify get_domain still returns the domain
        self.assertLessEqual(
            domain_ref.items(),
            PROVIDERS.resource_api.get_domain(domain_id).items())
        # Invalidate cache
        PROVIDERS.resource_api.get_domain.invalidate(
            PROVIDERS.resource_api, domain_id
        )
        # Verify get_domain now raises DomainNotFound
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain, domain_id)
        # Recreate Domain
        PROVIDERS.resource_api.create_domain(domain_id, domain)
        PROVIDERS.resource_api.get_domain(domain_id)
        # Make sure domain is 'disabled', bypass resource api manager
        domain['enabled'] = False
        PROVIDERS.resource_api.driver.update_project(domain_id, domain)
        PROVIDERS.resource_api.driver.update_project(
            domain_id, {'enabled': False}
        )
        # Delete domain
        PROVIDERS.resource_api.delete_domain(domain_id)
        # verify DomainNotFound raised
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain,
                          domain_id)

    @unit.skip_if_cache_disabled('resource')
    @unit.skip_if_no_multiple_domains_support
    def test_project_rename_invalidates_get_project_by_name_cache(self):
        domain = unit.new_domain_ref()
        project = unit.new_project_ref(domain_id=domain['id'])
        project_id = project['id']
        project_name = project['name']
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        # Create a project
        PROVIDERS.resource_api.create_project(project_id, project)
        PROVIDERS.resource_api.get_project_by_name(project_name, domain['id'])
        project['name'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_project(project_id, project)
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project_by_name,
                          project_name,
                          domain['id'])

    @unit.skip_if_cache_disabled('resource')
    @unit.skip_if_no_multiple_domains_support
    def test_cache_layer_project_crud(self):
        domain = unit.new_domain_ref()
        project = unit.new_project_ref(domain_id=domain['id'])
        project_id = project['id']
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        # Create a project
        PROVIDERS.resource_api.create_project(project_id, project)
        PROVIDERS.resource_api.get_project(project_id)
        updated_project = copy.deepcopy(project)
        updated_project['name'] = uuid.uuid4().hex
        # Update project, bypassing resource manager
        PROVIDERS.resource_api.driver.update_project(
            project_id, updated_project
        )
        # Verify get_project still returns the original project_ref
        self.assertLessEqual(
            project.items(),
            PROVIDERS.resource_api.get_project(project_id).items())
        # Invalidate cache
        PROVIDERS.resource_api.get_project.invalidate(
            PROVIDERS.resource_api, project_id
        )
        # Verify get_project now returns the new project
        self.assertLessEqual(
            updated_project.items(),
            PROVIDERS.resource_api.get_project(project_id).items())
        # Update project using the resource_api manager back to original
        PROVIDERS.resource_api.update_project(project['id'], project)
        # Verify get_project returns the original project_ref
        self.assertLessEqual(
            project.items(),
            PROVIDERS.resource_api.get_project(project_id).items())
        # Delete project bypassing resource
        PROVIDERS.resource_api.driver.delete_project(project_id)
        # Verify get_project still returns the project_ref
        self.assertLessEqual(
            project.items(),
            PROVIDERS.resource_api.get_project(project_id).items())
        # Invalidate cache
        PROVIDERS.resource_api.get_project.invalidate(
            PROVIDERS.resource_api, project_id
        )
        # Verify ProjectNotFound now raised
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project_id)
        # recreate project
        PROVIDERS.resource_api.create_project(project_id, project)
        PROVIDERS.resource_api.get_project(project_id)
        # delete project
        PROVIDERS.resource_api.delete_project(project_id)
        # Verify ProjectNotFound is raised
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project_id)

    @unit.skip_if_no_multiple_domains_support
    def test_get_default_domain_by_name(self):
        domain_name = 'default'

        domain = unit.new_domain_ref(name=domain_name)
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        domain_ref = PROVIDERS.resource_api.get_domain_by_name(domain_name)
        self.assertEqual(domain, domain_ref)

    def test_get_not_default_domain_by_name(self):
        domain_name = 'foo'
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain_by_name,
                          domain_name)

    def test_project_update_and_project_get_return_same_response(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)

        PROVIDERS.resource_api.create_project(project['id'], project)

        updated_project = {'enabled': False}
        updated_project_ref = PROVIDERS.resource_api.update_project(
            project['id'], updated_project)

        # SQL backend adds 'extra' field
        updated_project_ref.pop('extra', None)

        self.assertIs(False, updated_project_ref['enabled'])

        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(updated_project_ref, project_ref)

    def test_delete_project_clears_default_project_id(self):
        self.config_fixture.config(group='cache', enabled=False)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 project_id=project['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)
        user = PROVIDERS.identity_api.create_user(user)
        user = PROVIDERS.identity_api.get_user(user['id'])

        # LDAP is read only default_project_id doesn't exist
        if 'default_project_id' in user:
            self.assertIsNotNone(user['default_project_id'])
            PROVIDERS.resource_api.delete_project(project['id'])
            user = PROVIDERS.identity_api.get_user(user['id'])
            self.assertNotIn('default_project_id', user)

    def test_delete_project_with_roles_clears_default_project_id(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 project_id=project['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)
        user = PROVIDERS.identity_api.create_user(user)
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        PROVIDERS.assignment_api.create_grant(
            user_id=user['id'], project_id=project['id'], role_id=role['id']
        )
        PROVIDERS.resource_api.delete_project(project['id'])
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertNotIn('default_project_id', user)

    def _create_project_and_tags(self, num_of_tags=1):
        """Create a project and tags associated to that project.

        :param num_of_tags: the desired number of tags attached to a
                            project, default is 1.

        :returns: A tuple of a new project and a list of random tags
        """
        tags = [uuid.uuid4().hex for i in range(num_of_tags)]
        ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, tags=tags)
        project = PROVIDERS.resource_api.create_project(ref['id'], ref)

        return project, tags

    def test_create_project_with_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=5)
        tag_ref = PROVIDERS.resource_api.get_project_tag(
            project['id'], tags[0]
        )
        self.assertEqual(tags[0], tag_ref)

    def test_get_project_contains_tags(self):
        project, _ = self._create_project_and_tags()
        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)
        ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertIn(tag, ref['tags'])

    def test_list_project_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=1)
        tag_ref = PROVIDERS.resource_api.list_project_tags(project['id'])
        self.assertEqual(tags[0], tag_ref[0])

    def test_list_project_tags_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.list_project_tags,
                          uuid.uuid4().hex)

    def test_get_project_tag(self):
        project, tags = self._create_project_and_tags()
        tag_ref = PROVIDERS.resource_api.get_project_tag(
            project['id'], tags[0]
        )
        self.assertEqual(tags[0], tag_ref)

    def test_create_project_tag_with_trailing_whitespace(self):
        project, _ = self._create_project_and_tags()
        tag = uuid.uuid4().hex + '   '
        tag_ref = PROVIDERS.resource_api.create_project_tag(project['id'], tag)
        self.assertEqual(tag.strip(), tag_ref)

    def test_create_project_tag_is_case_sensitive(self):
        project, _ = self._create_project_and_tags()
        new_tags = ['aaa', 'AAA']

        ref = PROVIDERS.resource_api.update_project_tags(
            project['id'], new_tags
        )
        for tag in new_tags:
            self.assertIn(tag, ref)

    def test_update_project_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=2)
        project_tag_ref = PROVIDERS.resource_api.list_project_tags(
            project['id']
        )
        self.assertEqual(len(project_tag_ref), 2)

        # Update project to only have one tag
        tags = ['one']
        PROVIDERS.resource_api.update_project_tags(project['id'], tags)
        project_tag_ref = PROVIDERS.resource_api.list_project_tags(
            project['id']
        )
        self.assertEqual(len(project_tag_ref), 1)

    def test_update_project_tags_returns_not_found(self):
        _, tags = self._create_project_and_tags(num_of_tags=2)
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.update_project_tags,
                          uuid.uuid4().hex,
                          tags)

    def test_delete_tag_from_project(self):
        project, tags = self._create_project_and_tags(num_of_tags=2)
        tag_to_delete = tags[-1]
        PROVIDERS.resource_api.delete_project_tag(project['id'], tag_to_delete)
        project_tag_ref = PROVIDERS.resource_api.list_project_tags(
            project['id'])
        self.assertEqual(len(project_tag_ref), 1)
        self.assertEqual(project_tag_ref[0], tags[0])

    def test_delete_project_tag_returns_not_found(self):
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.delete_project_tag,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_delete_project_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=5)
        project_tag_ref = PROVIDERS.resource_api.list_project_tags(
            project['id'])
        self.assertEqual(len(project_tag_ref), 5)

        PROVIDERS.resource_api.update_project_tags(project['id'], [])
        project_tag_ref = PROVIDERS.resource_api.list_project_tags(
            project['id']
        )
        self.assertEqual(project_tag_ref, [])

    def test_create_project_immutable(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project['options'][ro_opt.IMMUTABLE_OPT.option_name] = True

        p_created = PROVIDERS.resource_api.create_project(
            project['id'], project)
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue('options' in p_created)
        self.assertTrue('options' in project_via_manager)
        self.assertTrue(
            project_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertTrue(
            p_created['options'][ro_opt.IMMUTABLE_OPT.option_name])

    def test_cannot_update_immutable_project(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.resource_api.create_project(project['id'], project)

        update_project = {'name': uuid.uuid4().hex}
        self.assertRaises(exception.ResourceUpdateForbidden,
                          PROVIDERS.resource_api.update_project,
                          project['id'],
                          update_project)

    def test_cannot_update_immutable_project_while_unsetting_immutable(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.resource_api.create_project(project['id'], project)

        update_project = {
            'name': uuid.uuid4().hex,
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }}
        self.assertRaises(exception.ResourceUpdateForbidden,
                          PROVIDERS.resource_api.update_project,
                          project['id'],
                          update_project)

    def test_cannot_delete_immutable_project(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.resource_api.create_project(project['id'], project)
        self.assertRaises(exception.ResourceDeleteForbidden,
                          PROVIDERS.resource_api.delete_project,
                          project['id'])

    def test_update_project_set_immutable(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)
        update_project = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }}
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue('options' in project_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in project_via_manager['options'])
        p_update = PROVIDERS.resource_api.update_project(
            project['id'], update_project)
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in p_update['options'])
        self.assertTrue(
            p_update['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in project_via_manager['options'])
        self.assertTrue(
            project_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

    def test_update_project_set_immutable_with_additional_updates(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)
        update_project = {
            'name': uuid.uuid4().hex,
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }}
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue('options' in project_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in project_via_manager['options'])
        p_update = PROVIDERS.resource_api.update_project(
            project['id'], update_project)
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertEqual(p_update['name'], update_project['name'])
        self.assertEqual(project_via_manager['name'], update_project['name'])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in p_update['options'])
        self.assertTrue(
            p_update['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in project_via_manager['options'])
        self.assertTrue(
            project_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

    def test_update_project_unset_immutable(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.resource_api.create_project(project['id'], project)
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue('options' in project_via_manager)
        self.assertTrue(
            project_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

        update_project = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: False
            }}
        PROVIDERS.resource_api.update_project(project['id'], update_project)
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue('options' in project_via_manager)
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in project_via_manager['options'])
        self.assertFalse(
            project_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

        update_project = {'name': uuid.uuid4().hex}
        p_updated = PROVIDERS.resource_api.update_project(
            project['id'], update_project)
        self.assertEqual(p_updated['name'], update_project['name'])

        update_project = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: None
            }}
        p_updated = PROVIDERS.resource_api.update_project(
            project['id'], update_project)
        project_via_manager = PROVIDERS.resource_api.get_project(project['id'])
        self.assertTrue('options' in p_updated)
        self.assertTrue('options' in project_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in p_updated['options'])
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in project_via_manager['options'])

    def test_cannot_delete_project_tags_immutable_project(self):
        project, tags = self._create_project_and_tags(num_of_tags=2)
        update_project = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }
        }
        PROVIDERS.resource_api.update_project(project['id'], update_project)
        self.assertRaises(exception.ResourceUpdateForbidden,
                          PROVIDERS.resource_api.delete_project_tag,
                          project['id'],
                          tags[0])

    def test_cannot_update_project_tags_immutable_project(self):
        # Update and Add tag use the same API
        project, tags = self._create_project_and_tags(num_of_tags=2)
        update_project = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }
        }
        PROVIDERS.resource_api.update_project(project['id'], update_project)
        tags.append(uuid.uuid4().hex)
        self.assertRaises(exception.ResourceUpdateForbidden,
                          PROVIDERS.resource_api.update_project_tags,
                          project['id'],
                          tags)

    @unit.skip_if_no_multiple_domains_support
    def test_create_domain_immutable(self):
        domain_id = uuid.uuid4().hex

        domain = {
            'name': uuid.uuid4().hex,
            'id': domain_id,
            'is_domain': True,
            'options': {'immutable': True}
        }

        PROVIDERS.resource_api.create_domain(domain_id, domain)
        domain_via_manager = PROVIDERS.resource_api.get_domain(domain_id)
        self.assertTrue('options' in domain_via_manager)
        self.assertTrue(domain_via_manager['options']['immutable'])

    @unit.skip_if_no_multiple_domains_support
    def test_cannot_update_immutable_domain(self):
        domain_id = uuid.uuid4().hex

        domain = {
            'name': uuid.uuid4().hex,
            'id': domain_id,
            'is_domain': True,
            'options': {'immutable': True}
        }

        PROVIDERS.resource_api.create_domain(domain_id, domain)
        update_domain = {'name': uuid.uuid4().hex}
        self.assertRaises(exception.ResourceUpdateForbidden,
                          PROVIDERS.resource_api.update_domain,
                          domain_id,
                          update_domain)

    @unit.skip_if_no_multiple_domains_support
    def test_cannot_delete_immutable_domain(self):
        domain_id = uuid.uuid4().hex

        domain = {
            'name': uuid.uuid4().hex,
            'id': domain_id,
            'is_domain': True,
            'options': {'immutable': True}
        }

        PROVIDERS.resource_api.create_domain(domain_id, domain)
        self.assertRaises(exception.ResourceDeleteForbidden,
                          PROVIDERS.resource_api.delete_domain,
                          domain_id,)

    @unit.skip_if_no_multiple_domains_support
    def test_cannot_delete_disabled_domain_with_immutable_project(self):
        domain_id = uuid.uuid4().hex

        domain = {
            'name': uuid.uuid4().hex,
            'id': domain_id,
            'is_domain': True,
        }

        PROVIDERS.resource_api.create_domain(domain_id, domain)
        project = unit.new_project_ref(domain_id)
        project['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.resource_api.create_project(project['id'], project)
        # Disable the domain
        PROVIDERS.resource_api.update_domain(domain_id, {'enabled': False})
        # attempt to delete the domain, should error when the immutable
        # project is reached
        self.assertRaises(exception.ResourceDeleteForbidden,
                          PROVIDERS.resource_api.delete_domain,
                          domain_id)

    @unit.skip_if_no_multiple_domains_support
    def test_update_domain_set_immutable(self):
        # domains are projects, this should be the same as the project version
        domain_id = uuid.uuid4().hex

        domain = {
            'name': uuid.uuid4().hex,
            'id': domain_id,
            'is_domain': True,
        }

        PROVIDERS.resource_api.create_domain(domain_id, domain)
        domain_via_manager = PROVIDERS.resource_api.get_domain(domain_id)
        self.assertTrue('options' in domain_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in domain_via_manager['options'])

        domain_update = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }}
        d_update = PROVIDERS.resource_api.update_domain(
            domain_id, domain_update)
        domain_via_manager = PROVIDERS.resource_api.get_domain(domain_id)
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in d_update['options'])
        self.assertTrue(
            d_update['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in domain_via_manager['options'])
        self.assertTrue(
            domain_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

    def test_update_domain_unset_immutable(self):
        # domains are projects, this should be the same as the project version
        domain_id = uuid.uuid4().hex

        domain = {
            'name': uuid.uuid4().hex,
            'id': domain_id,
            'is_domain': True,
        }

        PROVIDERS.resource_api.create_domain(domain_id, domain)
        domain_via_manager = PROVIDERS.resource_api.get_domain(domain_id)
        self.assertTrue('options' in domain_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in domain_via_manager['options'])

        update_domain = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: False
            }}
        d_updated = PROVIDERS.resource_api.update_domain(
            domain_id, update_domain)
        domain_via_manager = PROVIDERS.resource_api.get_domain(domain_id)
        self.assertTrue('options' in domain_via_manager)
        self.assertTrue('options' in d_updated)
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in domain_via_manager['options'])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in d_updated['options'])
        self.assertFalse(
            d_updated['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertFalse(
            domain_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

        update_domain = {'name': uuid.uuid4().hex}
        d_updated = PROVIDERS.resource_api.update_domain(
            domain_id, update_domain)
        self.assertEqual(d_updated['name'], update_domain['name'])

        update_domain = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: None
            }}
        d_updated = PROVIDERS.resource_api.update_domain(
            domain_id, update_domain)
        domain_via_manager = PROVIDERS.resource_api.get_domain(domain_id)
        self.assertTrue('options' in d_updated)
        self.assertTrue('options' in domain_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in d_updated['options'])
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in domain_via_manager['options'])


class ResourceDriverTests(object):
    """Test for the resource driver.

    Subclasses must set self.driver to the driver instance.

    """

    def test_create_project(self):
        project_id = uuid.uuid4().hex
        project = {
            'name': uuid.uuid4().hex,
            'id': project_id,
            'domain_id': default_fixtures.ROOT_DOMAIN['id'],
        }
        self.driver.create_project(project_id, project)

    def test_create_project_all_defined_properties(self):
        project_id = uuid.uuid4().hex
        project = {
            'name': uuid.uuid4().hex,
            'id': project_id,
            'domain_id': default_fixtures.ROOT_DOMAIN['id'],
        }
        parent_project = self.driver.create_project(project_id, project)

        project_id = uuid.uuid4().hex
        project = {
            'name': uuid.uuid4().hex,
            'id': project_id,
            'domain_id': default_fixtures.ROOT_DOMAIN['id'],
            'description': uuid.uuid4().hex,
            'enabled': True,
            'parent_id': parent_project['id'],
            'is_domain': True,
        }
        self.driver.create_project(project_id, project)

    def test_create_project_null_domain(self):
        project_id = uuid.uuid4().hex
        project = {
            'name': uuid.uuid4().hex,
            'id': project_id,
            'domain_id': None,
        }
        self.driver.create_project(project_id, project)

    def test_create_project_same_name_same_domain_conflict(self):
        name = uuid.uuid4().hex
        domain_id = default_fixtures.ROOT_DOMAIN['id']

        project_id = uuid.uuid4().hex
        project = {
            'name': name,
            'id': project_id,
            'domain_id': domain_id,
        }
        self.driver.create_project(project_id, project)

        project_id = uuid.uuid4().hex
        project = {
            'name': name,
            'id': project_id,
            'domain_id': domain_id,
        }
        self.assertRaises(exception.Conflict, self.driver.create_project,
                          project_id, project)

    def test_create_project_same_id_conflict(self):
        project_id = uuid.uuid4().hex

        project = {
            'name': uuid.uuid4().hex,
            'id': project_id,
            'domain_id': default_fixtures.ROOT_DOMAIN['id'],
        }
        self.driver.create_project(project_id, project)

        project = {
            'name': uuid.uuid4().hex,
            'id': project_id,
            'domain_id': default_fixtures.ROOT_DOMAIN['id'],
        }
        self.assertRaises(exception.Conflict, self.driver.create_project,
                          project_id, project)
