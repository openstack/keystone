# -*- coding: utf-8 -*-
# Copyright 2012 OpenStack Foundation
# Copyright 2013 IBM Corp.
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
from unittest import mock
import uuid

import fixtures
import http.client
import ldap
from oslo_log import versionutils
import pkg_resources
from testtools import matchers

from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone import identity
from keystone.identity.backends import ldap as ldap_identity
from keystone.identity.backends.ldap import common as common_ldap
from keystone.identity.backends import sql as sql_identity
from keystone.identity.mapping_backends import mapping as map
from keystone.tests import unit
from keystone.tests.unit.assignment import test_backends as assignment_tests
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.identity import test_backends as identity_tests
from keystone.tests.unit import identity_mapping as mapping_sql
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.ksfixtures import ldapdb
from keystone.tests.unit.resource import test_backends as resource_tests


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


def _assert_backends(testcase, **kwargs):

    def _get_backend_cls(testcase, subsystem):
        observed_backend = getattr(testcase, subsystem + '_api').driver
        return observed_backend.__class__

    def _get_domain_specific_backend_cls(manager, domain):
        observed_backend = manager.domain_configs.get_domain_driver(domain)
        return observed_backend.__class__

    def _get_entrypoint_cls(subsystem, name):
        entrypoint = entrypoint_map['keystone.' + subsystem][name]
        return entrypoint.resolve()

    def _load_domain_specific_configs(manager):
        if (not manager.domain_configs.configured and
                CONF.identity.domain_specific_drivers_enabled):
            manager.domain_configs.setup_domain_drivers(
                manager.driver, manager.resource_api)

    def _assert_equal(expected_cls, observed_cls, subsystem,
                      domain=None):
        msg = ('subsystem %(subsystem)s expected %(expected_cls)r, '
               'but observed %(observed_cls)r')
        if domain:
            subsystem = '%s[domain=%s]' % (subsystem, domain)
        assert expected_cls == observed_cls, msg % {
            'expected_cls': expected_cls,
            'observed_cls': observed_cls,
            'subsystem': subsystem,
        }

    env = pkg_resources.Environment()
    keystone_dist = env['keystone'][0]
    entrypoint_map = pkg_resources.get_entry_map(keystone_dist)

    for subsystem, entrypoint_name in kwargs.items():
        if isinstance(entrypoint_name, str):
            observed_cls = _get_backend_cls(testcase, subsystem)
            expected_cls = _get_entrypoint_cls(subsystem, entrypoint_name)
            _assert_equal(expected_cls, observed_cls, subsystem)

        elif isinstance(entrypoint_name, dict):
            manager = getattr(testcase, subsystem + '_api')
            _load_domain_specific_configs(manager)

            for domain, entrypoint_name in entrypoint_name.items():
                if domain is None:
                    observed_cls = _get_backend_cls(testcase, subsystem)
                    expected_cls = _get_entrypoint_cls(
                        subsystem, entrypoint_name)
                    _assert_equal(expected_cls, observed_cls, subsystem)
                    continue

                observed_cls = _get_domain_specific_backend_cls(
                    manager, domain)
                expected_cls = _get_entrypoint_cls(subsystem, entrypoint_name)
                _assert_equal(expected_cls, observed_cls, subsystem, domain)

        else:
            raise ValueError('%r is not an expected value for entrypoint name'
                             % entrypoint_name)


class IdentityTests(identity_tests.IdentityTests):

    def test_update_domain_set_immutable(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_cannot_delete_disabled_domain_with_immutable(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_delete_immutable_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_create_domain_immutable(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_update_domain_unset_immutable(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_cannot_update_immutable_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_delete_user_with_group_project_domain_links(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_delete_group_with_user_project_domain_links(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_create_duplicate_user_name_in_different_domains(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_create_duplicate_group_name_in_different_domains(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_move_user_between_domains(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_move_group_between_domains(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_arbitrary_attributes_are_returned_from_get_user(self):
        self.skip_test_overrides(
            "Using arbitrary attributes doesn't work under LDAP")

    def test_new_arbitrary_attributes_are_returned_from_update_user(self):
        self.skip_test_overrides(
            "Using arbitrary attributes doesn't work under LDAP")

    def test_updated_arbitrary_attributes_are_returned_from_update_user(self):
        self.skip_test_overrides(
            "Using arbitrary attributes doesn't work under LDAP")

    def test_remove_user_from_group(self):
        self.skip_test_overrides('N/A: LDAP does not support write')

    def test_remove_user_from_group_returns_not_found(self):
        self.skip_test_overrides('N/A: LDAP does not support write')

    def test_delete_user_returns_not_found(self):
        self.skip_test_overrides('N/A: LDAP does not support write')


class AssignmentTests(assignment_tests.AssignmentTests):

    def test_get_role_assignment_by_domain_not_found(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_del_role_assignment_by_domain_not_found(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_get_and_remove_role_grant_by_user_and_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_get_and_remove_correct_role_grant_from_a_mix(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_get_and_remove_role_grant_by_group_and_cross_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_get_and_remove_role_grant_by_user_and_cross_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_role_grant_by_group_and_cross_domain_project(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_role_grant_by_user_and_cross_domain_project(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_delete_role_with_user_and_group_grants(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_list_role_assignment_containing_names(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_get_roles_for_user_and_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_get_roles_for_groups_on_domain(self):
        self.skip_test_overrides(
            'N/A: LDAP does not implement get_roles_for_groups; '
            'see bug 1333712 for details')

    def test_get_role_by_trustor_and_project(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_get_roles_for_groups_on_project(self):
        self.skip_test_overrides(
            'N/A: LDAP does not implement get_roles_for_groups; '
            'see bug 1333712 for details')

    def test_list_domains_for_groups(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_list_projects_for_groups(self):
        self.skip_test_overrides(
            'N/A: LDAP does not implement list_projects_for_groups; '
            'see bug 1333712 for details')

    def test_multi_group_grants_on_project_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')

    def test_delete_user_grant_no_user(self):
        self.skip_test_overrides('N/A: LDAP has no write support')

    def test_delete_group_grant_no_group(self):
        self.skip_test_overrides('N/A: LDAP has no write support')

    def test_delete_user_with_project_roles(self):
        self.skip_test_overrides('N/A: LDAP has no write support')

    def test_delete_user_with_project_association(self):
        self.skip_test_overrides('N/A: LDAP has no write support')

    def test_delete_group_removes_role_assignments(self):
        self.skip_test_overrides('N/A: LDAP has no write support')


class ResourceTests(resource_tests.ResourceTests):

    def test_create_duplicate_project_name_in_different_domains(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_move_project_between_domains(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_move_project_between_domains_with_clashing_names_fails(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_domain_delete_hierarchy(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_cache_layer_domain_crud(self):
        # TODO(morganfainberg): This also needs to be removed when full LDAP
        # implementation is submitted.  No need to duplicate the above test,
        # just skip this time.
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_domain_crud(self):
        self.skip_test_overrides('N/A: Not relevant for multi ldap testing')

    def test_delete_domain_call_db_time(self):
        self.skip_test_overrides('Domains are read-only against LDAP')

    def test_create_project_with_parent_id_and_without_domain_id(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_create_domain_under_regular_project_hierarchy_fails(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_create_project_passing_is_domain_flag_true(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_check_leaf_projects(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_list_projects_in_subtree(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_list_projects_in_subtree_with_circular_reference(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_list_project_parents(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_update_project_enabled_cascade(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_cannot_enable_cascade_with_parent_disabled(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_hierarchical_projects_crud(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_create_project_under_disabled_one(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_create_project_with_invalid_parent(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_update_project_parent(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_enable_project_with_disabled_parent(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_disable_hierarchical_leaf_project(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_disable_hierarchical_not_leaf_project(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_delete_hierarchical_leaf_project(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_delete_hierarchical_not_leaf_project(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_check_hierarchy_depth(self):
        self.skip_test_overrides('Resource LDAP has been removed')

    def test_list_projects_for_alternate_domain(self):
        self.skip_test_overrides('N/A: LDAP does not support multiple domains')


class LDAPTestSetup(object):
    """Common setup for LDAP tests."""

    def setUp(self):
        super(LDAPTestSetup, self).setUp()
        self.ldapdb = self.useFixture(ldapdb.LDAPDatabase())
        self.useFixture(database.Database())

        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.assert_backends()


class BaseLDAPIdentity(LDAPTestSetup, IdentityTests, AssignmentTests,
                       ResourceTests):

    def _get_domain_fixture(self):
        """Return the static domain, since domains in LDAP are read-only."""
        return PROVIDERS.resource_api.get_domain(
            CONF.identity.default_domain_id
        )

    def get_config(self, domain_id):
        # Only one conf structure unless we are using separate domain backends
        return CONF

    def config_overrides(self):
        super(BaseLDAPIdentity, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(BaseLDAPIdentity, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def new_user_ref(self, domain_id, project_id=None, **kwargs):
        ref = unit.new_user_ref(domain_id=domain_id, project_id=project_id,
                                **kwargs)
        if 'id' not in kwargs:
            del ref['id']
        return ref

    def get_user_enabled_vals(self, user):
        user_dn = (
            PROVIDERS.identity_api.driver.user._id_to_dn_string(user['id']))
        enabled_attr_name = CONF.ldap.user_enabled_attribute

        ldap_ = PROVIDERS.identity_api.driver.user.get_connection()
        res = ldap_.search_s(user_dn,
                             ldap.SCOPE_BASE,
                             u'(sn=%s)' % user['name'])
        if enabled_attr_name in res[0][1]:
            return res[0][1][enabled_attr_name]
        else:
            return None

    def test_build_tree(self):
        """Regression test for building the tree names."""
        user_api = identity.backends.ldap.UserApi(CONF)
        self.assertTrue(user_api)
        self.assertEqual("ou=Users,%s" % CONF.ldap.suffix, user_api.tree_dn)

    def test_configurable_allowed_user_actions(self):
        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        PROVIDERS.identity_api.get_user(user['id'])

        user['password'] = u'fäképass2'
        PROVIDERS.identity_api.update_user(user['id'], user)

        self.assertRaises(exception.Forbidden,
                          PROVIDERS.identity_api.delete_user,
                          user['id'])

    def test_user_filter(self):
        user_ref = PROVIDERS.identity_api.get_user(self.user_foo['id'])
        self.user_foo.pop('password')
        self.assertDictEqual(self.user_foo, user_ref)

        driver = PROVIDERS.identity_api._select_identity_driver(
            user_ref['domain_id'])
        driver.user.ldap_filter = '(CN=DOES_NOT_MATCH)'
        # invalidate the cache if the result is cached.
        PROVIDERS.identity_api.get_user.invalidate(
            PROVIDERS.identity_api, self.user_foo['id']
        )
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user,
                          self.user_foo['id'])

    def test_list_users_by_name_and_with_filter(self):
        # confirm that the user is not exposed when it does not match the
        # filter setting in conf even if it is requested by name in user list
        hints = driver_hints.Hints()
        hints.add_filter('name', self.user_foo['name'])
        domain_id = self.user_foo['domain_id']
        driver = PROVIDERS.identity_api._select_identity_driver(domain_id)
        driver.user.ldap_filter = ('(|(cn=%s)(cn=%s))' %
                                   (self.user_sna['id'], self.user_two['id']))
        users = PROVIDERS.identity_api.list_users(
            domain_scope=self._set_domain_scope(domain_id),
            hints=hints)
        self.assertEqual(0, len(users))

    def test_list_groups_by_name_and_with_filter(self):
        # Create some test groups.
        domain = self._get_domain_fixture()
        group_names = []
        numgroups = 3
        for _ in range(numgroups):
            group = unit.new_group_ref(domain_id=domain['id'])
            group = PROVIDERS.identity_api.create_group(group)
            group_names.append(group['name'])
        # confirm that the groups can all be listed
        groups = PROVIDERS.identity_api.list_groups(
            domain_scope=self._set_domain_scope(domain['id']))
        self.assertEqual(numgroups, len(groups))
        # configure the group filter
        driver = PROVIDERS.identity_api._select_identity_driver(domain['id'])
        driver.group.ldap_filter = ('(|(ou=%s)(ou=%s))' %
                                    tuple(group_names[:2]))
        # confirm that the group filter is working
        groups = PROVIDERS.identity_api.list_groups(
            domain_scope=self._set_domain_scope(domain['id']))
        self.assertEqual(2, len(groups))
        # confirm that a group is not exposed when it does not match the
        # filter setting in conf even if it is requested by name in group list
        hints = driver_hints.Hints()
        hints.add_filter('name', group_names[2])
        groups = PROVIDERS.identity_api.list_groups(
            domain_scope=self._set_domain_scope(domain['id']),
            hints=hints)
        self.assertEqual(0, len(groups))

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

    def test_get_and_remove_role_grant_by_group_and_project(self):
        new_domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_user = self.new_user_ref(domain_id=new_domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )

        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.project_bar['id'])
        self.assertEqual([], roles_ref)
        self.assertEqual(0, len(roles_ref))

        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'],
            project_id=self.project_bar['id'],
            role_id=default_fixtures.MEMBER_ROLE_ID)
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.project_bar['id'])
        self.assertNotEmpty(roles_ref)
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
        # TODO(henry-nash): We should really rewrite the tests in
        # unit.resource.test_backends to be more flexible as to where the
        # domains are sourced from, so that we would not need to override such
        # tests here. This is raised as bug 1373865.
        new_domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=new_domain['id'],)
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_user = self.new_user_ref(domain_id=new_domain['id'])
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
        self.assertRaises(exception.NotFound,
                          PROVIDERS.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id=default_fixtures.MEMBER_ROLE_ID)

    def test_list_projects_for_user(self):
        domain = self._get_domain_fixture()
        user1 = self.new_user_ref(domain_id=domain['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user1['id']
        )
        self.assertThat(user_projects, matchers.HasLength(0))

        # new grant(user1, role_member, project_bar)
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        # new grant(user1, role_member, project_baz)
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_baz['id'],
            role_id=self.role_member['id']
        )
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user1['id']
        )
        self.assertThat(user_projects, matchers.HasLength(2))

        # Now, check number of projects through groups
        user2 = self.new_user_ref(domain_id=domain['id'])
        user2 = PROVIDERS.identity_api.create_user(user2)

        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)

        PROVIDERS.identity_api.add_user_to_group(user2['id'], group1['id'])

        # new grant(group1(user2), role_member, project_bar)
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        # new grant(group1(user2), role_member, project_baz)
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=self.project_baz['id'],
            role_id=self.role_member['id']
        )
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user2['id']
        )
        self.assertThat(user_projects, matchers.HasLength(2))

        # new grant(group1(user2), role_other, project_bar)
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=self.project_bar['id'],
            role_id=self.role_other['id']
        )
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user2['id']
        )
        self.assertThat(user_projects, matchers.HasLength(2))

    def test_list_projects_for_user_and_groups(self):
        domain = self._get_domain_fixture()
        # Create user1
        user1 = self.new_user_ref(domain_id=domain['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)

        # Create new group for user1
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)

        # Add user1 to group1
        PROVIDERS.identity_api.add_user_to_group(user1['id'], group1['id'])

        # Now, add grant to user1 and group1 in project_bar
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )

        # The result is user1 has only one project granted
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user1['id']
        )
        self.assertThat(user_projects, matchers.HasLength(1))

        # Now, delete user1 grant into project_bar and check
        PROVIDERS.assignment_api.delete_grant(
            user_id=user1['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )

        # The result is user1 has only one project granted.
        # Granted through group1.
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user1['id']
        )
        self.assertThat(user_projects, matchers.HasLength(1))

    def test_list_projects_for_user_with_grants(self):
        domain = self._get_domain_fixture()
        new_user = self.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)

        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)

        project1 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        project2 = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)

        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], group2['id']
        )

        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'], project_id=self.project_bar['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'], project_id=project1['id'],
            role_id=self.role_admin['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], project_id=project2['id'],
            role_id=self.role_admin['id']
        )

        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            new_user['id'])
        self.assertEqual(3, len(user_projects))

    def test_list_role_assignments_unfiltered(self):
        new_domain = self._get_domain_fixture()
        new_user = self.new_user_ref(domain_id=new_domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_project = unit.new_project_ref(domain_id=new_domain['id'])
        PROVIDERS.resource_api.create_project(new_project['id'], new_project)

        # First check how many role grant already exist
        existing_assignments = len(
            PROVIDERS.assignment_api.list_role_assignments()
        )

        PROVIDERS.assignment_api.create_grant(
            user_id=new_user['id'],
            project_id=new_project['id'],
            role_id=default_fixtures.OTHER_ROLE_ID)
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'],
            project_id=new_project['id'],
            role_id=default_fixtures.ADMIN_ROLE_ID)

        # Read back the list of assignments - check it is gone up by 2
        after_assignments = len(
            PROVIDERS.assignment_api.list_role_assignments()
        )
        self.assertEqual(existing_assignments + 2, after_assignments)

    def test_list_group_members_when_no_members(self):
        # List group members when there is no member in the group.
        # No exception should be raised.
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        # If this doesn't raise, then the test is successful.
        PROVIDERS.identity_api.list_users_in_group(group['id'])

    def test_list_domains(self):
        # We have more domains here than the parent class, check for the
        # correct number of domains for the multildap backend configs
        domain1 = unit.new_domain_ref()
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        domains = PROVIDERS.resource_api.list_domains()
        self.assertEqual(7, len(domains))
        domain_ids = []
        for domain in domains:
            domain_ids.append(domain.get('id'))
        self.assertIn(CONF.identity.default_domain_id, domain_ids)
        self.assertIn(domain1['id'], domain_ids)
        self.assertIn(domain2['id'], domain_ids)

    def test_authenticate_requires_simple_bind(self):
        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'], self.project_baz['id'], role_member['id']
        )
        driver = PROVIDERS.identity_api._select_identity_driver(
            user['domain_id'])
        driver.user.LDAP_USER = None
        driver.user.LDAP_PASSWORD = None

        with self.make_request():
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password=None)

    @mock.patch.object(versionutils, 'report_deprecated_feature')
    def test_user_crud(self, mock_deprecator):
        # NOTE(stevemar): As of the Mitaka release, we now check for calls that
        # the LDAP write functionality has been deprecated.
        user_dict = self.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user_dict)
        args, _kwargs = mock_deprecator.call_args
        self.assertIn("create_user for the LDAP identity backend", args[1])

        del user_dict['password']
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertLessEqual(user_dict.items(), user_ref_dict.items())

        user_dict['password'] = uuid.uuid4().hex
        PROVIDERS.identity_api.update_user(user['id'], user_dict)
        args, _kwargs = mock_deprecator.call_args
        self.assertIn("update_user for the LDAP identity backend", args[1])

        del user_dict['password']
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertLessEqual(user_dict.items(), user_ref_dict.items())

    # The group and domain CRUD tests below override the standard ones in
    # unit.identity.test_backends.py so that we can exclude the update name
    # test, since we do not (and will not) support the update of either group
    # or domain names with LDAP. In the tests below, the update is tested by
    # updating description.
    @mock.patch.object(versionutils, 'report_deprecated_feature')
    def test_group_crud(self, mock_deprecator):
        # NOTE(stevemar): As of the Mitaka release, we now check for calls that
        # the LDAP write functionality has been deprecated.
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        args, _kwargs = mock_deprecator.call_args
        self.assertIn("create_group for the LDAP identity backend", args[1])

        group_ref = PROVIDERS.identity_api.get_group(group['id'])
        self.assertDictEqual(group, group_ref)
        group['description'] = uuid.uuid4().hex
        PROVIDERS.identity_api.update_group(group['id'], group)
        args, _kwargs = mock_deprecator.call_args
        self.assertIn("update_group for the LDAP identity backend", args[1])

        group_ref = PROVIDERS.identity_api.get_group(group['id'])
        self.assertDictEqual(group, group_ref)

    @mock.patch.object(versionutils, 'report_deprecated_feature')
    def test_add_user_group_deprecated(self, mock_deprecator):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])
        args, _kwargs = mock_deprecator.call_args
        self.assertIn("add_user_to_group for the LDAP identity", args[1])

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_group_crud(self):
        # Note(knikolla): Since delete logic has been deleted from LDAP,
        # this doesn't test caching on delete.
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        # cache the result
        PROVIDERS.identity_api.get_group(group['id'])
        group['description'] = uuid.uuid4().hex
        group_ref = PROVIDERS.identity_api.update_group(group['id'], group)
        self.assertLessEqual(
            PROVIDERS.identity_api.get_group(group['id']).items(),
            group_ref.items()
        )

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user(self):
        # Note(knikolla): Since delete logic has been deleted from LDAP,
        # this doesn't test caching on delete.
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        ref = PROVIDERS.identity_api.get_user_by_name(
            user['name'], user['domain_id']
        )
        user['description'] = uuid.uuid4().hex
        # cache the result.
        PROVIDERS.identity_api.get_user(ref['id'])
        # update using identity api and get back updated user.
        user_updated = PROVIDERS.identity_api.update_user(ref['id'], user)
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user(ref['id']).items(),
            user_updated.items()
        )
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user_by_name(
                ref['name'], ref['domain_id']
            ).items(),
            user_updated.items()
        )

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user_by_name(self):
        # Note(knikolla): Since delete logic has been deleted from LDAP,
        # this doesn't test caching on delete.
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        ref = PROVIDERS.identity_api.get_user_by_name(
            user['name'], user['domain_id']
        )
        user['description'] = uuid.uuid4().hex
        user_updated = PROVIDERS.identity_api.update_user(ref['id'], user)
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user(ref['id']).items(),
            user_updated.items()
        )
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user_by_name(
                ref['name'], ref['domain_id']
            ).items(),
            user_updated.items()
        )

    def test_create_user_none_mapping(self):
        # When create a user where an attribute maps to None, the entry is
        # created without that attribute and it doesn't fail with a TypeError.
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.attribute_ignore = ['enabled', 'email',
                                        'projects', 'projectId']
        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 project_id='maps_to_none')

        # If this doesn't raise, then the test is successful.
        user = PROVIDERS.identity_api.create_user(user)

    def test_unignored_user_none_mapping(self):
        # Ensure that an attribute that maps to None that is not explicitly
        # ignored in configuration is implicitly ignored without triggering
        # an error.
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.attribute_ignore = ['enabled', 'email',
                                        'projects', 'projectId']

        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user_ref = PROVIDERS.identity_api.create_user(user)

        # If this doesn't raise, then the test is successful.
        PROVIDERS.identity_api.get_user(user_ref['id'])

    def test_update_user_name(self):
        """A user's name cannot be changed through the LDAP driver."""
        self.assertRaises(exception.Conflict,
                          super(BaseLDAPIdentity, self).test_update_user_name)

    def test_user_id_comma(self):
        """Even if the user has a , in their ID, groups can be listed."""
        # Create a user with a , in their ID
        # NOTE(blk-u): the DN for this user is hard-coded in fakeldap!

        # Since we want to fake up this special ID, we'll squirt this
        # direct into the driver and bypass the manager layer.
        user_id = u'Doe, John'
        user = self.new_user_ref(id=user_id,
                                 domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.driver.create_user(user_id, user)

        # Now we'll use the manager to discover it, which will create a
        # Public ID for it.
        ref_list = PROVIDERS.identity_api.list_users()
        public_user_id = None
        for ref in ref_list:
            if ref['name'] == user['name']:
                public_user_id = ref['id']
                break

        # Create a group
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_id = group['id']
        group = PROVIDERS.identity_api.driver.create_group(group_id, group)
        # Now we'll use the manager to discover it, which will create a
        # Public ID for it.
        ref_list = PROVIDERS.identity_api.list_groups()
        public_group_id = None
        for ref in ref_list:
            if ref['name'] == group['name']:
                public_group_id = ref['id']
                break

        # Put the user in the group
        PROVIDERS.identity_api.add_user_to_group(
            public_user_id, public_group_id
        )

        # List groups for user.
        ref_list = PROVIDERS.identity_api.list_groups_for_user(public_user_id)
        for ref in ref_list:
            del(ref['membership_expires_at'])

        group['id'] = public_group_id
        self.assertThat(ref_list, matchers.Equals([group]))

    def test_user_id_comma_grants(self):
        """List user and group grants, even with a comma in the user's ID."""
        # Create a user with a , in their ID
        # NOTE(blk-u): the DN for this user is hard-coded in fakeldap!

        # Since we want to fake up this special ID, we'll squirt this
        # direct into the driver and bypass the manager layer
        user_id = u'Doe, John'
        user = self.new_user_ref(id=user_id,
                                 domain_id=CONF.identity.default_domain_id)
        PROVIDERS.identity_api.driver.create_user(user_id, user)

        # Now we'll use the manager to discover it, which will create a
        # Public ID for it.
        ref_list = PROVIDERS.identity_api.list_users()
        public_user_id = None
        for ref in ref_list:
            if ref['name'] == user['name']:
                public_user_id = ref['id']
                break

        # Grant the user a role on a project.

        role_id = default_fixtures.MEMBER_ROLE_ID
        project_id = self.project_baz['id']

        PROVIDERS.assignment_api.create_grant(
            role_id, user_id=public_user_id, project_id=project_id
        )

        role_ref = PROVIDERS.assignment_api.get_grant(
            role_id, user_id=public_user_id, project_id=project_id
        )

        self.assertEqual(role_id, role_ref['id'])

    def test_user_enabled_ignored_disable_error(self):
        # When the server is configured so that the enabled attribute is
        # ignored for users, users cannot be disabled.

        self.config_fixture.config(group='ldap',
                                   user_attribute_ignore=['enabled'])

        # Need to re-load backends for the config change to take effect.
        self.load_backends()

        # Attempt to disable the user.
        self.assertRaises(
            exception.ForbiddenAction,
            PROVIDERS.identity_api.update_user, self.user_foo['id'],
            {'enabled': False}
        )

        user_info = PROVIDERS.identity_api.get_user(self.user_foo['id'])

        # If 'enabled' is ignored then 'enabled' isn't returned as part of the
        # ref.
        self.assertNotIn('enabled', user_info)

    def test_group_enabled_ignored_disable_error(self):
        # When the server is configured so that the enabled attribute is
        # ignored for groups, groups cannot be disabled.

        self.config_fixture.config(group='ldap',
                                   group_attribute_ignore=['enabled'])

        # Need to re-load backends for the config change to take effect.
        self.load_backends()

        # There's no group fixture so create a group.
        new_domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=new_domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)

        # Attempt to disable the group.
        self.assertRaises(exception.ForbiddenAction,
                          PROVIDERS.identity_api.update_group, new_group['id'],
                          {'enabled': False})

        group_info = PROVIDERS.identity_api.get_group(new_group['id'])

        # If 'enabled' is ignored then 'enabled' isn't returned as part of the
        # ref.
        self.assertNotIn('enabled', group_info)

    def test_list_role_assignment_by_domain(self):
        """Multiple domain assignments are not supported."""
        self.assertRaises(
            (exception.Forbidden, exception.DomainNotFound,
             exception.ValidationError),
            super(BaseLDAPIdentity, self).test_list_role_assignment_by_domain)

    def test_list_role_assignment_by_user_with_domain_group_roles(self):
        """Multiple domain assignments are not supported."""
        self.assertRaises(
            (exception.Forbidden, exception.DomainNotFound,
             exception.ValidationError),
            super(BaseLDAPIdentity, self).
            test_list_role_assignment_by_user_with_domain_group_roles)

    def test_list_role_assignment_using_sourced_groups_with_domains(self):
        """Multiple domain assignments are not supported."""
        self.assertRaises(
            (exception.Forbidden, exception.ValidationError,
             exception.DomainNotFound),
            super(BaseLDAPIdentity, self).
            test_list_role_assignment_using_sourced_groups_with_domains)

    def test_create_project_with_domain_id_and_without_parent_id(self):
        """Multiple domains are not supported."""
        self.assertRaises(
            exception.ValidationError,
            super(BaseLDAPIdentity, self).
            test_create_project_with_domain_id_and_without_parent_id)

    def test_create_project_with_domain_id_mismatch_to_parent_domain(self):
        """Multiple domains are not supported."""
        self.assertRaises(
            exception.ValidationError,
            super(BaseLDAPIdentity, self).
            test_create_project_with_domain_id_mismatch_to_parent_domain)

    def test_remove_foreign_assignments_when_deleting_a_domain(self):
        """Multiple domains are not supported."""
        self.assertRaises(
            (exception.ValidationError, exception.DomainNotFound),
            super(BaseLDAPIdentity,
                  self).test_remove_foreign_assignments_when_deleting_a_domain)


class LDAPIdentity(BaseLDAPIdentity):

    def assert_backends(self):
        _assert_backends(self,
                         assignment='sql',
                         identity='ldap',
                         resource='sql')

    def test_list_domains(self):
        domains = PROVIDERS.resource_api.list_domains()
        default_domain = unit.new_domain_ref(
            description=u'The default domain',
            id=CONF.identity.default_domain_id,
            name=u'Default')
        self.assertEqual([default_domain], domains)

    def test_authenticate_wrong_credentials(self):
        self.assertRaises(exception.LDAPInvalidCredentialsError,
                          PROVIDERS.identity_api.driver.user.get_connection,
                          user='demo',
                          password='demo',
                          end_user_auth=True)

    def test_configurable_allowed_project_actions(self):
        domain = self._get_domain_fixture()
        project = unit.new_project_ref(domain_id=domain['id'])
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertEqual(project['id'], project_ref['id'])

        project['enabled'] = False
        PROVIDERS.resource_api.update_project(project['id'], project)

        PROVIDERS.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project['id'])

    def test_user_enable_attribute_mask(self):
        self.config_fixture.config(group='ldap', user_enabled_mask=2,
                                   user_enabled_default='512')
        self.ldapdb.clear()
        self.load_backends()

        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user_ref = PROVIDERS.identity_api.create_user(user)

        # Use assertIs rather than assertTrue because assertIs will assert the
        # value is a Boolean as expected.
        self.assertIs(True, user_ref['enabled'])
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([512], enabled_vals)

        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])
        self.assertNotIn('enabled_nomask', user_ref)

        user['enabled'] = False
        user_ref = PROVIDERS.identity_api.update_user(user_ref['id'], user)
        self.assertIs(False, user_ref['enabled'])
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([514], enabled_vals)

        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(False, user_ref['enabled'])
        self.assertNotIn('enabled_nomask', user_ref)

        user['enabled'] = True
        user_ref = PROVIDERS.identity_api.update_user(user_ref['id'], user)
        self.assertIs(True, user_ref['enabled'])
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([512], enabled_vals)

        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])
        self.assertNotIn('enabled_nomask', user_ref)

    def test_user_enabled_invert(self):
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_default='False')
        self.ldapdb.clear()
        self.load_backends()

        user1 = self.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user2 = self.new_user_ref(enabled=False,
                                  domain_id=CONF.identity.default_domain_id)

        user3 = self.new_user_ref(domain_id=CONF.identity.default_domain_id)

        # Ensure that the LDAP attribute is False for a newly created
        # enabled user.
        user_ref = PROVIDERS.identity_api.create_user(user1)
        self.assertIs(True, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([False], enabled_vals)
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

        # Ensure that the LDAP attribute is True for a disabled user.
        user1['enabled'] = False
        user_ref = PROVIDERS.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(False, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([True], enabled_vals)

        # Enable the user and ensure that the LDAP attribute is True again.
        user1['enabled'] = True
        user_ref = PROVIDERS.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(True, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([False], enabled_vals)

        # Ensure that the LDAP attribute is True for a newly created
        # disabled user.
        user_ref = PROVIDERS.identity_api.create_user(user2)
        self.assertIs(False, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([True], enabled_vals)
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(False, user_ref['enabled'])

        # Ensure that the LDAP attribute is inverted for a newly created
        # user when the user_enabled_default setting is used.
        user_ref = PROVIDERS.identity_api.create_user(user3)
        self.assertIs(True, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([False], enabled_vals)
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_user_enabled_invert_default_str_value(self, mock_ldap_get):
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_default='False')
        # Mock the search results to return an entry with
        # no enabled value.
        mock_ldap_get.return_value = (
            'cn=junk,dc=example,dc=com',
            {
                'sn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
                'cn': ['junk']
            }
        )

        user_api = identity.backends.ldap.UserApi(CONF)
        user_ref = user_api.get('junk')
        # Ensure that the model enabled attribute is inverted
        # from the resource default.
        self.assertIs(True, user_ref['enabled'])

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'connect')
    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'search_s')
    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    def test_filter_ldap_result_by_attr(self, mock_simple_bind_s,
                                        mock_search_s, mock_connect):

        # Mock the ldap search results to return user entries with
        # user_name_attribute('sn') value has emptyspaces, emptystring
        # and attibute itself is not set.
        mock_search_s.return_value = [(
            'sn=junk1,dc=example,dc=com',
            {
                'cn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
                'sn': ['junk1']
            }
        ),
            (
            '',
            {
                'cn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
            }
        ),
            (
            'sn=,dc=example,dc=com',
            {
                'cn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
                'sn': ['']
            }
        ),
            (
            'sn=   ,dc=example,dc=com',
            {
                'cn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
                'sn': ['   ']
            }
        )]

        user_api = identity.backends.ldap.UserApi(CONF)
        user_refs = user_api.get_all()
        # validate that keystone.identity.backends.ldap.common.BaseLdap.
        # _filter_ldap_result_by_attr() method filtered the ldap query results
        # whose name attribute values has emptyspaces, emptystring
        # and attibute itself is not set.
        self.assertEqual(1, len(user_refs))

        self.assertEqual('junk1', user_refs[0]['name'])
        self.assertEqual('sn=junk1,dc=example,dc=com', user_refs[0]['dn'])

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'connect')
    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'search_s')
    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    def test_filter_ldap_result_with_case_sensitive_attr(self,
                                                         mock_simple_bind_s,
                                                         mock_search_s,
                                                         mock_connect):
        # Mock the ldap search results to return user entries
        # irrespective of lowercase and uppercase characters in
        # ldap_result attribute keys e.g. {'Sn': ['junk1']} with
        # user_name_attribute('sn')
        mock_search_s.return_value = [(
            'sn=junk1,dc=example,dc=com',
            {
                'cn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
                'sN': ['junk1']
            }
        ),
            (
            'sn=junk1,dc=example,dc=com',
            {
                'cn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
                'Sn': ['junk1']
            }
        ),
            (
            'sn=junk1,dc=example,dc=com',
            {
                'cn': [uuid.uuid4().hex],
                'email': [uuid.uuid4().hex],
                'sn': ['    ']
            }
        )
        ]

        user_api = identity.backends.ldap.UserApi(CONF)
        user_refs = user_api.get_all()
        # validate that keystone.identity.backends.ldap.common.BaseLdap.
        # _filter_ldap_result_by_attr() method filtered the ldap query results
        # whose name attribute keys having case insensitive characters.
        self.assertEqual(2, len(user_refs))

        self.assertEqual('junk1', user_refs[0]['name'])
        self.assertEqual('sn=junk1,dc=example,dc=com', user_refs[0]['dn'])

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_user_enabled_attribute_handles_expired(self, mock_ldap_get):
        # If using 'passwordisexpired' as enabled attribute, and inverting it,
        # Then an unauthorized user (expired password) should not be enabled.
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_attribute='passwordisexpired')
        mock_ldap_get.return_value = (
            u'uid=123456789,c=us,ou=our_ldap,o=acme.com',
            {
                'uid': [123456789],
                'mail': ['shaun@acme.com'],
                'passwordisexpired': ['TRUE'],
                'cn': ['uid=123456789,c=us,ou=our_ldap,o=acme.com']
            }
        )

        user_api = identity.backends.ldap.UserApi(CONF)
        user_ref = user_api.get('123456789')
        self.assertIs(False, user_ref['enabled'])

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_user_enabled_attribute_handles_utf8(self, mock_ldap_get):
        # If using 'passwordisexpired' as enabled attribute, and inverting it,
        # and the result is utf8 encoded, then the an authorized user should
        # be enabled.
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_attribute='passwordisexpired')
        mock_ldap_get.return_value = (
            u'uid=123456789,c=us,ou=our_ldap,o=acme.com',
            {
                'uid': [123456789],
                'mail': [u'shaun@acme.com'],
                'passwordisexpired': [u'false'],
                'cn': [u'uid=123456789,c=us,ou=our_ldap,o=acme.com']
            }
        )

        user_api = identity.backends.ldap.UserApi(CONF)
        user_ref = user_api.get('123456789')
        self.assertIs(True, user_ref['enabled'])

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'simple_bind_s')
    def test_user_api_get_connection_no_user_password(self, mocked_method):
        """Bind anonymously when the user and password are blank."""
        # Ensure the username/password are in-fact blank
        self.config_fixture.config(group='ldap', user=None, password=None)
        user_api = identity.backends.ldap.UserApi(CONF)
        user_api.get_connection(user=None, password=None)
        self.assertTrue(mocked_method.called)

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'connect')
    def test_chase_referrals_off(self, mocked_fakeldap):
        self.config_fixture.config(
            group='ldap',
            url='fake://memory',
            chase_referrals=False)
        user_api = identity.backends.ldap.UserApi(CONF)
        user_api.get_connection(user=None, password=None)

        # The last call_arg should be a dictionary and should contain
        # chase_referrals. Check to make sure the value of chase_referrals
        # is as expected.
        self.assertFalse(mocked_fakeldap.call_args[-1]['chase_referrals'])

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'connect')
    def test_chase_referrals_on(self, mocked_fakeldap):
        self.config_fixture.config(
            group='ldap',
            url='fake://memory',
            chase_referrals=True)
        user_api = identity.backends.ldap.UserApi(CONF)
        user_api.get_connection(user=None, password=None)

        # The last call_arg should be a dictionary and should contain
        # chase_referrals. Check to make sure the value of chase_referrals
        # is as expected.
        self.assertTrue(mocked_fakeldap.call_args[-1]['chase_referrals'])

    @mock.patch.object(common_ldap.KeystoneLDAPHandler, 'connect')
    def test_debug_level_set(self, mocked_fakeldap):
        level = 12345
        self.config_fixture.config(
            group='ldap',
            url='fake://memory',
            debug_level=level)
        user_api = identity.backends.ldap.UserApi(CONF)
        user_api.get_connection(user=None, password=None)

        # The last call_arg should be a dictionary and should contain
        # debug_level. Check to make sure the value of debug_level
        # is as expected.
        self.assertEqual(level, mocked_fakeldap.call_args[-1]['debug_level'])

    def test_user_extra_attribute_mapping(self):
        self.config_fixture.config(
            group='ldap',
            user_additional_attribute_mapping=['description:name'])
        self.load_backends()
        user = self.new_user_ref(name='EXTRA_ATTRIBUTES',
                                 password='extra',
                                 domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        dn, attrs = PROVIDERS.identity_api.driver.user._ldap_get(user['id'])
        self.assertThat([user['name']], matchers.Equals(attrs['description']))

    def test_user_description_attribute_mapping(self):
        self.config_fixture.config(
            group='ldap',
            user_description_attribute='displayName')
        self.load_backends()

        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 displayName=uuid.uuid4().hex)
        description = user['displayName']
        user = PROVIDERS.identity_api.create_user(user)
        res = PROVIDERS.identity_api.driver.user.get_all()

        new_user = [u for u in res if u['id'] == user['id']][0]
        self.assertThat(new_user['description'], matchers.Equals(description))

    def test_user_extra_attribute_mapping_description_is_returned(self):
        # Given a mapping like description:description, the description is
        # returned.

        self.config_fixture.config(
            group='ldap',
            user_additional_attribute_mapping=['description:description'])
        self.load_backends()

        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 description=uuid.uuid4().hex)
        description = user['description']
        user = PROVIDERS.identity_api.create_user(user)
        res = PROVIDERS.identity_api.driver.user.get_all()

        new_user = [u for u in res if u['id'] == user['id']][0]
        self.assertThat(new_user['description'], matchers.Equals(description))

    def test_user_with_missing_id(self):
        # create a user that doesn't have the id attribute
        ldap_ = PROVIDERS.identity_api.driver.user.get_connection()
        # `sn` is used for the attribute in the DN because it's allowed by
        # the entry's objectclasses so that this test could conceivably run in
        # the live tests.
        ldap_id_field = 'sn'
        ldap_id_value = uuid.uuid4().hex
        dn = '%s=%s,ou=Users,cn=example,cn=com' % (ldap_id_field,
                                                   ldap_id_value)
        modlist = [('objectClass', ['person', 'inetOrgPerson']),
                   (ldap_id_field, [ldap_id_value]),
                   ('mail', ['email@example.com']),
                   ('userPassword', [uuid.uuid4().hex])]
        ldap_.add_s(dn, modlist)

        # make sure the user doesn't break other users
        users = PROVIDERS.identity_api.driver.user.get_all()
        self.assertThat(users, matchers.HasLength(len(default_fixtures.USERS)))

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_user_mixed_case_attribute(self, mock_ldap_get):
        # Mock the search results to return attribute names
        # with unexpected case.
        mock_ldap_get.return_value = (
            'cn=junk,dc=example,dc=com',
            {
                'sN': [uuid.uuid4().hex],
                'MaIl': [uuid.uuid4().hex],
                'cn': ['junk']
            }
        )
        user = PROVIDERS.identity_api.get_user('junk')
        self.assertEqual(mock_ldap_get.return_value[1]['sN'][0],
                         user['name'])
        self.assertEqual(mock_ldap_get.return_value[1]['MaIl'][0],
                         user['email'])

    def test_parse_extra_attribute_mapping(self):
        option_list = ['description:name', 'gecos:password',
                       'fake:invalid', 'invalid1', 'invalid2:',
                       'description:name:something']
        mapping = PROVIDERS.identity_api.driver.user._parse_extra_attrs(
            option_list
        )
        expected_dict = {'description': 'name', 'gecos': 'password',
                         'fake': 'invalid', 'invalid2': ''}
        self.assertDictEqual(expected_dict, mapping)

    def test_create_domain(self):
        domain = unit.new_domain_ref()
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.create_domain,
                          domain['id'],
                          domain)

    @unit.skip_if_no_multiple_domains_support
    def test_create_domain_case_sensitivity(self):
        # domains are read-only, so case sensitivity isn't an issue
        ref = unit.new_domain_ref()
        self.assertRaises(exception.Forbidden,
                          PROVIDERS.resource_api.create_domain,
                          ref['id'],
                          ref)

    def test_domain_rename_invalidates_get_domain_by_name_cache(self):
        parent = super(LDAPIdentity, self)
        self.assertRaises(
            exception.Forbidden,
            parent.test_domain_rename_invalidates_get_domain_by_name_cache)

    def test_project_rename_invalidates_get_project_by_name_cache(self):
        parent = super(LDAPIdentity, self)
        self.assertRaises(
            exception.Forbidden,
            parent.test_project_rename_invalidates_get_project_by_name_cache)

    def test_project_crud(self):
        # NOTE(topol): LDAP implementation does not currently support the
        #              updating of a project name so this method override
        #              provides a different update test
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)

        project = PROVIDERS.resource_api.create_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])

        self.assertDictEqual(project, project_ref)

        project['description'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(project, project_ref)

        PROVIDERS.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project['id'])

    @unit.skip_if_cache_disabled('assignment')
    def test_cache_layer_project_crud(self):
        # NOTE(morganfainberg): LDAP implementation does not currently support
        # updating project names.  This method override provides a different
        # update test.
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project_id = project['id']
        # Create a project
        project = PROVIDERS.resource_api.create_project(project_id, project)
        PROVIDERS.resource_api.get_project(project_id)
        updated_project = copy.deepcopy(project)
        updated_project['description'] = uuid.uuid4().hex
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
        # Delete project bypassing resource_api
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

    def test_update_is_domain_field(self):
        domain = self._get_domain_fixture()
        project = unit.new_project_ref(domain_id=domain['id'])
        project = PROVIDERS.resource_api.create_project(project['id'], project)

        # Try to update the is_domain field to True
        project['is_domain'] = True
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.resource_api.update_project,
                          project['id'], project)

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        # This is a partial implementation of the standard test that
        # is defined in unit.assignment.test_backends.py.  It omits
        # both domain and group grants. since neither of these are
        # yet supported by the ldap backend.

        role_list = []
        for _ in range(2):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        user1 = self.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user1 = PROVIDERS.identity_api.create_user(user1)
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project1['id'], project1)

        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user_id=user1['id'],
            project_id=project1['id'],
            role_id=role_list[0]['id'])
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user_id=user1['id'],
            project_id=project1['id'],
            role_id=role_list[1]['id'])

        # Although list_grants are not yet supported, we can test the
        # alternate way of getting back lists of grants, where user
        # and group roles are combined.  Only directly assigned user
        # roles are available, since group grants are not yet supported

        combined_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user1['id'], project1['id']
            )
        )
        self.assertEqual(2, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)
        self.assertIn(role_list[1]['id'], combined_list)

        # Finally, although domain roles are not implemented, check we can
        # issue the combined get roles call with benign results, since thus is
        # used in token generation

        combined_role_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_domain(
                user1['id'], CONF.identity.default_domain_id
            )
        )
        self.assertEqual(0, len(combined_role_list))

    def test_get_default_domain_by_name(self):
        domain = self._get_domain_fixture()

        domain_ref = PROVIDERS.resource_api.get_domain_by_name(domain['name'])
        self.assertEqual(domain_ref, domain)

    def test_base_ldap_connection_deref_option(self):
        def get_conn(deref_name):
            self.config_fixture.config(group='ldap',
                                       alias_dereferencing=deref_name)
            base_ldap = common_ldap.BaseLdap(CONF)
            return base_ldap.get_connection()

        conn = get_conn('default')
        self.assertEqual(ldap.get_option(ldap.OPT_DEREF),
                         conn.get_option(ldap.OPT_DEREF))

        conn = get_conn('always')
        self.assertEqual(ldap.DEREF_ALWAYS,
                         conn.get_option(ldap.OPT_DEREF))

        conn = get_conn('finding')
        self.assertEqual(ldap.DEREF_FINDING,
                         conn.get_option(ldap.OPT_DEREF))

        conn = get_conn('never')
        self.assertEqual(ldap.DEREF_NEVER,
                         conn.get_option(ldap.OPT_DEREF))

        conn = get_conn('searching')
        self.assertEqual(ldap.DEREF_SEARCHING,
                         conn.get_option(ldap.OPT_DEREF))

    def test_list_users_no_dn(self):
        users = PROVIDERS.identity_api.list_users()
        self.assertEqual(len(default_fixtures.USERS), len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['name'])['id']
                                for user in default_fixtures.USERS)
        for user_ref in users:
            self.assertNotIn('dn', user_ref)
        self.assertEqual(expected_user_ids, user_ids)

    def test_list_groups_no_dn(self):
        # Create some test groups.
        domain = self._get_domain_fixture()
        expected_group_ids = []
        numgroups = 3
        for _ in range(numgroups):
            group = unit.new_group_ref(domain_id=domain['id'])
            group = PROVIDERS.identity_api.create_group(group)
            expected_group_ids.append(group['id'])
        # Fetch the test groups and ensure that they don't contain a dn.
        groups = PROVIDERS.identity_api.list_groups()
        self.assertEqual(numgroups, len(groups))
        group_ids = set(group['id'] for group in groups)
        for group_ref in groups:
            self.assertNotIn('dn', group_ref)
        self.assertEqual(set(expected_group_ids), group_ids)

    def test_list_groups_for_user_no_dn(self):
        # Create a test user.
        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        # Create some test groups and add the test user as a member.
        domain = self._get_domain_fixture()
        expected_group_ids = []
        numgroups = 3
        for _ in range(numgroups):
            group = unit.new_group_ref(domain_id=domain['id'])
            group = PROVIDERS.identity_api.create_group(group)
            expected_group_ids.append(group['id'])
            PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])
        # Fetch the groups for the test user
        # and ensure they don't contain a dn.
        groups = PROVIDERS.identity_api.list_groups_for_user(user['id'])
        self.assertEqual(numgroups, len(groups))
        group_ids = set(group['id'] for group in groups)
        for group_ref in groups:
            self.assertNotIn('dn', group_ref)
        self.assertEqual(set(expected_group_ids), group_ids)

    def test_user_id_attribute_in_create(self):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'mail'

        user = self.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        # 'email' attribute should've created because it is also being used
        # as user_id
        self.assertEqual(user_ref['id'], user_ref['email'])

    def test_user_id_attribute_map(self):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'mail'

        user_ref = PROVIDERS.identity_api.get_user(self.user_foo['email'])
        # the user_id_attribute map should be honored, which means
        # user_ref['id'] should contains the email attribute
        self.assertEqual(self.user_foo['email'], user_ref['id'])

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_get_multivalued_attribute_id_from_dn(self,
                                                  mock_ldap_get):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'mail'

        # make 'email' multivalued so we can test the error condition
        email1 = uuid.uuid4().hex
        email2 = uuid.uuid4().hex
        # Mock the ldap search results to return user entries with
        # user_name_attribute('sn') value has emptyspaces, emptystring
        # and attibute itself is not set.
        mock_ldap_get.return_value = (
            'cn=users,dc=example,dc=com',
            {
                'mail': [email1, email2],
            }
        )

        # This is not a valid scenario, since we do not support multiple value
        # attribute id on DN.
        self.assertRaises(exception.NotFound,
                          PROVIDERS.identity_api.get_user, email1)

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_raise_not_found_dn_for_multivalued_attribute_id(self,
                                                             mock_ldap_get):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'mail'

        # make 'email' multivalued so we can test the error condition
        email1 = uuid.uuid4().hex
        email2 = uuid.uuid4().hex
        mock_ldap_get.return_value = (
            'cn=nobodycares,dc=example,dc=com',
            {
                'sn': [uuid.uuid4().hex],
                'mail': [email1, email2],
                'cn': 'nobodycares'
            }
        )

        # This is not a valid scenario, since we do not support multiple value
        # attribute id on DN.
        self.assertRaises(exception.NotFound,
                          PROVIDERS.identity_api.get_user, email1)

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_get_id_not_in_dn(self,
                              mock_ldap_get):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'sAMAccountName'

        user_id = uuid.uuid4().hex
        mock_ldap_get.return_value = (
            'cn=someuser,dc=example,dc=com',
            {
                'cn': 'someuser',
                'sn': [uuid.uuid4().hex],
                'sAMAccountName': [user_id],
            }
        )
        user_ref = PROVIDERS.identity_api.get_user(user_id)
        self.assertEqual(user_id, user_ref['id'])

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_id_attribute_not_found(self, mock_ldap_get):
        mock_ldap_get.return_value = (
            'cn=nobodycares,dc=example,dc=com',
            {
                'sn': [uuid.uuid4().hex],
            }
        )

        user_api = identity.backends.ldap.UserApi(CONF)
        self.assertRaises(exception.NotFound,
                          user_api.get,
                          'nobodycares')

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_user_id_not_in_dn(self, mock_ldap_get):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'uid'
        driver.user.attribute_mapping['name'] = 'cn'

        mock_ldap_get.return_value = (
            'foo=bar,dc=example,dc=com',
            {
                'sn': [uuid.uuid4().hex],
                'foo': ['bar'],
                'cn': ['junk'],
                'uid': ['crap']
            }
        )
        user_ref = PROVIDERS.identity_api.get_user('crap')
        self.assertEqual('crap', user_ref['id'])
        self.assertEqual('junk', user_ref['name'])

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_user_name_in_dn(self, mock_ldap_get):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'SAMAccountName'
        driver.user.attribute_mapping['name'] = 'cn'

        mock_ldap_get.return_value = (
            'cn=Foo Bar,dc=example,dc=com',
            {
                'sn': [uuid.uuid4().hex],
                'cn': ['Foo Bar'],
                'SAMAccountName': ['crap']
            }
        )
        user_ref = PROVIDERS.identity_api.get_user('crap')
        self.assertEqual('crap', user_ref['id'])
        self.assertEqual('Foo Bar', user_ref['name'])

    def test_identity_manager_catches_forbidden_when_deleting_a_project(self):
        # The identity API registers a callback that listens for notifications
        # that a project has been deleted. When it receives one, it uses the ID
        # and attempts to clear any users who have `default_project_id`
        # attributes associated to that project. Since the LDAP backend is
        # read-only, clearing the `default_project_id` requires a write which
        # isn't possible.
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        with mock.patch.object(
            ldap_identity.Identity, '_disallow_write'
        ) as mocked:
            mocked.side_effect = exception.Forbidden()
            PROVIDERS.resource_api.delete_project(project['id'])

        mocked.assert_called_once()


class LDAPLimitTests(unit.TestCase, identity_tests.LimitTests):
    def setUp(self):
        super(LDAPLimitTests, self).setUp()

        self.useFixture(ldapdb.LDAPDatabase())
        self.useFixture(database.Database())
        self.load_backends()
        self.load_fixtures(default_fixtures)
        identity_tests.LimitTests.setUp(self)
        _assert_backends(self,
                         assignment='sql',
                         identity='ldap',
                         resource='sql')

    def config_overrides(self):
        super(LDAPLimitTests, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='identity',
                                   list_limit=len(default_fixtures.USERS) - 1)

    def config_files(self):
        config_files = super(LDAPLimitTests, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files


class LDAPIdentityEnabledEmulation(LDAPIdentity, unit.TestCase):
    def setUp(self):
        super(LDAPIdentityEnabledEmulation, self).setUp()
        _assert_backends(self, identity='ldap')

    def load_fixtures(self, fixtures):
        # Override super impl since need to create group container.
        super(LDAPIdentity, self).load_fixtures(fixtures)
        for obj in [self.project_bar, self.project_baz, self.user_foo,
                    self.user_two, self.user_badguy]:
            obj.setdefault('enabled', True)

    def config_files(self):
        config_files = super(LDAPIdentityEnabledEmulation, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def config_overrides(self):
        super(LDAPIdentityEnabledEmulation, self).config_overrides()
        self.config_fixture.config(group='ldap',
                                   user_enabled_emulation=True)

    def test_project_crud(self):
        # NOTE(topol): LDAPIdentityEnabledEmulation will create an
        #              enabled key in the project dictionary so this
        #              method override handles this side-effect
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)

        project = PROVIDERS.resource_api.create_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])

        # PROVIDERS.resource_api.create_project adds an enabled
        # key with a value of True when LDAPIdentityEnabledEmulation
        # is used so we now add this expected key to the project dictionary
        project['enabled'] = True
        self.assertDictEqual(project, project_ref)

        project['description'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(project, project_ref)

        PROVIDERS.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project['id'])

    def test_user_auth_emulated(self):
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.enabled_emulation_dn = 'cn=test,dc=test'
        with self.make_request():
            PROVIDERS.identity_api.authenticate(
                user_id=self.user_foo['id'],
                password=self.user_foo['password'])

    def test_user_enable_attribute_mask(self):
        self.skip_test_overrides(
            "Enabled emulation conflicts with enabled mask")

    def test_user_enabled_use_group_config(self):
        # Establish enabled-emulation group name to later query its members
        group_name = 'enabled_users'
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        group_dn = 'cn=%s,%s' % (group_name, driver.group.tree_dn)

        self.config_fixture.config(
            group='ldap',
            user_enabled_emulation_use_group_config=True,
            user_enabled_emulation_dn=group_dn,
            group_name_attribute='cn',
            group_member_attribute='uniqueMember',
            group_objectclass='groupOfUniqueNames')
        self.ldapdb.clear()
        self.load_backends()

        # Create a user and ensure they are enabled.
        user1 = unit.new_user_ref(enabled=True,
                                  domain_id=CONF.identity.default_domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user1)
        self.assertIs(True, user_ref['enabled'])

        # Get a user and ensure they are enabled.
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

        # Ensure state matches the group config
        group_ref = PROVIDERS.identity_api.get_group_by_name(
            group_name, CONF.identity.default_domain_id)
        PROVIDERS.identity_api.check_user_in_group(
            user_ref['id'], group_ref['id'])

    def test_user_enabled_use_group_config_with_ids(self):
        # Establish enabled-emulation group name to later query its members
        group_name = 'enabled_users'
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        group_dn = 'cn=%s,%s' % (group_name, driver.group.tree_dn)

        self.config_fixture.config(
            group='ldap',
            user_enabled_emulation_use_group_config=True,
            user_enabled_emulation_dn=group_dn,
            group_name_attribute='cn',
            group_member_attribute='memberUid',
            group_members_are_ids=True,
            group_objectclass='posixGroup')
        self.ldapdb.clear()
        self.load_backends()

        # Create a user and ensure they are enabled.
        user1 = unit.new_user_ref(enabled=True,
                                  domain_id=CONF.identity.default_domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user1)
        self.assertIs(True, user_ref['enabled'])

        # Get a user and ensure they are enabled.
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

        # Ensure state matches the group config
        group_ref = PROVIDERS.identity_api.get_group_by_name(
            group_name, CONF.identity.default_domain_id)
        PROVIDERS.identity_api.check_user_in_group(
            user_ref['id'], group_ref['id'])

    def test_user_enabled_invert(self):
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_default='False')
        self.ldapdb.clear()
        self.load_backends()

        user1 = self.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user2 = self.new_user_ref(enabled=False,
                                  domain_id=CONF.identity.default_domain_id)

        user3 = self.new_user_ref(domain_id=CONF.identity.default_domain_id)

        # Ensure that the enabled LDAP attribute is not set for a
        # newly created enabled user.
        user_ref = PROVIDERS.identity_api.create_user(user1)
        self.assertIs(True, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

        # Ensure that an enabled LDAP attribute is not set for a disabled user.
        user1['enabled'] = False
        user_ref = PROVIDERS.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(False, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))

        # Enable the user and ensure that the LDAP enabled
        # attribute is not set.
        user1['enabled'] = True
        user_ref = PROVIDERS.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(True, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))

        # Ensure that the LDAP enabled attribute is not set for a
        # newly created disabled user.
        user_ref = PROVIDERS.identity_api.create_user(user2)
        self.assertIs(False, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(False, user_ref['enabled'])

        # Ensure that the LDAP enabled attribute is not set for a newly created
        # user when the user_enabled_default setting is used.
        user_ref = PROVIDERS.identity_api.create_user(user3)
        self.assertIs(True, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))
        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

    def test_user_enabled_invert_default_str_value(self):
        self.skip_test_overrides(
            "N/A: Covered by test_user_enabled_invert")

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get')
    def test_user_enabled_attribute_handles_utf8(self, mock_ldap_get):
        # Since user_enabled_emulation is enabled in this test, this test will
        # fail since it's using user_enabled_invert.
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_attribute='passwordisexpired')
        mock_ldap_get.return_value = (
            u'uid=123456789,c=us,ou=our_ldap,o=acme.com',
            {
                'uid': [123456789],
                'mail': [u'shaun@acme.com'],
                'passwordisexpired': [u'false'],
                'cn': [u'uid=123456789,c=us,ou=our_ldap,o=acme.com']
            }
        )

        user_api = identity.backends.ldap.UserApi(CONF)
        user_ref = user_api.get('123456789')
        self.assertIs(False, user_ref['enabled'])

    def test_escape_member_dn(self):
        # The enabled member DN is properly escaped when querying for enabled
        # user.

        object_id = uuid.uuid4().hex
        driver = PROVIDERS.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)

        # driver.user is the EnabledEmuMixIn implementation used for this test.
        mixin_impl = driver.user

        # ) is a special char in a filter and must be escaped.
        sample_dn = 'cn=foo)bar'
        # LDAP requires ) is escaped by being replaced with "\29"
        sample_dn_filter_esc = r'cn=foo\29bar'

        # Override the tree_dn, it's used to build the enabled member filter
        mixin_impl.tree_dn = sample_dn

        # The filter, which _is_id_enabled is going to build, contains the
        # tree_dn, which better be escaped in this case.
        exp_filter = '(%s=%s=%s,%s)' % (
            mixin_impl.member_attribute, mixin_impl.id_attr, object_id,
            sample_dn_filter_esc)

        with mixin_impl.get_connection() as conn:
            m = self.useFixture(
                fixtures.MockPatchObject(conn, 'search_s')).mock
            mixin_impl._is_id_enabled(object_id, conn)
            # The 3rd argument is the DN.
            self.assertEqual(exp_filter, m.call_args[0][2])


class LDAPPosixGroupsTest(LDAPTestSetup, unit.TestCase):

    def assert_backends(self):
        _assert_backends(self, identity='ldap')

    def config_overrides(self):
        super(LDAPPosixGroupsTest, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='ldap', group_members_are_ids=True,
                                   group_member_attribute='memberUID')

    def config_files(self):
        config_files = super(LDAPPosixGroupsTest, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def _get_domain_fixture(self):
        """Return the static domain, since domains in LDAP are read-only."""
        return PROVIDERS.resource_api.get_domain(
            CONF.identity.default_domain_id
        )

    def test_posix_member_id(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        # Make sure we get an empty list back on a new group, not an error.
        user_refs = PROVIDERS.identity_api.list_users_in_group(new_group['id'])
        self.assertEqual([], user_refs)
        # Make sure we get the correct users back once they have been added
        # to the group.
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)

        # NOTE(amakarov): Create the group directly using LDAP operations
        # rather than going through the manager.
        group_api = PROVIDERS.identity_api.driver.group
        group_ref = group_api.get(new_group['id'])
        mod = (ldap.MOD_ADD, group_api.member_attribute, new_user['id'])
        conn = group_api.get_connection()
        conn.modify_s(group_ref['dn'], [mod])

        # Testing the case "the group contains a user"
        user_refs = PROVIDERS.identity_api.list_users_in_group(new_group['id'])
        self.assertIn(new_user['id'], (x['id'] for x in user_refs))

        # Testing the case "the user is a member of a group"
        group_refs = PROVIDERS.identity_api.list_groups_for_user(
            new_user['id']
        )
        self.assertIn(new_group['id'], (x['id'] for x in group_refs))


class LdapIdentityWithMapping(
        BaseLDAPIdentity, unit.SQLDriverOverrides, unit.TestCase):
    """Class to test mapping of default LDAP backend.

    The default configuration is not to enable mapping when using a single
    backend LDAP driver.  However, a cloud provider might want to enable
    the mapping, hence hiding the LDAP IDs from any clients of keystone.
    Setting backward_compatible_ids to False will enable this mapping.

    """

    def config_files(self):
        config_files = super(LdapIdentityWithMapping, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap_sql.conf'))
        return config_files

    def setUp(self):
        super(LdapIdentityWithMapping, self).setUp()
        cache.configure_cache()

    def assert_backends(self):
        _assert_backends(self, identity='ldap')

    def config_overrides(self):
        super(LdapIdentityWithMapping, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def test_dynamic_mapping_build(self):
        """Test to ensure entities not create via controller are mapped.

        Many LDAP backends will, essentially, by Read Only. In these cases
        the mapping is not built by creating objects, rather from enumerating
        the entries.  We test this here my manually deleting the mapping and
        then trying to re-read the entries.

        """
        initial_mappings = len(mapping_sql.list_id_mappings())
        user1 = self.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user1 = PROVIDERS.identity_api.create_user(user1)
        user2 = self.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user2 = PROVIDERS.identity_api.create_user(user2)
        mappings = mapping_sql.list_id_mappings()
        self.assertEqual(initial_mappings + 2, len(mappings))

        # Now delete the mappings for the two users above
        PROVIDERS.id_mapping_api.purge_mappings({'public_id': user1['id']})
        PROVIDERS.id_mapping_api.purge_mappings({'public_id': user2['id']})

        # We should no longer be able to get these users via their old IDs
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user,
                          user1['id'])
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user,
                          user2['id'])

        # Now enumerate all users...this should re-build the mapping, and
        # we should be able to find the users via their original public IDs.
        PROVIDERS.identity_api.list_users()
        PROVIDERS.identity_api.get_user(user1['id'])
        PROVIDERS.identity_api.get_user(user2['id'])

    def test_list_domains(self):
        domains = PROVIDERS.resource_api.list_domains()
        default_domain = unit.new_domain_ref(
            description=u'The default domain',
            id=CONF.identity.default_domain_id,
            name=u'Default')
        self.assertEqual([default_domain], domains)


class BaseMultiLDAPandSQLIdentity(object):
    """Mixin class with support methods for domain-specific config testing."""

    def create_users_across_domains(self):
        """Create a set of users, each with a role on their own domain."""
        # We also will check that the right number of id mappings get created
        initial_mappings = len(mapping_sql.list_id_mappings())

        users = {}

        users['user0'] = unit.create_user(
            PROVIDERS.identity_api,
            self.domain_default['id'])
        PROVIDERS.assignment_api.create_grant(
            user_id=users['user0']['id'],
            domain_id=self.domain_default['id'],
            role_id=self.role_member['id'])
        for x in range(1, self.domain_count):
            users['user%s' % x] = unit.create_user(
                PROVIDERS.identity_api,
                self.domains['domain%s' % x]['id'])
            PROVIDERS.assignment_api.create_grant(
                user_id=users['user%s' % x]['id'],
                domain_id=self.domains['domain%s' % x]['id'],
                role_id=self.role_member['id'])

        # So how many new id mappings should have been created? One for each
        # user created in a domain that is using the non default driver..
        self.assertEqual(initial_mappings + self.domain_specific_count,
                         len(mapping_sql.list_id_mappings()))

        return users

    def check_user(self, user, domain_id, expected_status):
        """Check user is in correct backend.

        As part of the tests, we want to force ourselves to manually
        select the driver for a given domain, to make sure the entity
        ended up in the correct backend.

        """
        driver = PROVIDERS.identity_api._select_identity_driver(domain_id)
        unused, unused, entity_id = (
            PROVIDERS.identity_api._get_domain_driver_and_entity_id(
                user['id']))

        if expected_status == http.client.OK:
            ref = driver.get_user(entity_id)
            ref = PROVIDERS.identity_api._set_domain_id_and_mapping(
                ref, domain_id, driver, map.EntityType.USER)
            user = user.copy()
            del user['password']
            self.assertDictEqual(user, ref)
        else:
            # TODO(henry-nash): Use AssertRaises here, although
            # there appears to be an issue with using driver.get_user
            # inside that construct
            try:
                driver.get_user(entity_id)
            except expected_status:
                pass

    def setup_initial_domains(self):

        def create_domain(domain):
            try:
                ref = PROVIDERS.resource_api.create_domain(
                    domain['id'], domain)
            except exception.Conflict:
                ref = (
                    PROVIDERS.resource_api.get_domain_by_name(domain['name']))
            return ref

        self.domains = {}
        for x in range(1, self.domain_count):
            domain = 'domain%s' % x
            self.domains[domain] = create_domain(
                {'id': uuid.uuid4().hex, 'name': domain})

    def test_authenticate_to_each_domain(self):
        """Test that a user in each domain can authenticate."""
        users = self.create_users_across_domains()

        for user_num in range(self.domain_count):
            user = 'user%s' % user_num
            with self.make_request():
                PROVIDERS.identity_api.authenticate(
                    user_id=users[user]['id'],
                    password=users[user]['password'])


class MultiLDAPandSQLIdentity(BaseLDAPIdentity, unit.SQLDriverOverrides,
                              unit.TestCase, BaseMultiLDAPandSQLIdentity):
    """Class to test common SQL plus individual LDAP backends.

    We define a set of domains and domain-specific backends:

    - A separate LDAP backend for the default domain
    - A separate LDAP backend for domain1
    - domain2 shares the same LDAP as domain1, but uses a different
      tree attach point
    - An SQL backend for all other domains (which will include domain3
      and domain4)

    Normally one would expect that the default domain would be handled as
    part of the "other domains" - however the above provides better
    test coverage since most of the existing backend tests use the default
    domain.

    """

    def load_fixtures(self, fixtures):
        self.domain_count = 5
        self.domain_specific_count = 3
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)
        self.setup_initial_domains()

        # All initial test data setup complete, time to switch on support
        # for separate backends per domain.
        self.enable_multi_domain()

        super(MultiLDAPandSQLIdentity, self).load_fixtures(fixtures)

    def assert_backends(self):
        _assert_backends(self,
                         assignment='sql',
                         identity={
                             None: 'sql',
                             self.domain_default['id']: 'ldap',
                             self.domains['domain1']['id']: 'ldap',
                             self.domains['domain2']['id']: 'ldap',
                         },
                         resource='sql')

    def config_overrides(self):
        super(MultiLDAPandSQLIdentity, self).config_overrides()
        # Make sure identity and assignment are actually SQL drivers,
        # BaseLDAPIdentity sets these options to use LDAP.
        self.config_fixture.config(group='identity', driver='sql')
        self.config_fixture.config(group='resource', driver='sql')
        self.config_fixture.config(group='assignment', driver='sql')

    def enable_multi_domain(self):
        """Enable the chosen form of multi domain configuration support.

        This method enables the file-based configuration support. Child classes
        that wish to use the database domain configuration support should
        override this method and set the appropriate config_fixture option.

        """
        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_config_dir=unit.TESTCONF + '/domain_configs_multi_ldap',
            list_limit=1000)
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def get_config(self, domain_id):
        # Get the config for this domain, will return CONF
        # if no specific config defined for this domain
        return PROVIDERS.identity_api.domain_configs.get_domain_conf(domain_id)

    def test_list_users(self):
        _users = self.create_users_across_domains()

        # Override the standard list users, since we have added an extra user
        # to the default domain, so the number of expected users is one more
        # than in the standard test.
        users = PROVIDERS.identity_api.list_users(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(len(default_fixtures.USERS) + 1, len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['name'])['id']
                                for user in default_fixtures.USERS)
        expected_user_ids.add(_users['user0']['id'])
        for user_ref in users:
            self.assertNotIn('password', user_ref)
        self.assertEqual(expected_user_ids, user_ids)

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get_all')
    def test_list_limit_domain_specific_inheritance(self, ldap_get_all):
        # passiging hints is important, because if it's not passed, limiting
        # is considered be disabled
        hints = driver_hints.Hints()
        PROVIDERS.identity_api.list_users(
            domain_scope=self.domains['domain2']['id'],
            hints=hints)
        # since list_limit is not specified in keystone.domain2.conf, it should
        # take the default, which is 1000
        self.assertTrue(ldap_get_all.called)
        args, kwargs = ldap_get_all.call_args
        hints = args[0]
        self.assertEqual(1000, hints.limit['limit'])

    @mock.patch.object(common_ldap.BaseLdap, '_ldap_get_all')
    def test_list_limit_domain_specific_override(self, ldap_get_all):
        # passiging hints is important, because if it's not passed, limiting
        # is considered to be disabled
        hints = driver_hints.Hints()
        PROVIDERS.identity_api.list_users(
            domain_scope=self.domains['domain1']['id'],
            hints=hints)
        # this should have the list_limit set in Keystone.domain1.conf, which
        # is 101
        self.assertTrue(ldap_get_all.called)
        args, kwargs = ldap_get_all.call_args
        hints = args[0]
        self.assertEqual(101, hints.limit['limit'])

    def test_domain_segregation(self):
        """Test that separate configs have segregated the domain.

        Test Plan:

        - Users were created in each domain as part of setup, now make sure
          you can only find a given user in its relevant domain/backend
        - Make sure that for a backend that supports multiple domains
          you can get the users via any of its domains

        """
        users = self.create_users_across_domains()

        # Check that I can read a user with the appropriate domain-selected
        # driver, but won't find it via any other domain driver

        check_user = self.check_user
        check_user(users['user0'],
                   self.domain_default['id'], http.client.OK)
        for domain in [self.domains['domain1']['id'],
                       self.domains['domain2']['id'],
                       self.domains['domain3']['id'],
                       self.domains['domain4']['id']]:
            check_user(users['user0'], domain, exception.UserNotFound)

        check_user(users['user1'], self.domains['domain1']['id'],
                   http.client.OK)
        for domain in [self.domain_default['id'],
                       self.domains['domain2']['id'],
                       self.domains['domain3']['id'],
                       self.domains['domain4']['id']]:
            check_user(users['user1'], domain, exception.UserNotFound)

        check_user(users['user2'], self.domains['domain2']['id'],
                   http.client.OK)
        for domain in [self.domain_default['id'],
                       self.domains['domain1']['id'],
                       self.domains['domain3']['id'],
                       self.domains['domain4']['id']]:
            check_user(users['user2'], domain, exception.UserNotFound)

        # domain3 and domain4 share the same backend, so you should be
        # able to see user3 and user4 from either.

        check_user(users['user3'], self.domains['domain3']['id'],
                   http.client.OK)
        check_user(users['user3'], self.domains['domain4']['id'],
                   http.client.OK)
        check_user(users['user4'], self.domains['domain3']['id'],
                   http.client.OK)
        check_user(users['user4'], self.domains['domain4']['id'],
                   http.client.OK)

        for domain in [self.domain_default['id'],
                       self.domains['domain1']['id'],
                       self.domains['domain2']['id']]:
            check_user(users['user3'], domain, exception.UserNotFound)
            check_user(users['user4'], domain, exception.UserNotFound)

        # Finally, going through the regular manager layer, make sure we
        # only see the right number of users in each of the non-default
        # domains.  One might have expected two users in domain1 (since we
        # created one before we switched to multi-backend), however since
        # that domain changed backends in the switch we don't find it anymore.
        # This is as designed - we don't support moving domains between
        # backends.
        #
        # The listing of the default domain is already handled in the
        # test_lists_users() method.
        for domain in [self.domains['domain1']['id'],
                       self.domains['domain2']['id'],
                       self.domains['domain4']['id']]:
            self.assertThat(
                PROVIDERS.identity_api.list_users(domain_scope=domain),
                matchers.HasLength(1))

        # domain3 had a user created before we switched on
        # multiple backends, plus one created afterwards - and its
        # backend has not changed - so we should find two.
        self.assertThat(
            PROVIDERS.identity_api.list_users(
                domain_scope=self.domains['domain3']['id']),
            matchers.HasLength(1))

    def test_existing_uuids_work(self):
        """Test that 'uni-domain' created IDs still work.

        Throwing the switch to domain-specific backends should not cause
        existing identities to be inaccessible via ID.

        """
        userA = unit.create_user(
            PROVIDERS.identity_api,
            self.domain_default['id'])
        userB = unit.create_user(
            PROVIDERS.identity_api,
            self.domains['domain1']['id'])
        userC = unit.create_user(
            PROVIDERS.identity_api,
            self.domains['domain3']['id'])
        PROVIDERS.identity_api.get_user(userA['id'])
        PROVIDERS.identity_api.get_user(userB['id'])
        PROVIDERS.identity_api.get_user(userC['id'])

    def test_scanning_of_config_dir(self):
        """Test the Manager class scans the config directory.

        The setup for the main tests above load the domain configs directly
        so that the test overrides can be included. This test just makes sure
        that the standard config directory scanning does pick up the relevant
        domain config files.

        """
        # Confirm that config has drivers_enabled as True, which we will
        # check has been set to False later in this test
        self.assertTrue(CONF.identity.domain_specific_drivers_enabled)
        self.load_backends()
        # Execute any command to trigger the lazy loading of domain configs
        PROVIDERS.identity_api.list_users(
            domain_scope=self.domains['domain1']['id'])
        # ...and now check the domain configs have been set up
        self.assertIn('default', PROVIDERS.identity_api.domain_configs)
        self.assertIn(self.domains['domain1']['id'],
                      PROVIDERS.identity_api.domain_configs)
        self.assertIn(self.domains['domain2']['id'],
                      PROVIDERS.identity_api.domain_configs)
        self.assertNotIn(self.domains['domain3']['id'],
                         PROVIDERS.identity_api.domain_configs)
        self.assertNotIn(self.domains['domain4']['id'],
                         PROVIDERS.identity_api.domain_configs)

        # Finally check that a domain specific config contains items from both
        # the primary config and the domain specific config
        conf = PROVIDERS.identity_api.domain_configs.get_domain_conf(
            self.domains['domain1']['id'])
        # This should now be false, as is the default, since this is not
        # set in the standard primary config file
        self.assertFalse(conf.identity.domain_specific_drivers_enabled)
        # ..and make sure a domain-specific options is also set
        self.assertEqual('fake://memory1', conf.ldap.url)

    def test_delete_domain_with_user_added(self):
        domain = unit.new_domain_ref()
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        project_ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(project, project_ref)

        PROVIDERS.assignment_api.create_grant(
            user_id=self.user_foo['id'], project_id=project['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.delete_grant(
            user_id=self.user_foo['id'], project_id=project['id'],
            role_id=self.role_member['id']
        )
        domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain['id'], domain)
        PROVIDERS.resource_api.delete_domain(domain['id'])
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain,
                          domain['id'])

    def test_user_enabled_ignored_disable_error(self):
        # Override.
        self.skip_test_overrides("Doesn't apply since LDAP config has no "
                                 "affect on the SQL identity backend.")

    def test_group_enabled_ignored_disable_error(self):
        # Override.
        self.skip_test_overrides("Doesn't apply since LDAP config has no "
                                 "affect on the SQL identity backend.")

    def test_list_role_assignments_filtered_by_role(self):
        # Domain roles are supported by the SQL Assignment backend
        base = super(BaseLDAPIdentity, self)
        base.test_list_role_assignments_filtered_by_role()

    def test_list_role_assignment_by_domain(self):
        # With multi LDAP this method should work, so override the override
        # from BaseLDAPIdentity
        super(BaseLDAPIdentity, self).test_list_role_assignment_by_domain()

    def test_list_role_assignment_by_user_with_domain_group_roles(self):
        # With multi LDAP this method should work, so override the override
        # from BaseLDAPIdentity
        super(BaseLDAPIdentity, self).\
            test_list_role_assignment_by_user_with_domain_group_roles()

    def test_list_role_assignment_using_sourced_groups_with_domains(self):
        # With SQL Assignment this method should work, so override the override
        # from BaseLDAPIdentity
        base = super(BaseLDAPIdentity, self)
        base.test_list_role_assignment_using_sourced_groups_with_domains()

    def test_create_project_with_domain_id_and_without_parent_id(self):
        # With multi LDAP this method should work, so override the override
        # from BaseLDAPIdentity
        super(BaseLDAPIdentity, self).\
            test_create_project_with_domain_id_and_without_parent_id()

    def test_create_project_with_domain_id_mismatch_to_parent_domain(self):
        # With multi LDAP this method should work, so override the override
        # from BaseLDAPIdentity
        super(BaseLDAPIdentity, self).\
            test_create_project_with_domain_id_mismatch_to_parent_domain()

    def test_remove_foreign_assignments_when_deleting_a_domain(self):
        # With multi LDAP this method should work, so override the override
        # from BaseLDAPIdentity
        base = super(BaseLDAPIdentity, self)
        base.test_remove_foreign_assignments_when_deleting_a_domain()

    @mock.patch.object(ldap_identity.Identity, 'unset_default_project_id')
    @mock.patch.object(sql_identity.Identity, 'unset_default_project_id')
    def test_delete_project_unset_project_ids_for_all_backends(self, sql_mock,
                                                               ldap_mock):
        ldap_mock.side_effect = exception.Forbidden
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.resource_api.delete_project(project['id'])
        ldap_mock.assert_called_with(project['id'])
        sql_mock.assert_called_with(project['id'])


class MultiLDAPandSQLIdentityDomainConfigsInSQL(MultiLDAPandSQLIdentity):
    """Class to test the use of domain configs stored in the database.

    Repeat the same tests as MultiLDAPandSQLIdentity, but instead of using the
    domain specific config files, store the domain specific values in the
    database.

    """

    def assert_backends(self):
        _assert_backends(self,
                         assignment='sql',
                         identity={
                             None: 'sql',
                             self.domain_default['id']: 'ldap',
                             self.domains['domain1']['id']: 'ldap',
                             self.domains['domain2']['id']: 'ldap',
                         },
                         resource='sql')

    def enable_multi_domain(self):
        # The values below are the same as in the domain_configs_multi_ldap
        # directory of test config_files.
        default_config = {
            'ldap': {'url': 'fake://memory',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=example,cn=com'},
            'identity': {'driver': 'ldap'}
        }
        domain1_config = {
            'ldap': {'url': 'fake://memory1',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=example,cn=com'},
            'identity': {'driver': 'ldap',
                         'list_limit': 101}
        }
        domain2_config = {
            'ldap': {'url': 'fake://memory',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=myroot,cn=com',
                     'group_tree_dn': 'ou=UserGroups,dc=myroot,dc=org',
                     'user_tree_dn': 'ou=Users,dc=myroot,dc=org'},
            'identity': {'driver': 'ldap'}
        }

        PROVIDERS.domain_config_api.create_config(
            CONF.identity.default_domain_id, default_config
        )
        PROVIDERS.domain_config_api.create_config(
            self.domains['domain1']['id'], domain1_config
        )
        PROVIDERS.domain_config_api.create_config(
            self.domains['domain2']['id'], domain2_config
        )

        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_configurations_from_database=True,
            list_limit=1000)
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def test_domain_config_has_no_impact_if_database_support_disabled(self):
        """Ensure database domain configs have no effect if disabled.

        Set reading from database configs to false, restart the backends
        and then try and set and use database configs.

        """
        self.config_fixture.config(
            group='identity', domain_configurations_from_database=False)
        self.load_backends()
        new_config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        # Trigger the identity backend to initialise any domain specific
        # configurations
        PROVIDERS.identity_api.list_users()
        # Check that the new config has not been passed to the driver for
        # the default domain.
        default_config = (
            PROVIDERS.identity_api.domain_configs.get_domain_conf(
                CONF.identity.default_domain_id))
        self.assertEqual(CONF.ldap.url, default_config.ldap.url)

    def test_reloading_domain_config(self):
        """Ensure domain drivers are reloaded on a config modification."""
        domain_cfgs = PROVIDERS.identity_api.domain_configs

        # Create a new config for the default domain, hence overwriting the
        # current settings.
        new_config = {
            'ldap': {'url': uuid.uuid4().hex},
            'identity': {'driver': 'ldap'}}
        PROVIDERS.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        default_config = (
            domain_cfgs.get_domain_conf(CONF.identity.default_domain_id))
        self.assertEqual(new_config['ldap']['url'], default_config.ldap.url)

        # Ensure updating is also honored
        updated_config = {'url': uuid.uuid4().hex}
        PROVIDERS.domain_config_api.update_config(
            CONF.identity.default_domain_id, updated_config,
            group='ldap', option='url')
        default_config = (
            domain_cfgs.get_domain_conf(CONF.identity.default_domain_id))
        self.assertEqual(updated_config['url'], default_config.ldap.url)

        # ...and finally ensure delete causes the driver to get the standard
        # config again.
        PROVIDERS.domain_config_api.delete_config(
            CONF.identity.default_domain_id
        )
        default_config = (
            domain_cfgs.get_domain_conf(CONF.identity.default_domain_id))
        self.assertEqual(CONF.ldap.url, default_config.ldap.url)

    def test_setting_multiple_sql_driver_raises_exception(self):
        """Ensure setting multiple domain specific sql drivers is prevented."""
        new_config = {'identity': {'driver': 'sql'}}
        PROVIDERS.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        PROVIDERS.identity_api.domain_configs.get_domain_conf(
            CONF.identity.default_domain_id)
        PROVIDERS.domain_config_api.create_config(
            self.domains['domain1']['id'], new_config
        )
        self.assertRaises(
            exception.MultipleSQLDriversInConfig,
            PROVIDERS.identity_api.domain_configs.get_domain_conf,
            self.domains['domain1']['id']
        )

    def test_same_domain_gets_sql_driver(self):
        """Ensure we can set an SQL driver if we have had it before."""
        new_config = {'identity': {'driver': 'sql'}}
        PROVIDERS.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        PROVIDERS.identity_api.domain_configs.get_domain_conf(
            CONF.identity.default_domain_id)

        # By using a slightly different config, we cause the driver to be
        # reloaded...and hence check if we can reuse the sql driver
        new_config = {'identity': {'driver': 'sql'},
                      'ldap': {'url': 'fake://memory1'}}
        PROVIDERS.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        PROVIDERS.identity_api.domain_configs.get_domain_conf(
            CONF.identity.default_domain_id)

    def test_delete_domain_clears_sql_registration(self):
        """Ensure registration is deleted when a domain is deleted."""
        domain = unit.new_domain_ref()
        domain = PROVIDERS.resource_api.create_domain(domain['id'], domain)
        new_config = {'identity': {'driver': 'sql'}}
        PROVIDERS.domain_config_api.create_config(domain['id'], new_config)
        PROVIDERS.identity_api.domain_configs.get_domain_conf(domain['id'])

        # First show that trying to set SQL for another driver fails
        PROVIDERS.domain_config_api.create_config(
            self.domains['domain1']['id'], new_config
        )
        self.assertRaises(
            exception.MultipleSQLDriversInConfig,
            PROVIDERS.identity_api.domain_configs.get_domain_conf,
            self.domains['domain1']['id']
        )
        PROVIDERS.domain_config_api.delete_config(
            self.domains['domain1']['id']
        )

        # Now we delete the domain
        domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain['id'], domain)
        PROVIDERS.resource_api.delete_domain(domain['id'])

        # The registration should now be available
        PROVIDERS.domain_config_api.create_config(
            self.domains['domain1']['id'], new_config
        )
        PROVIDERS.identity_api.domain_configs.get_domain_conf(
            self.domains['domain1']['id']
        )

    def test_orphaned_registration_does_not_prevent_getting_sql_driver(self):
        """Ensure we self heal an orphaned sql registration."""
        domain = unit.new_domain_ref()
        domain = PROVIDERS.resource_api.create_domain(domain['id'], domain)
        new_config = {'identity': {'driver': 'sql'}}
        PROVIDERS.domain_config_api.create_config(domain['id'], new_config)
        PROVIDERS.identity_api.domain_configs.get_domain_conf(domain['id'])

        # First show that trying to set SQL for another driver fails
        PROVIDERS.domain_config_api.create_config(
            self.domains['domain1']['id'], new_config
        )
        self.assertRaises(
            exception.MultipleSQLDriversInConfig,
            PROVIDERS.identity_api.domain_configs.get_domain_conf,
            self.domains['domain1']['id']
        )

        # Now we delete the domain by using the backend driver directly,
        # which causes the domain to be deleted without any of the cleanup
        # that is in the manager (this is simulating a server process crashing
        # in the middle of a delete domain operation, and somehow leaving the
        # domain config settings in place, but the domain is deleted). We
        # should still be able to set another domain to SQL, since we should
        # self heal this issue.

        PROVIDERS.resource_api.driver.delete_project(domain['id'])
        # Invalidate cache (so we will see the domain has gone)
        PROVIDERS.resource_api.get_domain.invalidate(
            PROVIDERS.resource_api, domain['id'])

        # The registration should now be available
        PROVIDERS.domain_config_api.create_config(
            self.domains['domain1']['id'], new_config
        )
        PROVIDERS.identity_api.domain_configs.get_domain_conf(
            self.domains['domain1']['id'])


class DomainSpecificLDAPandSQLIdentity(
    BaseLDAPIdentity, unit.SQLDriverOverrides, unit.TestCase,
        BaseMultiLDAPandSQLIdentity):
    """Class to test when all domains use specific configs, including SQL.

    We define a set of domains and domain-specific backends:

    - A separate LDAP backend for the default domain
    - A separate SQL backend for domain1

    Although the default driver still exists, we don't use it.

    """

    DOMAIN_COUNT = 2
    DOMAIN_SPECIFIC_COUNT = 2

    def setUp(self):
        self.domain_count = self.DOMAIN_COUNT
        self.domain_specific_count = self.DOMAIN_SPECIFIC_COUNT

        super(DomainSpecificLDAPandSQLIdentity, self).setUp()

    def load_fixtures(self, fixtures):
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)
        self.setup_initial_domains()
        super(DomainSpecificLDAPandSQLIdentity, self).load_fixtures(fixtures)

    def assert_backends(self):
        _assert_backends(
            self,
            assignment='sql',
            identity={
                None: 'ldap',
                'default': 'ldap',
                self.domains['domain1']['id']: 'sql',
            },
            resource='sql')

    def config_overrides(self):
        super(DomainSpecificLDAPandSQLIdentity, self).config_overrides()
        # Make sure resource & assignment are actually SQL drivers,
        # BaseLDAPIdentity causes this option to use LDAP.
        self.config_fixture.config(group='resource', driver='sql')
        self.config_fixture.config(group='assignment', driver='sql')

        # We aren't setting up any initial data ahead of switching to
        # domain-specific operation, so make the switch straight away.
        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_config_dir=(
                unit.TESTCONF + '/domain_configs_one_sql_one_ldap'))

        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def get_config(self, domain_id):
        # Get the config for this domain, will return CONF
        # if no specific config defined for this domain
        return PROVIDERS.identity_api.domain_configs.get_domain_conf(domain_id)

    def test_list_domains(self):
        self.skip_test_overrides('N/A: Not relevant for multi ldap testing')

    def test_delete_domain(self):
        # With this restricted multi LDAP class, tests that use multiple
        # domains and identity, are still not supported
        self.assertRaises(
            exception.DomainNotFound,
            super(BaseLDAPIdentity, self).test_delete_domain_with_project_api)

    def test_list_users(self):
        _users = self.create_users_across_domains()

        # Override the standard list users, since we have added an extra user
        # to the default domain, so the number of expected users is one more
        # than in the standard test.
        users = PROVIDERS.identity_api.list_users(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(len(default_fixtures.USERS) + 1, len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['name'])['id']
                                for user in default_fixtures.USERS)
        expected_user_ids.add(_users['user0']['id'])
        for user_ref in users:
            self.assertNotIn('password', user_ref)
        self.assertEqual(expected_user_ids, user_ids)

    def test_domain_segregation(self):
        """Test that separate configs have segregated the domain.

        Test Plan:

        - Users were created in each domain as part of setup, now make sure
          you can only find a given user in its relevant domain/backend
        - Make sure that for a backend that supports multiple domains
          you can get the users via any of its domains

        """
        users = self.create_users_across_domains()

        # Check that I can read a user with the appropriate domain-selected
        # driver, but won't find it via any other domain driver

        self.check_user(users['user0'],
                        self.domain_default['id'], http.client.OK)
        self.check_user(users['user0'],
                        self.domains['domain1']['id'], exception.UserNotFound)

        self.check_user(users['user1'],
                        self.domains['domain1']['id'], http.client.OK)
        self.check_user(users['user1'],
                        self.domain_default['id'],
                        exception.UserNotFound)

        # Finally, going through the regular manager layer, make sure we
        # only see the right number of users in the non-default domain.

        self.assertThat(
            PROVIDERS.identity_api.list_users(
                domain_scope=self.domains['domain1']['id']),
            matchers.HasLength(1))

    def test_get_domain_mapping_list_is_used(self):
        # before get_domain_mapping_list was introduced, it was required to
        # make N calls to the database for N users, and it was slow.
        # get_domain_mapping_list solves this problem and should be used
        # when multiple users are fetched from domain-specific backend.
        for i in range(5):
            unit.create_user(PROVIDERS.identity_api,
                             domain_id=self.domains['domain1']['id'])

        with mock.patch.multiple(PROVIDERS.id_mapping_api,
                                 get_domain_mapping_list=mock.DEFAULT,
                                 get_id_mapping=mock.DEFAULT) as mocked:
            PROVIDERS.identity_api.list_users(
                domain_scope=self.domains['domain1']['id'])
            mocked['get_domain_mapping_list'].assert_called()
            mocked['get_id_mapping'].assert_not_called()

    def test_user_id_comma(self):
        self.skip_test_overrides('Only valid if it is guaranteed to be '
                                 'talking to the fakeldap backend')

    def test_user_enabled_ignored_disable_error(self):
        # Override.
        self.skip_test_overrides("Doesn't apply since LDAP config has no "
                                 "affect on the SQL identity backend.")

    def test_group_enabled_ignored_disable_error(self):
        # Override.
        self.skip_test_overrides("Doesn't apply since LDAP config has no "
                                 "affect on the SQL identity backend.")

    def test_list_role_assignments_filtered_by_role(self):
        # Domain roles are supported by the SQL Assignment backend
        base = super(BaseLDAPIdentity, self)
        base.test_list_role_assignments_filtered_by_role()

    def test_delete_domain_with_project_api(self):
        # With this restricted multi LDAP class, tests that use multiple
        # domains and identity, are still not supported
        self.assertRaises(
            exception.DomainNotFound,
            super(BaseLDAPIdentity, self).test_delete_domain_with_project_api)

    def test_create_project_with_domain_id_and_without_parent_id(self):
        # With restricted multi LDAP, tests that don't use identity, but do
        # required aditional domains will work
        base = super(BaseLDAPIdentity, self)
        base.test_create_project_with_domain_id_and_without_parent_id()

    def test_create_project_with_domain_id_mismatch_to_parent_domain(self):
        # With restricted multi LDAP, tests that don't use identity, but do
        # required aditional domains will work
        base = super(BaseLDAPIdentity, self)
        base.test_create_project_with_domain_id_mismatch_to_parent_domain()

    def test_list_domains_filtered_and_limited(self):
        # With this restricted multi LDAP class, tests that use multiple
        # domains and identity, are still not supported
        self.skip_test_overrides(
            'Restricted multi LDAP class does not support multiple domains')

    def test_list_limit_for_domains(self):
        # With this restricted multi LDAP class, tests that use multiple
        # domains and identity, are still not supported
        self.skip_test_overrides(
            'Restricted multi LDAP class does not support multiple domains')


class DomainSpecificSQLIdentity(DomainSpecificLDAPandSQLIdentity):
    """Class to test simplest use of domain-specific SQL driver.

    The simplest use of an SQL domain-specific backend is when it is used to
    augment the standard case when LDAP is the default driver defined in the
    main config file. This would allow, for example, service users to be
    stored in SQL while LDAP handles the rest. Hence we define:

    - The default driver uses the LDAP backend for the default domain
    - A separate SQL backend for domain1

    """

    DOMAIN_COUNT = 2
    DOMAIN_SPECIFIC_COUNT = 1

    def assert_backends(self):
        _assert_backends(self,
                         assignment='sql',
                         identity='ldap',
                         resource='sql')

    def config_overrides(self):
        super(DomainSpecificSQLIdentity, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

        # We aren't setting up any initial data ahead of switching to
        # domain-specific operation, so make the switch straight away.
        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_config_dir=(
                unit.TESTCONF + '/domain_configs_default_ldap_one_sql'))

        # Part of the testing counts how many new mappings get created as
        # we create users, so ensure we are NOT using mapping for the default
        # LDAP domain so this doesn't confuse the calculation.
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=True)

    def get_config(self, domain_id):
        if domain_id == CONF.identity.default_domain_id:
            return CONF
        else:
            return PROVIDERS.identity_api.domain_configs.get_domain_conf(
                domain_id
            )

    def test_default_sql_plus_sql_specific_driver_fails(self):
        # First confirm that if ldap is default driver, domain1 can be
        # loaded as sql
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='assignment', driver='sql')
        self.load_backends()
        # Make any identity call to initiate the lazy loading of configs
        PROVIDERS.identity_api.list_users(
            domain_scope=CONF.identity.default_domain_id)
        self.assertIsNotNone(self.get_config(self.domains['domain1']['id']))

        # Now re-initialize, but with sql as the identity driver
        self.config_fixture.config(group='identity', driver='sql')
        self.config_fixture.config(group='assignment', driver='sql')
        self.load_backends()
        # Make any identity call to initiate the lazy loading of configs, which
        # should fail since we would now have two sql drivers.
        self.assertRaises(exception.MultipleSQLDriversInConfig,
                          PROVIDERS.identity_api.list_users,
                          domain_scope=CONF.identity.default_domain_id)

    def test_multiple_sql_specific_drivers_fails(self):
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='assignment', driver='sql')
        self.load_backends()
        # Ensure default, domain1 and domain2 exist
        self.domain_count = 3
        self.setup_initial_domains()
        # Make any identity call to initiate the lazy loading of configs
        PROVIDERS.identity_api.list_users(
            domain_scope=CONF.identity.default_domain_id)
        # This will only load domain1, since the domain2 config file is
        # not stored in the same location
        self.assertIsNotNone(self.get_config(self.domains['domain1']['id']))

        # Now try and manually load a 2nd sql specific driver, for domain2,
        # which should fail.
        self.assertRaises(
            exception.MultipleSQLDriversInConfig,
            PROVIDERS.identity_api.domain_configs._load_config_from_file,
            PROVIDERS.resource_api,
            [unit.TESTCONF + '/domain_configs_one_extra_sql/' +
             'keystone.domain2.conf'],
            'domain2')


class LdapFilterTests(identity_tests.FilterTests, LDAPTestSetup,
                      unit.TestCase):

    def assert_backends(self):
        _assert_backends(self, identity='ldap')

    def config_overrides(self):
        super(LdapFilterTests, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(LdapFilterTests, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def test_list_users_in_group_inexact_filtered(self):
        # The LDAP identity driver currently does not support filtering on the
        # listing users for a given group, so will fail this test.
        self.skip_test_overrides('Not supported by LDAP identity driver')

    def test_list_users_in_group_exact_filtered(self):
        # The LDAP identity driver currently does not support filtering on the
        # listing users for a given group, so will fail this test.
        self.skip_test_overrides('Not supported by LDAP identity driver')


class LDAPMatchingRuleInChainTests(LDAPTestSetup, unit.TestCase):

    def setUp(self):
        super(LDAPMatchingRuleInChainTests, self).setUp()

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        self.group = PROVIDERS.identity_api.create_group(group)

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.user = PROVIDERS.identity_api.create_user(user)

        PROVIDERS.identity_api.add_user_to_group(
            self.user['id'], self.group['id']
        )

    def assert_backends(self):
        _assert_backends(self, identity='ldap')

    def config_overrides(self):
        super(LDAPMatchingRuleInChainTests, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(
            group='ldap',
            group_ad_nesting=True,
            url='fake://memory',
            chase_referrals=False,
            group_tree_dn='cn=UserGroups,cn=example,cn=com',
            query_scope='one')

    def config_files(self):
        config_files = super(LDAPMatchingRuleInChainTests, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def test_get_group(self):
        group_ref = PROVIDERS.identity_api.get_group(self.group['id'])
        self.assertDictEqual(self.group, group_ref)

    def test_list_user_groups(self):
        PROVIDERS.identity_api.list_groups_for_user(self.user['id'])

    def test_list_groups_for_user(self):
        groups_ref = PROVIDERS.identity_api.list_groups_for_user(
            self.user['id']
        )
        self.assertEqual(0, len(groups_ref))

    def test_list_groups(self):
        groups_refs = PROVIDERS.identity_api.list_groups()
        self.assertEqual(1, len(groups_refs))
        self.assertEqual(self.group['id'], groups_refs[0]['id'])
