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
import uuid

import ldap
import mock
from oslo_config import cfg
import pkg_resources
from six.moves import range
from testtools import matchers

from keystone.common import cache
from keystone.common import ldap as common_ldap
from keystone.common.ldap import core as common_ldap_core
from keystone import exception
from keystone import identity
from keystone.identity.mapping_backends import mapping as map
from keystone import resource
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import identity_mapping as mapping_sql
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.ksfixtures import ldapdb
from keystone.tests.unit import test_backend


CONF = cfg.CONF


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


def create_group_container(identity_api):
    # Create the groups base entry (ou=Groups,cn=example,cn=com)
    group_api = identity_api.driver.group
    conn = group_api.get_connection()
    dn = 'ou=Groups,cn=example,cn=com'
    conn.add_s(dn, [('objectclass', ['organizationalUnit']),
                    ('ou', ['Groups'])])


class BaseLDAPIdentity(test_backend.IdentityTests):

    def setUp(self):
        super(BaseLDAPIdentity, self).setUp()
        self.ldapdb = self.useFixture(ldapdb.LDAPDatabase())

        self.load_backends()
        self.load_fixtures(default_fixtures)

    def _get_domain_fixture(self):
        """Domains in LDAP are read-only, so just return the static one."""
        return self.resource_api.get_domain(CONF.identity.default_domain_id)

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

    def get_user_enabled_vals(self, user):
        user_dn = (
            self.identity_api.driver.user._id_to_dn_string(user['id']))
        enabled_attr_name = CONF.ldap.user_enabled_attribute

        ldap_ = self.identity_api.driver.user.get_connection()
        res = ldap_.search_s(user_dn,
                             ldap.SCOPE_BASE,
                             u'(sn=%s)' % user['name'])
        if enabled_attr_name in res[0][1]:
            return res[0][1][enabled_attr_name]
        else:
            return None

    def test_build_tree(self):
        """Regression test for building the tree names
        """
        user_api = identity.backends.ldap.UserApi(CONF)
        self.assertTrue(user_api)
        self.assertEqual("ou=Users,%s" % CONF.ldap.suffix, user_api.tree_dn)

    def test_configurable_allowed_user_actions(self):
        user = {'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                'tenants': ['bar']}
        user = self.identity_api.create_user(user)
        self.identity_api.get_user(user['id'])

        user['password'] = u'fäképass2'
        self.identity_api.update_user(user['id'], user)

        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])

    def test_configurable_forbidden_user_actions(self):
        driver = self.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.allow_create = False
        driver.user.allow_update = False
        driver.user.allow_delete = False

        user = {'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                'tenants': ['bar']}
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.create_user,
                          user)

        self.user_foo['password'] = u'fäképass2'
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.update_user,
                          self.user_foo['id'],
                          self.user_foo)

        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.delete_user,
                          self.user_foo['id'])

    def test_configurable_forbidden_create_existing_user(self):
        driver = self.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.allow_create = False

        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.create_user,
                          self.user_foo)

    def test_user_filter(self):
        user_ref = self.identity_api.get_user(self.user_foo['id'])
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)

        driver = self.identity_api._select_identity_driver(
            user_ref['domain_id'])
        driver.user.ldap_filter = '(CN=DOES_NOT_MATCH)'
        # invalidate the cache if the result is cached.
        self.identity_api.get_user.invalidate(self.identity_api,
                                              self.user_foo['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          self.user_foo['id'])

    def test_remove_role_grant_from_user_and_project(self):
        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_baz['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

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

    def test_get_and_remove_role_grant_by_group_and_project(self):
        new_domain = self._get_domain_fixture()
        new_group = {'domain_id': new_domain['id'],
                     'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_user = {'name': 'new_user', 'enabled': True,
                    'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])

        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertEqual([], roles_ref)
        self.assertEqual(0, len(roles_ref))

        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertNotEmpty(roles_ref)
        self.assertDictEqual(roles_ref[0], self.role_member)

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
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_get_role_assignment_by_domain_not_found(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_del_role_assignment_by_domain_not_found(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_get_and_remove_role_grant_by_user_and_domain(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_get_and_remove_correct_role_grant_from_a_mix(self):
        self.skipTest('Blocked by bug 1101287')

    def test_get_and_remove_role_grant_by_group_and_cross_domain(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_get_and_remove_role_grant_by_user_and_cross_domain(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_role_grant_by_group_and_cross_domain_project(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_role_grant_by_user_and_cross_domain_project(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_delete_role_with_user_and_group_grants(self):
        self.skipTest('Blocked by bug 1101287')

    def test_delete_user_with_group_project_domain_links(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_delete_group_with_user_project_domain_links(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_list_projects_for_user(self):
        domain = self._get_domain_fixture()
        user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                 'domain_id': domain['id'], 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertThat(user_projects, matchers.HasLength(0))

        # new grant(user1, role_member, tenant_bar)
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        # new grant(user1, role_member, tenant_baz)
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id=self.role_member['id'])
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertThat(user_projects, matchers.HasLength(2))

        # Now, check number of projects through groups
        user2 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                 'domain_id': domain['id'], 'enabled': True}
        user2 = self.identity_api.create_user(user2)

        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
        group1 = self.identity_api.create_group(group1)

        self.identity_api.add_user_to_group(user2['id'], group1['id'])

        # new grant(group1(user2), role_member, tenant_bar)
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        # new grant(group1(user2), role_member, tenant_baz)
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id=self.role_member['id'])
        user_projects = self.assignment_api.list_projects_for_user(user2['id'])
        self.assertThat(user_projects, matchers.HasLength(2))

        # new grant(group1(user2), role_other, tenant_bar)
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_other['id'])
        user_projects = self.assignment_api.list_projects_for_user(user2['id'])
        self.assertThat(user_projects, matchers.HasLength(2))

    def test_list_projects_for_user_and_groups(self):
        domain = self._get_domain_fixture()
        # Create user1
        user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                 'domain_id': domain['id'], 'enabled': True}
        user1 = self.identity_api.create_user(user1)

        # Create new group for user1
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
        group1 = self.identity_api.create_group(group1)

        # Add user1 to group1
        self.identity_api.add_user_to_group(user1['id'], group1['id'])

        # Now, add grant to user1 and group1 in tenant_bar
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])

        # The result is user1 has only one project granted
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertThat(user_projects, matchers.HasLength(1))

        # Now, delete user1 grant into tenant_bar and check
        self.assignment_api.delete_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])

        # The result is user1 has only one project granted.
        # Granted through group1.
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertThat(user_projects, matchers.HasLength(1))

    def test_list_projects_for_user_with_grants(self):
        domain = self._get_domain_fixture()
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': domain['id']}
        new_user = self.identity_api.create_user(new_user)

        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
        group1 = self.identity_api.create_group(group1)
        group2 = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
        group2 = self.identity_api.create_group(group2)

        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project2['id'], project2)

        self.identity_api.add_user_to_group(new_user['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(new_user['id'],
                                            group2['id'])

        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=project1['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         project_id=project2['id'],
                                         role_id=self.role_admin['id'])

        user_projects = self.assignment_api.list_projects_for_user(
            new_user['id'])
        self.assertEqual(3, len(user_projects))

    def test_create_duplicate_user_name_in_different_domains(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_create_duplicate_project_name_in_different_domains(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_create_duplicate_group_name_in_different_domains(self):
        self.skipTest(
            'N/A: LDAP does not support multiple domains')

    def test_move_user_between_domains(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_move_user_between_domains_with_clashing_names_fails(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_move_group_between_domains(self):
        self.skipTest(
            'N/A: LDAP does not support multiple domains')

    def test_move_group_between_domains_with_clashing_names_fails(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_move_project_between_domains(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_move_project_between_domains_with_clashing_names_fails(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_get_roles_for_user_and_domain(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_get_roles_for_groups_on_domain(self):
        self.skipTest('Blocked by bug: 1390125')

    def test_get_roles_for_groups_on_project(self):
        self.skipTest('Blocked by bug: 1390125')

    def test_list_domains_for_groups(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_list_projects_for_groups(self):
        self.skipTest('Blocked by bug: 1390125')

    def test_domain_delete_hierarchy(self):
        self.skipTest('Domains are read-only against LDAP')

    def test_list_role_assignments_unfiltered(self):
        new_domain = self._get_domain_fixture()
        new_user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        new_group = {'domain_id': new_domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_project = {'id': uuid.uuid4().hex,
                       'name': uuid.uuid4().hex,
                       'domain_id': new_domain['id']}
        self.resource_api.create_project(new_project['id'], new_project)

        # First check how many role grant already exist
        existing_assignments = len(self.assignment_api.list_role_assignments())

        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=new_project['id'],
                                         role_id='other')
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=new_project['id'],
                                         role_id='admin')

        # Read back the list of assignments - check it is gone up by 2
        after_assignments = len(self.assignment_api.list_role_assignments())
        self.assertEqual(existing_assignments + 2, after_assignments)

    def test_list_role_assignments_filtered_by_role(self):
        # Domain roles are not supported by the LDAP Assignment backend
        self.assertRaises(
            exception.NotImplemented,
            super(BaseLDAPIdentity, self).
            test_list_role_assignments_filtered_by_role)

    def test_list_role_assignments_dumb_member(self):
        self.config_fixture.config(group='ldap', use_dumb_member=True)
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        new_domain = self._get_domain_fixture()
        new_user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        new_project = {'id': uuid.uuid4().hex,
                       'name': uuid.uuid4().hex,
                       'domain_id': new_domain['id']}
        self.resource_api.create_project(new_project['id'], new_project)
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=new_project['id'],
                                         role_id='other')

        # Read back the list of assignments and ensure
        # that the LDAP dumb member isn't listed.
        assignment_ids = [a['user_id'] for a in
                          self.assignment_api.list_role_assignments()]
        dumb_id = common_ldap.BaseLdap._dn_to_id(CONF.ldap.dumb_member)
        self.assertNotIn(dumb_id, assignment_ids)

    def test_list_user_ids_for_project_dumb_member(self):
        self.config_fixture.config(group='ldap', use_dumb_member=True)
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                'enabled': True, 'domain_id': test_backend.DEFAULT_DOMAIN_ID}

        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                user['id'])
        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_baz['id'])

        self.assertIn(user['id'], user_ids)

        dumb_id = common_ldap.BaseLdap._dn_to_id(CONF.ldap.dumb_member)
        self.assertNotIn(dumb_id, user_ids)

    def test_multi_group_grants_on_project_domain(self):
        self.skipTest('Blocked by bug 1101287')

    def test_list_group_members_missing_entry(self):
        """List group members with deleted user.

        If a group has a deleted entry for a member, the non-deleted members
        are returned.

        """

        # Create a group
        group = dict(name=uuid.uuid4().hex,
                     domain_id=CONF.identity.default_domain_id)
        group_id = self.identity_api.create_group(group)['id']

        # Create a couple of users and add them to the group.
        user = dict(name=uuid.uuid4().hex,
                    domain_id=CONF.identity.default_domain_id)
        user_1_id = self.identity_api.create_user(user)['id']

        self.identity_api.add_user_to_group(user_1_id, group_id)

        user = dict(name=uuid.uuid4().hex,
                    domain_id=CONF.identity.default_domain_id)
        user_2_id = self.identity_api.create_user(user)['id']

        self.identity_api.add_user_to_group(user_2_id, group_id)

        # Delete user 2
        # NOTE(blk-u): need to go directly to user interface to keep from
        # updating the group.
        unused, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(user_2_id))
        driver.user.delete(entity_id)

        # List group users and verify only user 1.
        res = self.identity_api.list_users_in_group(group_id)

        self.assertEqual(1, len(res), "Expected 1 entry (user_1)")
        self.assertEqual(user_1_id, res[0]['id'], "Expected user 1 id")

    def test_list_group_members_when_no_members(self):
        # List group members when there is no member in the group.
        # No exception should be raised.
        group = {
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex}
        group = self.identity_api.create_group(group)

        # If this doesn't raise, then the test is successful.
        self.identity_api.list_users_in_group(group['id'])

    def test_list_group_members_dumb_member(self):
        self.config_fixture.config(group='ldap', use_dumb_member=True)
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        # Create a group
        group = dict(name=uuid.uuid4().hex,
                     domain_id=CONF.identity.default_domain_id)
        group_id = self.identity_api.create_group(group)['id']

        # Create a user
        user = dict(name=uuid.uuid4().hex,
                    domain_id=CONF.identity.default_domain_id)
        user_id = self.identity_api.create_user(user)['id']

        # Add user to the group
        self.identity_api.add_user_to_group(user_id, group_id)

        user_ids = self.identity_api.list_users_in_group(group_id)
        dumb_id = common_ldap.BaseLdap._dn_to_id(CONF.ldap.dumb_member)

        self.assertNotIn(dumb_id, user_ids)

    def test_list_domains(self):
        domains = self.resource_api.list_domains()
        self.assertEqual(
            [resource.calc_default_domain()],
            domains)

    def test_list_domains_non_default_domain_id(self):
        # If change the default_domain_id, the ID of the default domain
        # returned by list_domains changes is the new default_domain_id.

        new_domain_id = uuid.uuid4().hex
        self.config_fixture.config(group='identity',
                                   default_domain_id=new_domain_id)

        domains = self.resource_api.list_domains()

        self.assertEqual(new_domain_id, domains[0]['id'])

    def test_authenticate_requires_simple_bind(self):
        user = {
            'name': 'NO_META',
            'domain_id': test_backend.DEFAULT_DOMAIN_ID,
            'password': 'no_meta2',
            'enabled': True,
        }
        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                user['id'])
        driver = self.identity_api._select_identity_driver(
            user['domain_id'])
        driver.user.LDAP_USER = None
        driver.user.LDAP_PASSWORD = None

        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password=None)

    # (spzala)The group and domain crud tests below override the standard ones
    # in test_backend.py so that we can exclude the update name test, since we
    # do not yet support the update of either group or domain names with LDAP.
    # In the tests below, the update is demonstrated by updating description.
    # Refer to bug 1136403 for more detail.
    def test_group_crud(self):
        group = {
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex}
        group = self.identity_api.create_group(group)
        group_ref = self.identity_api.get_group(group['id'])
        self.assertDictEqual(group_ref, group)
        group['description'] = uuid.uuid4().hex
        self.identity_api.update_group(group['id'], group)
        group_ref = self.identity_api.get_group(group['id'])
        self.assertDictEqual(group_ref, group)

        self.identity_api.delete_group(group['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group,
                          group['id'])

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_group_crud(self):
        group = {
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex}
        group = self.identity_api.create_group(group)
        # cache the result
        group_ref = self.identity_api.get_group(group['id'])
        # delete the group bypassing identity api.
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(group['id']))
        driver.delete_group(entity_id)

        self.assertEqual(group_ref,
                         self.identity_api.get_group(group['id']))
        self.identity_api.get_group.invalidate(self.identity_api, group['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group, group['id'])

        group = {
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex}
        group = self.identity_api.create_group(group)
        # cache the result
        self.identity_api.get_group(group['id'])
        group['description'] = uuid.uuid4().hex
        group_ref = self.identity_api.update_group(group['id'], group)
        self.assertDictContainsSubset(self.identity_api.get_group(group['id']),
                                      group_ref)

    def test_create_user_none_mapping(self):
        # When create a user where an attribute maps to None, the entry is
        # created without that attribute and it doesn't fail with a TypeError.
        driver = self.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.attribute_ignore = ['enabled', 'email',
                                        'tenants', 'tenantId']
        user = {'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                'default_project_id': 'maps_to_none',
                }

        # If this doesn't raise, then the test is successful.
        user = self.identity_api.create_user(user)

    def test_create_user_with_boolean_string_names(self):
        # Ensure that any attribute that is equal to the string 'TRUE'
        # or 'FALSE' will not be converted to a boolean value, it
        # should be returned as is.
        boolean_strings = ['TRUE', 'FALSE', 'true', 'false', 'True', 'False',
                           'TrUe' 'FaLse']
        for name in boolean_strings:
            user = {
                'name': name,
                'domain_id': CONF.identity.default_domain_id}
            user_ref = self.identity_api.create_user(user)
            user_info = self.identity_api.get_user(user_ref['id'])
            self.assertEqual(name, user_info['name'])
            # Delete the user to ensure  that the Keystone uniqueness
            # requirements combined with the case-insensitive nature of a
            # typical LDAP schema does not cause subsequent names in
            # boolean_strings to clash.
            self.identity_api.delete_user(user_ref['id'])

    def test_unignored_user_none_mapping(self):
        # Ensure that an attribute that maps to None that is not explicitly
        # ignored in configuration is implicitly ignored without triggering
        # an error.
        driver = self.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.attribute_ignore = ['enabled', 'email',
                                        'tenants', 'tenantId']

        user = {'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                }

        user_ref = self.identity_api.create_user(user)

        # If this doesn't raise, then the test is successful.
        self.identity_api.get_user(user_ref['id'])

    def test_update_user_name(self):
        """A user's name cannot be changed through the LDAP driver."""
        self.assertRaises(exception.Conflict,
                          super(BaseLDAPIdentity, self).test_update_user_name)

    def test_arbitrary_attributes_are_returned_from_get_user(self):
        self.skipTest("Using arbitrary attributes doesn't work under LDAP")

    def test_new_arbitrary_attributes_are_returned_from_update_user(self):
        self.skipTest("Using arbitrary attributes doesn't work under LDAP")

    def test_updated_arbitrary_attributes_are_returned_from_update_user(self):
        self.skipTest("Using arbitrary attributes doesn't work under LDAP")

    def test_cache_layer_domain_crud(self):
        # TODO(morganfainberg): This also needs to be removed when full LDAP
        # implementation is submitted.  No need to duplicate the above test,
        # just skip this time.
        self.skipTest('Domains are read-only against LDAP')

    def test_user_id_comma(self):
        """Even if the user has a , in their ID, groups can be listed."""

        # Create a user with a , in their ID
        # NOTE(blk-u): the DN for this user is hard-coded in fakeldap!

        # Since we want to fake up this special ID, we'll squirt this
        # direct into the driver and bypass the manager layer.
        user_id = u'Doe, John'
        user = {
            'id': user_id,
            'name': self.getUniqueString(),
            'password': self.getUniqueString(),
            'domain_id': CONF.identity.default_domain_id,
        }
        user = self.identity_api.driver.create_user(user_id, user)

        # Now we'll use the manager to discover it, which will create a
        # Public ID for it.
        ref_list = self.identity_api.list_users()
        public_user_id = None
        for ref in ref_list:
            if ref['name'] == user['name']:
                public_user_id = ref['id']
                break

        # Create a group
        group_id = uuid.uuid4().hex
        group = {
            'id': group_id,
            'name': self.getUniqueString(prefix='tuidc'),
            'description': self.getUniqueString(),
            'domain_id': CONF.identity.default_domain_id,
        }
        group = self.identity_api.driver.create_group(group_id, group)
        # Now we'll use the manager to discover it, which will create a
        # Public ID for it.
        ref_list = self.identity_api.list_groups()
        public_group_id = None
        for ref in ref_list:
            if ref['name'] == group['name']:
                public_group_id = ref['id']
                break

        # Put the user in the group
        self.identity_api.add_user_to_group(public_user_id, public_group_id)

        # List groups for user.
        ref_list = self.identity_api.list_groups_for_user(public_user_id)

        group['id'] = public_group_id
        self.assertThat(ref_list, matchers.Equals([group]))

    def test_user_id_comma_grants(self):
        """Even if the user has a , in their ID, can get user and group grants.
        """

        # Create a user with a , in their ID
        # NOTE(blk-u): the DN for this user is hard-coded in fakeldap!

        # Since we want to fake up this special ID, we'll squirt this
        # direct into the driver and bypass the manager layer
        user_id = u'Doe, John'
        user = {
            'id': user_id,
            'name': self.getUniqueString(),
            'password': self.getUniqueString(),
            'domain_id': CONF.identity.default_domain_id,
        }
        self.identity_api.driver.create_user(user_id, user)

        # Now we'll use the manager to discover it, which will create a
        # Public ID for it.
        ref_list = self.identity_api.list_users()
        public_user_id = None
        for ref in ref_list:
            if ref['name'] == user['name']:
                public_user_id = ref['id']
                break

        # Grant the user a role on a project.

        role_id = 'member'
        project_id = self.tenant_baz['id']

        self.assignment_api.create_grant(role_id, user_id=public_user_id,
                                         project_id=project_id)

        role_ref = self.assignment_api.get_grant(role_id,
                                                 user_id=public_user_id,
                                                 project_id=project_id)

        self.assertEqual(role_id, role_ref['id'])

    def test_user_enabled_ignored_disable_error(self):
        # When the server is configured so that the enabled attribute is
        # ignored for users, users cannot be disabled.

        self.config_fixture.config(group='ldap',
                                   user_attribute_ignore=['enabled'])

        # Need to re-load backends for the config change to take effect.
        self.load_backends()

        # Attempt to disable the user.
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.update_user, self.user_foo['id'],
                          {'enabled': False})

        user_info = self.identity_api.get_user(self.user_foo['id'])

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
        new_group = {'domain_id': new_domain['id'],
                     'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)

        # Attempt to disable the group.
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.update_group, new_group['id'],
                          {'enabled': False})

        group_info = self.identity_api.get_group(new_group['id'])

        # If 'enabled' is ignored then 'enabled' isn't returned as part of the
        # ref.
        self.assertNotIn('enabled', group_info)

    def test_project_enabled_ignored_disable_error(self):
        # When the server is configured so that the enabled attribute is
        # ignored for projects, projects cannot be disabled.

        self.config_fixture.config(group='ldap',
                                   project_attribute_ignore=['enabled'])

        # Need to re-load backends for the config change to take effect.
        self.load_backends()

        # Attempt to disable the project.
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.update_project,
                          self.tenant_baz['id'], {'enabled': False})

        project_info = self.resource_api.get_project(self.tenant_baz['id'])

        # Unlike other entities, if 'enabled' is ignored then 'enabled' is
        # returned as part of the ref.
        self.assertIs(True, project_info['enabled'])

    def test_list_role_assignment_by_domain(self):
        """Multiple domain assignments are not supported."""
        self.assertRaises(
            (exception.Forbidden, exception.DomainNotFound),
            super(BaseLDAPIdentity, self).test_list_role_assignment_by_domain)

    def test_list_role_assignment_by_user_with_domain_group_roles(self):
        """Multiple domain assignments are not supported."""
        self.assertRaises(
            (exception.Forbidden, exception.DomainNotFound),
            super(BaseLDAPIdentity, self).
            test_list_role_assignment_by_user_with_domain_group_roles)


class LDAPIdentity(BaseLDAPIdentity, unit.TestCase):

    def setUp(self):
        # NOTE(dstanek): The database must be setup prior to calling the
        # parent's setUp. The parent's setUp uses services (like
        # credentials) that require a database.
        self.useFixture(database.Database())
        super(LDAPIdentity, self).setUp()
        _assert_backends(self,
                         assignment='ldap',
                         identity='ldap',
                         resource='ldap')

    def load_fixtures(self, fixtures):
        # Override super impl since need to create group container.
        create_group_container(self.identity_api)
        super(LDAPIdentity, self).load_fixtures(fixtures)

    def test_configurable_allowed_project_actions(self):
        domain = self._get_domain_fixture()
        tenant = {'id': u'fäké1', 'name': u'fäké1', 'enabled': True,
                  'domain_id': domain['id']}
        self.resource_api.create_project(u'fäké1', tenant)
        tenant_ref = self.resource_api.get_project(u'fäké1')
        self.assertEqual(u'fäké1', tenant_ref['id'])

        tenant['enabled'] = False
        self.resource_api.update_project(u'fäké1', tenant)

        self.resource_api.delete_project(u'fäké1')
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          u'fäké1')

    def test_configurable_subtree_delete(self):
        self.config_fixture.config(group='ldap', allow_subtree_delete=True)
        self.load_backends()

        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': CONF.identity.default_domain_id}
        self.resource_api.create_project(project1['id'], project1)

        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role1['id'], role1)

        user1 = {'name': uuid.uuid4().hex,
                 'domain_id': CONF.identity.default_domain_id,
                 'password': uuid.uuid4().hex,
                 'enabled': True}
        user1 = self.identity_api.create_user(user1)

        self.assignment_api.add_role_to_user_and_project(
            user_id=user1['id'],
            tenant_id=project1['id'],
            role_id=role1['id'])

        self.resource_api.delete_project(project1['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project1['id'])

        self.resource_api.create_project(project1['id'], project1)

        list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'],
            project1['id'])
        self.assertEqual(0, len(list))

    def test_configurable_forbidden_project_actions(self):
        self.config_fixture.config(
            group='ldap', project_allow_create=False,
            project_allow_update=False, project_allow_delete=False)
        self.load_backends()

        domain = self._get_domain_fixture()
        tenant = {'id': u'fäké1', 'name': u'fäké1', 'domain_id': domain['id']}
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.create_project,
                          u'fäké1',
                          tenant)

        self.tenant_bar['enabled'] = False
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.update_project,
                          self.tenant_bar['id'],
                          self.tenant_bar)
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.delete_project,
                          self.tenant_bar['id'])

    def test_project_filter(self):
        tenant_ref = self.resource_api.get_project(self.tenant_bar['id'])
        self.assertDictEqual(tenant_ref, self.tenant_bar)

        self.config_fixture.config(group='ldap',
                                   project_filter='(CN=DOES_NOT_MATCH)')
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.project_filter  will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.role_api.get_role.invalidate(self.role_api,
                                          self.role_member['id'])
        self.role_api.get_role(self.role_member['id'])
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 self.tenant_bar['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          self.tenant_bar['id'])

    def test_dumb_member(self):
        self.config_fixture.config(group='ldap', use_dumb_member=True)
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        dumb_id = common_ldap.BaseLdap._dn_to_id(CONF.ldap.dumb_member)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          dumb_id)

    def test_project_attribute_mapping(self):
        self.config_fixture.config(
            group='ldap', project_name_attribute='ou',
            project_desc_attribute='description',
            project_enabled_attribute='enabled')
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.project_name_attribute,
        # CONF.ldap.project_desc_attribute, and
        # CONF.ldap.project_enabled_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 self.tenant_baz['id'])
        tenant_ref = self.resource_api.get_project(self.tenant_baz['id'])
        self.assertEqual(self.tenant_baz['id'], tenant_ref['id'])
        self.assertEqual(self.tenant_baz['name'], tenant_ref['name'])
        self.assertEqual(
            self.tenant_baz['description'],
            tenant_ref['description'])
        self.assertEqual(self.tenant_baz['enabled'], tenant_ref['enabled'])

        self.config_fixture.config(group='ldap',
                                   project_name_attribute='description',
                                   project_desc_attribute='ou')
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.project_name_attribute,
        # CONF.ldap.project_desc_attribute, and
        # CONF.ldap.project_enabled_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 self.tenant_baz['id'])
        tenant_ref = self.resource_api.get_project(self.tenant_baz['id'])
        self.assertEqual(self.tenant_baz['id'], tenant_ref['id'])
        self.assertEqual(self.tenant_baz['description'], tenant_ref['name'])
        self.assertEqual(self.tenant_baz['name'], tenant_ref['description'])
        self.assertEqual(self.tenant_baz['enabled'], tenant_ref['enabled'])

    def test_project_attribute_ignore(self):
        self.config_fixture.config(
            group='ldap',
            project_attribute_ignore=['name', 'description', 'enabled'])
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.project_attribute_ignore will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change configs values in tests
        # that could affect what the drivers would return up to the manager.
        # This solves this assumption when working with aggressive (on-create)
        # cache population.
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 self.tenant_baz['id'])
        tenant_ref = self.resource_api.get_project(self.tenant_baz['id'])
        self.assertEqual(self.tenant_baz['id'], tenant_ref['id'])
        self.assertNotIn('name', tenant_ref)
        self.assertNotIn('description', tenant_ref)
        self.assertNotIn('enabled', tenant_ref)

    def test_user_enable_attribute_mask(self):
        self.config_fixture.config(group='ldap', user_enabled_mask=2,
                                   user_enabled_default='512')
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        user = {'name': u'fäké1', 'enabled': True,
                'domain_id': CONF.identity.default_domain_id}

        user_ref = self.identity_api.create_user(user)

        # Use assertIs rather than assertTrue because assertIs will assert the
        # value is a Boolean as expected.
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([512], enabled_vals)

        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

        user['enabled'] = False
        user_ref = self.identity_api.update_user(user_ref['id'], user)
        self.assertIs(user_ref['enabled'], False)
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([514], enabled_vals)

        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(user_ref['enabled'], False)
        self.assertNotIn('enabled_nomask', user_ref)

        user['enabled'] = True
        user_ref = self.identity_api.update_user(user_ref['id'], user)
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([512], enabled_vals)

        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

    def test_user_enabled_invert(self):
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_default=False)
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        user1 = {'name': u'fäké1', 'enabled': True,
                 'domain_id': CONF.identity.default_domain_id}

        user2 = {'name': u'fäké2', 'enabled': False,
                 'domain_id': CONF.identity.default_domain_id}

        user3 = {'name': u'fäké3',
                 'domain_id': CONF.identity.default_domain_id}

        # Ensure that the LDAP attribute is False for a newly created
        # enabled user.
        user_ref = self.identity_api.create_user(user1)
        self.assertIs(True, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([False], enabled_vals)
        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

        # Ensure that the LDAP attribute is True for a disabled user.
        user1['enabled'] = False
        user_ref = self.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(False, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([True], enabled_vals)

        # Enable the user and ensure that the LDAP attribute is True again.
        user1['enabled'] = True
        user_ref = self.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(True, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([False], enabled_vals)

        # Ensure that the LDAP attribute is True for a newly created
        # disabled user.
        user_ref = self.identity_api.create_user(user2)
        self.assertIs(False, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([True], enabled_vals)
        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(False, user_ref['enabled'])

        # Ensure that the LDAP attribute is inverted for a newly created
        # user when the user_enabled_default setting is used.
        user_ref = self.identity_api.create_user(user3)
        self.assertIs(True, user_ref['enabled'])
        enabled_vals = self.get_user_enabled_vals(user_ref)
        self.assertEqual([False], enabled_vals)
        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
    def test_user_enabled_invert_no_enabled_value(self, mock_ldap_get):
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_default=False)
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
        self.assertIs(not CONF.ldap.user_enabled_default, user_ref['enabled'])

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
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

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
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

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
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

    @mock.patch.object(common_ldap_core.KeystoneLDAPHandler, 'simple_bind_s')
    def test_user_api_get_connection_no_user_password(self, mocked_method):
        """Don't bind in case the user and password are blank."""
        # Ensure the username/password are in-fact blank
        self.config_fixture.config(group='ldap', user=None, password=None)
        user_api = identity.backends.ldap.UserApi(CONF)
        user_api.get_connection(user=None, password=None)
        self.assertFalse(mocked_method.called,
                         msg='`simple_bind_s` method was unexpectedly called')

    @mock.patch.object(common_ldap_core.KeystoneLDAPHandler, 'connect')
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

    @mock.patch.object(common_ldap_core.KeystoneLDAPHandler, 'connect')
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

    @mock.patch.object(common_ldap_core.KeystoneLDAPHandler, 'connect')
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

    def test_wrong_ldap_scope(self):
        self.config_fixture.config(group='ldap', query_scope=uuid.uuid4().hex)
        self.assertRaisesRegexp(
            ValueError,
            'Invalid LDAP scope: %s. *' % CONF.ldap.query_scope,
            identity.backends.ldap.Identity)

    def test_wrong_alias_dereferencing(self):
        self.config_fixture.config(group='ldap',
                                   alias_dereferencing=uuid.uuid4().hex)
        self.assertRaisesRegexp(
            ValueError,
            'Invalid LDAP deref option: %s\.' % CONF.ldap.alias_dereferencing,
            identity.backends.ldap.Identity)

    def test_is_dumb_member(self):
        self.config_fixture.config(group='ldap',
                                   use_dumb_member=True)
        self.load_backends()

        dn = 'cn=dumb,dc=nonexistent'
        self.assertTrue(self.identity_api.driver.user._is_dumb_member(dn))

    def test_is_dumb_member_upper_case_keys(self):
        self.config_fixture.config(group='ldap',
                                   use_dumb_member=True)
        self.load_backends()

        dn = 'CN=dumb,DC=nonexistent'
        self.assertTrue(self.identity_api.driver.user._is_dumb_member(dn))

    def test_is_dumb_member_with_false_use_dumb_member(self):
        self.config_fixture.config(group='ldap',
                                   use_dumb_member=False)
        self.load_backends()
        dn = 'cn=dumb,dc=nonexistent'
        self.assertFalse(self.identity_api.driver.user._is_dumb_member(dn))

    def test_is_dumb_member_not_dumb(self):
        self.config_fixture.config(group='ldap',
                                   use_dumb_member=True)
        self.load_backends()
        dn = 'ou=some,dc=example.com'
        self.assertFalse(self.identity_api.driver.user._is_dumb_member(dn))

    def test_user_extra_attribute_mapping(self):
        self.config_fixture.config(
            group='ldap',
            user_additional_attribute_mapping=['description:name'])
        self.load_backends()
        user = {
            'name': 'EXTRA_ATTRIBUTES',
            'password': 'extra',
            'domain_id': CONF.identity.default_domain_id
        }
        user = self.identity_api.create_user(user)
        dn, attrs = self.identity_api.driver.user._ldap_get(user['id'])
        self.assertThat([user['name']], matchers.Equals(attrs['description']))

    def test_user_extra_attribute_mapping_description_is_returned(self):
        # Given a mapping like description:description, the description is
        # returned.

        self.config_fixture.config(
            group='ldap',
            user_additional_attribute_mapping=['description:description'])
        self.load_backends()

        description = uuid.uuid4().hex
        user = {
            'name': uuid.uuid4().hex,
            'description': description,
            'password': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id
        }
        user = self.identity_api.create_user(user)
        res = self.identity_api.driver.user.get_all()

        new_user = [u for u in res if u['id'] == user['id']][0]
        self.assertThat(new_user['description'], matchers.Equals(description))

    def test_user_with_missing_id(self):
        # create a user that doesn't have the id attribute
        ldap_ = self.identity_api.driver.user.get_connection()
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
        users = self.identity_api.driver.user.get_all()
        self.assertThat(users, matchers.HasLength(len(default_fixtures.USERS)))

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
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
        user = self.identity_api.get_user('junk')
        self.assertEqual(mock_ldap_get.return_value[1]['sN'][0],
                         user['name'])
        self.assertEqual(mock_ldap_get.return_value[1]['MaIl'][0],
                         user['email'])

    def test_parse_extra_attribute_mapping(self):
        option_list = ['description:name', 'gecos:password',
                       'fake:invalid', 'invalid1', 'invalid2:',
                       'description:name:something']
        mapping = self.identity_api.driver.user._parse_extra_attrs(option_list)
        expected_dict = {'description': 'name', 'gecos': 'password',
                         'fake': 'invalid', 'invalid2': ''}
        self.assertDictEqual(expected_dict, mapping)

# TODO(henry-nash): These need to be removed when the full LDAP implementation
# is submitted - see Bugs 1092187, 1101287, 1101276, 1101289

    def test_domain_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True, 'description': uuid.uuid4().hex}
        self.assertRaises(exception.Forbidden,
                          self.resource_api.create_domain,
                          domain['id'],
                          domain)
        self.assertRaises(exception.Conflict,
                          self.resource_api.create_domain,
                          CONF.identity.default_domain_id,
                          domain)
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])

        domain['description'] = uuid.uuid4().hex
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.update_domain,
                          domain['id'],
                          domain)
        self.assertRaises(exception.Forbidden,
                          self.resource_api.update_domain,
                          CONF.identity.default_domain_id,
                          domain)
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.delete_domain,
                          domain['id'])
        self.assertRaises(exception.Forbidden,
                          self.resource_api.delete_domain,
                          CONF.identity.default_domain_id)
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])

    @unit.skip_if_no_multiple_domains_support
    def test_create_domain_case_sensitivity(self):
        # domains are read-only, so case sensitivity isn't an issue
        ref = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex}
        self.assertRaises(exception.Forbidden,
                          self.resource_api.create_domain,
                          ref['id'],
                          ref)

    def test_cache_layer_domain_crud(self):
        # TODO(morganfainberg): This also needs to be removed when full LDAP
        # implementation is submitted.  No need to duplicate the above test,
        # just skip this time.
        self.skipTest('Domains are read-only against LDAP')

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
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': CONF.identity.default_domain_id,
                   'description': uuid.uuid4().hex,
                   'enabled': True,
                   'parent_id': None,
                   'is_domain': False}
        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])

        self.assertDictEqual(project_ref, project)

        project['description'] = uuid.uuid4().hex
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project_ref, project)

        self.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project['id'])

    @unit.skip_if_cache_disabled('assignment')
    def test_cache_layer_project_crud(self):
        # NOTE(morganfainberg): LDAP implementation does not currently support
        # updating project names.  This method override provides a different
        # update test.
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': CONF.identity.default_domain_id,
                   'description': uuid.uuid4().hex}
        project_id = project['id']
        # Create a project
        self.resource_api.create_project(project_id, project)
        self.resource_api.get_project(project_id)
        updated_project = copy.deepcopy(project)
        updated_project['description'] = uuid.uuid4().hex
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
        # Delete project bypassing resource_api
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

    def _assert_create_hierarchy_not_allowed(self):
        domain = self._get_domain_fixture()

        project1 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'description': '',
                    'domain_id': domain['id'],
                    'enabled': True,
                    'parent_id': None,
                    'is_domain': False}
        self.resource_api.create_project(project1['id'], project1)

        # Creating project2 under project1. LDAP will not allow
        # the creation of a project with parent_id being set
        project2 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'description': '',
                    'domain_id': domain['id'],
                    'enabled': True,
                    'parent_id': project1['id'],
                    'is_domain': False}

        self.assertRaises(exception.InvalidParentProject,
                          self.resource_api.create_project,
                          project2['id'],
                          project2)

        # Now, we'll create project 2 with no parent
        project2['parent_id'] = None
        self.resource_api.create_project(project2['id'], project2)

        # Returning projects to be used across the tests
        return [project1, project2]

    def _assert_create_is_domain_project_not_allowed(self):
        """Tests that we can't create more than one project acting as domain.

        This method will be used at any test that require the creation of a
        project that act as a domain. LDAP does not support multiple domains
        and the only domain it has (default) is immutable.
        """
        domain = self._get_domain_fixture()
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'description': '',
                   'domain_id': domain['id'],
                   'enabled': True,
                   'parent_id': None,
                   'is_domain': True}

        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'], project)

    def test_update_is_domain_field(self):
        domain = self._get_domain_fixture()
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'description': '',
                   'domain_id': domain['id'],
                   'enabled': True,
                   'parent_id': None,
                   'is_domain': False}
        self.resource_api.create_project(project['id'], project)

        # Try to update the is_domain field to True
        project['is_domain'] = True
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'], project)

    def test_delete_is_domain_project(self):
        self._assert_create_is_domain_project_not_allowed()

    def test_create_domain_under_regular_project_hierarchy_fails(self):
        self._assert_create_hierarchy_not_allowed()

    def test_create_not_is_domain_project_under_is_domain_hierarchy(self):
        self._assert_create_hierarchy_not_allowed()

    def test_create_is_domain_project(self):
        self._assert_create_is_domain_project_not_allowed()

    def test_create_project_with_parent_id_and_without_domain_id(self):
        self._assert_create_hierarchy_not_allowed()

    def test_check_leaf_projects(self):
        projects = self._assert_create_hierarchy_not_allowed()
        for project in projects:
            self.assertTrue(self.resource_api.is_leaf_project(project))

    def test_list_projects_in_subtree(self):
        projects = self._assert_create_hierarchy_not_allowed()
        for project in projects:
            subtree_list = self.resource_api.list_projects_in_subtree(
                project['id'])
            self.assertEqual(0, len(subtree_list))

    def test_list_projects_in_subtree_with_circular_reference(self):
        self._assert_create_hierarchy_not_allowed()

    def test_list_project_parents(self):
        projects = self._assert_create_hierarchy_not_allowed()
        for project in projects:
            parents_list = self.resource_api.list_project_parents(
                project['id'])
            self.assertEqual(0, len(parents_list))

    def test_hierarchical_projects_crud(self):
        self._assert_create_hierarchy_not_allowed()

    def test_create_project_under_disabled_one(self):
        self._assert_create_hierarchy_not_allowed()

    def test_create_project_with_invalid_parent(self):
        self._assert_create_hierarchy_not_allowed()

    def test_create_leaf_project_with_invalid_domain(self):
        self._assert_create_hierarchy_not_allowed()

    def test_update_project_parent(self):
        self._assert_create_hierarchy_not_allowed()

    def test_enable_project_with_disabled_parent(self):
        self._assert_create_hierarchy_not_allowed()

    def test_disable_hierarchical_leaf_project(self):
        self._assert_create_hierarchy_not_allowed()

    def test_disable_hierarchical_not_leaf_project(self):
        self._assert_create_hierarchy_not_allowed()

    def test_delete_hierarchical_leaf_project(self):
        self._assert_create_hierarchy_not_allowed()

    def test_delete_hierarchical_not_leaf_project(self):
        self._assert_create_hierarchy_not_allowed()

    def test_check_hierarchy_depth(self):
        projects = self._assert_create_hierarchy_not_allowed()
        for project in projects:
            depth = self._get_hierarchy_depth(project['id'])
            self.assertEqual(1, depth)

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        # This is a partial implementation of the standard test that
        # is defined in test_backend.py.  It omits both domain and
        # group grants. since neither of these are yet supported by
        # the ldap backend.

        role_list = []
        for _ in range(2):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        user1 = {'name': uuid.uuid4().hex,
                 'domain_id': CONF.identity.default_domain_id,
                 'password': uuid.uuid4().hex,
                 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': CONF.identity.default_domain_id}
        self.resource_api.create_project(project1['id'], project1)

        self.assignment_api.add_role_to_user_and_project(
            user_id=user1['id'],
            tenant_id=project1['id'],
            role_id=role_list[0]['id'])
        self.assignment_api.add_role_to_user_and_project(
            user_id=user1['id'],
            tenant_id=project1['id'],
            role_id=role_list[1]['id'])

        # Although list_grants are not yet supported, we can test the
        # alternate way of getting back lists of grants, where user
        # and group roles are combined.  Only directly assigned user
        # roles are available, since group grants are not yet supported

        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'],
            project1['id'])
        self.assertEqual(2, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)
        self.assertIn(role_list[1]['id'], combined_list)

        # Finally, although domain roles are not implemented, check we can
        # issue the combined get roles call with benign results, since thus is
        # used in token generation

        combined_role_list = self.assignment_api.get_roles_for_user_and_domain(
            user1['id'], CONF.identity.default_domain_id)
        self.assertEqual(0, len(combined_role_list))

    def test_list_projects_for_alternate_domain(self):
        self.skipTest(
            'N/A: LDAP does not support multiple domains')

    def test_get_default_domain_by_name(self):
        domain = self._get_domain_fixture()

        domain_ref = self.resource_api.get_domain_by_name(domain['name'])
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
        users = self.identity_api.list_users()
        self.assertEqual(len(default_fixtures.USERS), len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['id'])['id']
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
            group = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
            group = self.identity_api.create_group(group)
            expected_group_ids.append(group['id'])
        # Fetch the test groups and ensure that they don't contain a dn.
        groups = self.identity_api.list_groups()
        self.assertEqual(numgroups, len(groups))
        group_ids = set(group['id'] for group in groups)
        for group_ref in groups:
            self.assertNotIn('dn', group_ref)
        self.assertEqual(set(expected_group_ids), group_ids)

    def test_list_groups_for_user_no_dn(self):
        # Create a test user.
        user = {'name': uuid.uuid4().hex,
                'domain_id': CONF.identity.default_domain_id,
                'password': uuid.uuid4().hex, 'enabled': True}
        user = self.identity_api.create_user(user)
        # Create some test groups and add the test user as a member.
        domain = self._get_domain_fixture()
        expected_group_ids = []
        numgroups = 3
        for _ in range(numgroups):
            group = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
            group = self.identity_api.create_group(group)
            expected_group_ids.append(group['id'])
            self.identity_api.add_user_to_group(user['id'], group['id'])
        # Fetch the groups for the test user
        # and ensure they don't contain a dn.
        groups = self.identity_api.list_groups_for_user(user['id'])
        self.assertEqual(numgroups, len(groups))
        group_ids = set(group['id'] for group in groups)
        for group_ref in groups:
            self.assertNotIn('dn', group_ref)
        self.assertEqual(set(expected_group_ids), group_ids)

    def test_user_id_attribute_in_create(self):
        driver = self.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'mail'

        user = {'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id}
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        # 'email' attribute should've created because it is also being used
        # as user_id
        self.assertEqual(user_ref['id'], user_ref['email'])

    def test_user_id_attribute_map(self):
        driver = self.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.id_attr = 'mail'

        user_ref = self.identity_api.get_user(self.user_foo['email'])
        # the user_id_attribute map should be honored, which means
        # user_ref['id'] should contains the email attribute
        self.assertEqual(self.user_foo['email'], user_ref['id'])

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
    def test_get_id_from_dn_for_multivalued_attribute_id(self, mock_ldap_get):
        driver = self.identity_api._select_identity_driver(
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

        user_ref = self.identity_api.get_user(email1)
        # make sure we get the ID from DN (old behavior) if the ID attribute
        # has multiple values
        self.assertEqual('nobodycares', user_ref['id'])

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
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

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
    def test_user_id_not_in_dn(self, mock_ldap_get):
        driver = self.identity_api._select_identity_driver(
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
        user_ref = self.identity_api.get_user('crap')
        self.assertEqual('crap', user_ref['id'])
        self.assertEqual('junk', user_ref['name'])

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
    def test_user_name_in_dn(self, mock_ldap_get):
        driver = self.identity_api._select_identity_driver(
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
        user_ref = self.identity_api.get_user('crap')
        self.assertEqual('crap', user_ref['id'])
        self.assertEqual('Foo Bar', user_ref['name'])


class LDAPIdentityEnabledEmulation(LDAPIdentity):
    def setUp(self):
        super(LDAPIdentityEnabledEmulation, self).setUp()
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        for obj in [self.tenant_bar, self.tenant_baz, self.user_foo,
                    self.user_two, self.user_badguy]:
            obj.setdefault('enabled', True)
        _assert_backends(self,
                         assignment='ldap',
                         identity='ldap',
                         resource='ldap')

    def load_fixtures(self, fixtures):
        # Override super impl since need to create group container.
        create_group_container(self.identity_api)
        super(LDAPIdentity, self).load_fixtures(fixtures)

    def config_files(self):
        config_files = super(LDAPIdentityEnabledEmulation, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def config_overrides(self):
        super(LDAPIdentityEnabledEmulation, self).config_overrides()
        self.config_fixture.config(group='ldap',
                                   user_enabled_emulation=True,
                                   project_enabled_emulation=True)

    def test_project_crud(self):
        # NOTE(topol): LDAPIdentityEnabledEmulation will create an
        #              enabled key in the project dictionary so this
        #              method override handles this side-effect
        project = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'description': uuid.uuid4().hex,
            'parent_id': None,
            'is_domain': False}

        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])

        # self.resource_api.create_project adds an enabled
        # key with a value of True when LDAPIdentityEnabledEmulation
        # is used so we now add this expected key to the project dictionary
        project['enabled'] = True
        self.assertDictEqual(project_ref, project)

        project['description'] = uuid.uuid4().hex
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project_ref, project)

        self.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project['id'])

    def test_user_crud(self):
        user_dict = {
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'password': uuid.uuid4().hex}
        user = self.identity_api.create_user(user_dict)
        user_dict['enabled'] = True
        user_ref = self.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertDictContainsSubset(user_dict, user_ref_dict)

        user_dict['password'] = uuid.uuid4().hex
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertDictContainsSubset(user_dict, user_ref_dict)

        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])

    def test_user_auth_emulated(self):
        driver = self.identity_api._select_identity_driver(
            CONF.identity.default_domain_id)
        driver.user.enabled_emulation_dn = 'cn=test,dc=test'
        self.identity_api.authenticate(
            context={},
            user_id=self.user_foo['id'],
            password=self.user_foo['password'])

    def test_user_enable_attribute_mask(self):
        self.skipTest(
            "Enabled emulation conflicts with enabled mask")

    def test_user_enabled_invert(self):
        self.config_fixture.config(group='ldap', user_enabled_invert=True,
                                   user_enabled_default=False)
        self.ldapdb.clear()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        user1 = {'name': u'fäké1', 'enabled': True,
                 'domain_id': CONF.identity.default_domain_id}

        user2 = {'name': u'fäké2', 'enabled': False,
                 'domain_id': CONF.identity.default_domain_id}

        user3 = {'name': u'fäké3',
                 'domain_id': CONF.identity.default_domain_id}

        # Ensure that the enabled LDAP attribute is not set for a
        # newly created enabled user.
        user_ref = self.identity_api.create_user(user1)
        self.assertIs(True, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))
        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

        # Ensure that an enabled LDAP attribute is not set for a disabled user.
        user1['enabled'] = False
        user_ref = self.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(False, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))

        # Enable the user and ensure that the LDAP enabled
        # attribute is not set.
        user1['enabled'] = True
        user_ref = self.identity_api.update_user(user_ref['id'], user1)
        self.assertIs(True, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))

        # Ensure that the LDAP enabled attribute is not set for a
        # newly created disabled user.
        user_ref = self.identity_api.create_user(user2)
        self.assertIs(False, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))
        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(False, user_ref['enabled'])

        # Ensure that the LDAP enabled attribute is not set for a newly created
        # user when the user_enabled_default setting is used.
        user_ref = self.identity_api.create_user(user3)
        self.assertIs(True, user_ref['enabled'])
        self.assertIsNone(self.get_user_enabled_vals(user_ref))
        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertIs(True, user_ref['enabled'])

    def test_user_enabled_invert_no_enabled_value(self):
        self.skipTest(
            "N/A: Covered by test_user_enabled_invert")

    def test_user_enabled_invert_default_str_value(self):
        self.skipTest(
            "N/A: Covered by test_user_enabled_invert")

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
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


class LdapIdentitySqlAssignment(BaseLDAPIdentity, unit.SQLDriverOverrides,
                                unit.TestCase):

    def config_files(self):
        config_files = super(LdapIdentitySqlAssignment, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap_sql.conf'))
        return config_files

    def setUp(self):
        sqldb = self.useFixture(database.Database())
        super(LdapIdentitySqlAssignment, self).setUp()
        self.ldapdb.clear()
        self.load_backends()
        cache.configure_cache_region(cache.REGION)

        sqldb.recreate()
        self.load_fixtures(default_fixtures)
        # defaulted by the data load
        self.user_foo['enabled'] = True
        _assert_backends(self,
                         assignment='sql',
                         identity='ldap',
                         resource='sql')

    def config_overrides(self):
        super(LdapIdentitySqlAssignment, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='resource', driver='sql')
        self.config_fixture.config(group='assignment', driver='sql')

    def test_domain_crud(self):
        pass

    def test_list_domains(self):
        domains = self.resource_api.list_domains()
        self.assertEqual([resource.calc_default_domain()], domains)

    def test_list_domains_non_default_domain_id(self):
        # If change the default_domain_id, the ID of the default domain
        # returned by list_domains doesn't change because the SQL identity
        # backend reads it from the database, which doesn't get updated by
        # config change.

        orig_default_domain_id = CONF.identity.default_domain_id

        new_domain_id = uuid.uuid4().hex
        self.config_fixture.config(group='identity',
                                   default_domain_id=new_domain_id)

        domains = self.resource_api.list_domains()

        self.assertEqual(orig_default_domain_id, domains[0]['id'])

    def test_create_domain(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        self.assertRaises(exception.Forbidden,
                          self.resource_api.create_domain,
                          domain['id'],
                          domain)

    def test_get_and_remove_role_grant_by_group_and_domain(self):
        # TODO(henry-nash): We should really rewrite the tests in test_backend
        # to be more flexible as to where the domains are sourced from, so
        # that we would not need to override such tests here. This is raised
        # as bug 1373865.
        new_domain = self._get_domain_fixture()
        new_group = {'domain_id': new_domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': new_domain['id']}
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
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.assignment_api.delete_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.NotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_project_enabled_ignored_disable_error(self):
        # Override
        self.skipTest("Doesn't apply since LDAP configuration is ignored for "
                      "SQL assignment backend.")

    def test_list_role_assignments_filtered_by_role(self):
        # Domain roles are supported by the SQL Assignment backend
        base = super(BaseLDAPIdentity, self)
        base.test_list_role_assignments_filtered_by_role()


class LdapIdentitySqlAssignmentWithMapping(LdapIdentitySqlAssignment):
    """Class to test mapping of default LDAP backend.

    The default configuration is not to enable mapping when using a single
    backend LDAP driver.  However, a cloud provider might want to enable
    the mapping, hence hiding the LDAP IDs from any clients of keystone.
    Setting backward_compatible_ids to False will enable this mapping.

    """
    def config_overrides(self):
        super(LdapIdentitySqlAssignmentWithMapping, self).config_overrides()
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
        user1 = {'name': uuid.uuid4().hex,
                 'domain_id': CONF.identity.default_domain_id,
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        user2 = {'name': uuid.uuid4().hex,
                 'domain_id': CONF.identity.default_domain_id,
                 'password': uuid.uuid4().hex, 'enabled': True}
        user2 = self.identity_api.create_user(user2)
        mappings = mapping_sql.list_id_mappings()
        self.assertEqual(initial_mappings + 2, len(mappings))

        # Now delete the mappings for the two users above
        self.id_mapping_api.purge_mappings({'public_id': user1['id']})
        self.id_mapping_api.purge_mappings({'public_id': user2['id']})

        # We should no longer be able to get these users via their old IDs
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user1['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user2['id'])

        # Now enumerate all users...this should re-build the mapping, and
        # we should be able to find the users via their original public IDs.
        self.identity_api.list_users()
        self.identity_api.get_user(user1['id'])
        self.identity_api.get_user(user2['id'])

    def test_get_roles_for_user_and_project_user_group_same_id(self):
        self.skipTest('N/A: We never generate the same ID for a user and '
                      'group in our mapping table')


class BaseMultiLDAPandSQLIdentity(object):
    """Mixin class with support methods for domain-specific config testing."""

    def create_user(self, domain_id):
        user = {'name': uuid.uuid4().hex,
                'domain_id': domain_id,
                'password': uuid.uuid4().hex,
                'enabled': True}
        user_ref = self.identity_api.create_user(user)
        # Put the password back in, since this is used later by tests to
        # authenticate.
        user_ref['password'] = user['password']
        return user_ref

    def create_users_across_domains(self):
        """Create a set of users, each with a role on their own domain."""

        # We also will check that the right number of id mappings get created
        initial_mappings = len(mapping_sql.list_id_mappings())

        self.users['user0'] = self.create_user(
            self.domains['domain_default']['id'])
        self.assignment_api.create_grant(
            user_id=self.users['user0']['id'],
            domain_id=self.domains['domain_default']['id'],
            role_id=self.role_member['id'])
        for x in range(1, self.domain_count):
            self.users['user%s' % x] = self.create_user(
                self.domains['domain%s' % x]['id'])
            self.assignment_api.create_grant(
                user_id=self.users['user%s' % x]['id'],
                domain_id=self.domains['domain%s' % x]['id'],
                role_id=self.role_member['id'])

        # So how many new id mappings should have been created? One for each
        # user created in a domain that is using the non default driver..
        self.assertEqual(initial_mappings + self.domain_specific_count,
                         len(mapping_sql.list_id_mappings()))

    def check_user(self, user, domain_id, expected_status):
        """Check user is in correct backend.

        As part of the tests, we want to force ourselves to manually
        select the driver for a given domain, to make sure the entity
        ended up in the correct backend.

        """
        driver = self.identity_api._select_identity_driver(domain_id)
        unused, unused, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(
                user['id']))

        if expected_status == 200:
            ref = driver.get_user(entity_id)
            ref = self.identity_api._set_domain_id_and_mapping(
                ref, domain_id, driver, map.EntityType.USER)
            user = user.copy()
            del user['password']
            self.assertDictEqual(ref, user)
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
                ref = self.resource_api.create_domain(
                    domain['id'], domain)
            except exception.Conflict:
                ref = (
                    self.resource_api.get_domain_by_name(domain['name']))
            return ref

        self.domains = {}
        for x in range(1, self.domain_count):
            domain = 'domain%s' % x
            self.domains[domain] = create_domain(
                {'id': uuid.uuid4().hex, 'name': domain})
        self.domains['domain_default'] = create_domain(
            resource.calc_default_domain())

    def test_authenticate_to_each_domain(self):
        """Test that a user in each domain can authenticate."""
        for user_num in range(self.domain_count):
            user = 'user%s' % user_num
            self.identity_api.authenticate(
                context={},
                user_id=self.users[user]['id'],
                password=self.users[user]['password'])


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
    def setUp(self):
        sqldb = self.useFixture(database.Database())
        super(MultiLDAPandSQLIdentity, self).setUp()

        self.load_backends()
        sqldb.recreate()

        self.domain_count = 5
        self.domain_specific_count = 3
        self.setup_initial_domains()
        self._setup_initial_users()

        # All initial test data setup complete, time to switch on support
        # for separate backends per domain.
        self.enable_multi_domain()

        self.ldapdb.clear()
        self.load_fixtures(default_fixtures)
        self.create_users_across_domains()
        self.assert_backends()

    def assert_backends(self):
        _assert_backends(self,
                         assignment='sql',
                         identity={
                             None: 'sql',
                             self.domains['domain_default']['id']: 'ldap',
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

    def _setup_initial_users(self):
        # Create some identity entities BEFORE we switch to multi-backend, so
        # we can test that these are still accessible
        self.users = {}
        self.users['userA'] = self.create_user(
            self.domains['domain_default']['id'])
        self.users['userB'] = self.create_user(
            self.domains['domain1']['id'])
        self.users['userC'] = self.create_user(
            self.domains['domain3']['id'])

    def enable_multi_domain(self):
        """Enable the chosen form of multi domain configuration support.

        This method enables the file-based configuration support. Child classes
        that wish to use the database domain configuration support should
        override this method and set the appropriate config_fixture option.

        """
        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_config_dir=unit.TESTCONF + '/domain_configs_multi_ldap')
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def get_config(self, domain_id):
        # Get the config for this domain, will return CONF
        # if no specific config defined for this domain
        return self.identity_api.domain_configs.get_domain_conf(domain_id)

    def test_list_domains(self):
        self.skipTest(
            'N/A: Not relevant for multi ldap testing')

    def test_list_domains_non_default_domain_id(self):
        self.skipTest(
            'N/A: Not relevant for multi ldap testing')

    def test_list_users(self):
        # Override the standard list users, since we have added an extra user
        # to the default domain, so the number of expected users is one more
        # than in the standard test.
        users = self.identity_api.list_users(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(len(default_fixtures.USERS) + 1, len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['id'])['id']
                                for user in default_fixtures.USERS)
        expected_user_ids.add(self.users['user0']['id'])
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
        # Check that I can read a user with the appropriate domain-selected
        # driver, but won't find it via any other domain driver

        check_user = self.check_user
        check_user(self.users['user0'],
                   self.domains['domain_default']['id'], 200)
        for domain in [self.domains['domain1']['id'],
                       self.domains['domain2']['id'],
                       self.domains['domain3']['id'],
                       self.domains['domain4']['id']]:
            check_user(self.users['user0'], domain, exception.UserNotFound)

        check_user(self.users['user1'], self.domains['domain1']['id'], 200)
        for domain in [self.domains['domain_default']['id'],
                       self.domains['domain2']['id'],
                       self.domains['domain3']['id'],
                       self.domains['domain4']['id']]:
            check_user(self.users['user1'], domain, exception.UserNotFound)

        check_user(self.users['user2'], self.domains['domain2']['id'], 200)
        for domain in [self.domains['domain_default']['id'],
                       self.domains['domain1']['id'],
                       self.domains['domain3']['id'],
                       self.domains['domain4']['id']]:
            check_user(self.users['user2'], domain, exception.UserNotFound)

        # domain3 and domain4 share the same backend, so you should be
        # able to see user3 and user4 from either.

        check_user(self.users['user3'], self.domains['domain3']['id'], 200)
        check_user(self.users['user3'], self.domains['domain4']['id'], 200)
        check_user(self.users['user4'], self.domains['domain3']['id'], 200)
        check_user(self.users['user4'], self.domains['domain4']['id'], 200)

        for domain in [self.domains['domain_default']['id'],
                       self.domains['domain1']['id'],
                       self.domains['domain2']['id']]:
            check_user(self.users['user3'], domain, exception.UserNotFound)
            check_user(self.users['user4'], domain, exception.UserNotFound)

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
                self.identity_api.list_users(domain_scope=domain),
                matchers.HasLength(1))

        # domain3 had a user created before we switched on
        # multiple backends, plus one created afterwards - and its
        # backend has not changed - so we should find two.
        self.assertThat(
            self.identity_api.list_users(
                domain_scope=self.domains['domain3']['id']),
            matchers.HasLength(2))

    def test_existing_uuids_work(self):
        """Test that 'uni-domain' created IDs still work.

        Throwing the switch to domain-specific backends should not cause
        existing identities to be inaccessible via ID.

        """
        self.identity_api.get_user(self.users['userA']['id'])
        self.identity_api.get_user(self.users['userB']['id'])
        self.identity_api.get_user(self.users['userC']['id'])

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
        self.identity_api.list_users(
            domain_scope=self.domains['domain1']['id'])
        # ...and now check the domain configs have been set up
        self.assertIn('default', self.identity_api.domain_configs)
        self.assertIn(self.domains['domain1']['id'],
                      self.identity_api.domain_configs)
        self.assertIn(self.domains['domain2']['id'],
                      self.identity_api.domain_configs)
        self.assertNotIn(self.domains['domain3']['id'],
                         self.identity_api.domain_configs)
        self.assertNotIn(self.domains['domain4']['id'],
                         self.identity_api.domain_configs)

        # Finally check that a domain specific config contains items from both
        # the primary config and the domain specific config
        conf = self.identity_api.domain_configs.get_domain_conf(
            self.domains['domain1']['id'])
        # This should now be false, as is the default, since this is not
        # set in the standard primary config file
        self.assertFalse(conf.identity.domain_specific_drivers_enabled)
        # ..and make sure a domain-specific options is also set
        self.assertEqual('fake://memory1', conf.ldap.url)

    def test_delete_domain_with_user_added(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': domain['id'],
                   'description': uuid.uuid4().hex,
                   'parent_id': None,
                   'enabled': True,
                   'is_domain': False}
        self.resource_api.create_domain(domain['id'], domain)
        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project_ref, project)

        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=project['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.delete_grant(user_id=self.user_foo['id'],
                                         project_id=project['id'],
                                         role_id=self.role_member['id'])
        domain['enabled'] = False
        self.resource_api.update_domain(domain['id'], domain)
        self.resource_api.delete_domain(domain['id'])
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])

    def test_user_enabled_ignored_disable_error(self):
        # Override.
        self.skipTest("Doesn't apply since LDAP config has no affect on the "
                      "SQL identity backend.")

    def test_group_enabled_ignored_disable_error(self):
        # Override.
        self.skipTest("Doesn't apply since LDAP config has no affect on the "
                      "SQL identity backend.")

    def test_project_enabled_ignored_disable_error(self):
        # Override
        self.skipTest("Doesn't apply since LDAP configuration is ignored for "
                      "SQL assignment backend.")

    def test_list_role_assignments_filtered_by_role(self):
        # Domain roles are supported by the SQL Assignment backend
        base = super(BaseLDAPIdentity, self)
        base.test_list_role_assignments_filtered_by_role()

    def test_list_role_assignment_by_domain(self):
        # With multi LDAP this method should work, so override the override
        # from BaseLDAPIdentity
        super(BaseLDAPIdentity, self).test_list_role_assignment_by_domain

    def test_list_role_assignment_by_user_with_domain_group_roles(self):
        # With multi LDAP this method should work, so override the override
        # from BaseLDAPIdentity
        super(BaseLDAPIdentity, self).\
            test_list_role_assignment_by_user_with_domain_group_roles


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
                             self.domains['domain_default']['id']: 'ldap',
                             self.domains['domain1']['id']: 'ldap',
                             self.domains['domain2']['id']: 'ldap',
                         },
                         resource='sql')

    def enable_multi_domain(self):
        # The values below are the same as in the domain_configs_multi_ldap
        # cdirectory of test config_files.
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
            'identity': {'driver': 'ldap'}
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

        self.domain_config_api.create_config(CONF.identity.default_domain_id,
                                             default_config)
        self.domain_config_api.create_config(self.domains['domain1']['id'],
                                             domain1_config)
        self.domain_config_api.create_config(self.domains['domain2']['id'],
                                             domain2_config)

        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_configurations_from_database=True)
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
        self.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        # Trigger the identity backend to initialise any domain specific
        # configurations
        self.identity_api.list_users()
        # Check that the new config has not been passed to the driver for
        # the default domain.
        default_config = (
            self.identity_api.domain_configs.get_domain_conf(
                CONF.identity.default_domain_id))
        self.assertEqual(CONF.ldap.url, default_config.ldap.url)

    def test_reloading_domain_config(self):
        """Ensure domain drivers are reloaded on a config modification."""

        domain_cfgs = self.identity_api.domain_configs

        # Create a new config for the default domain, hence overwriting the
        # current settings.
        new_config = {
            'ldap': {'url': uuid.uuid4().hex},
            'identity': {'driver': 'ldap'}}
        self.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        default_config = (
            domain_cfgs.get_domain_conf(CONF.identity.default_domain_id))
        self.assertEqual(new_config['ldap']['url'], default_config.ldap.url)

        # Ensure updating is also honored
        updated_config = {'url': uuid.uuid4().hex}
        self.domain_config_api.update_config(
            CONF.identity.default_domain_id, updated_config,
            group='ldap', option='url')
        default_config = (
            domain_cfgs.get_domain_conf(CONF.identity.default_domain_id))
        self.assertEqual(updated_config['url'], default_config.ldap.url)

        # ...and finally ensure delete causes the driver to get the standard
        # config again.
        self.domain_config_api.delete_config(CONF.identity.default_domain_id)
        default_config = (
            domain_cfgs.get_domain_conf(CONF.identity.default_domain_id))
        self.assertEqual(CONF.ldap.url, default_config.ldap.url)

    def test_setting_multiple_sql_driver_raises_exception(self):
        """Ensure setting multiple domain specific sql drivers is prevented."""

        new_config = {'identity': {'driver': 'sql'}}
        self.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        self.identity_api.domain_configs.get_domain_conf(
            CONF.identity.default_domain_id)
        self.domain_config_api.create_config(self.domains['domain1']['id'],
                                             new_config)
        self.assertRaises(exception.MultipleSQLDriversInConfig,
                          self.identity_api.domain_configs.get_domain_conf,
                          self.domains['domain1']['id'])

    def test_same_domain_gets_sql_driver(self):
        """Ensure we can set an SQL driver if we have had it before."""

        new_config = {'identity': {'driver': 'sql'}}
        self.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        self.identity_api.domain_configs.get_domain_conf(
            CONF.identity.default_domain_id)

        # By using a slightly different config, we cause the driver to be
        # reloaded...and hence check if we can reuse the sql driver
        new_config = {'identity': {'driver': 'sql'},
                      'ldap': {'url': 'fake://memory1'}}
        self.domain_config_api.create_config(
            CONF.identity.default_domain_id, new_config)
        self.identity_api.domain_configs.get_domain_conf(
            CONF.identity.default_domain_id)

    def test_delete_domain_clears_sql_registration(self):
        """Ensure registration is deleted when a domain is deleted."""

        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        domain = self.resource_api.create_domain(domain['id'], domain)
        new_config = {'identity': {'driver': 'sql'}}
        self.domain_config_api.create_config(domain['id'], new_config)
        self.identity_api.domain_configs.get_domain_conf(domain['id'])

        # First show that trying to set SQL for another driver fails
        self.domain_config_api.create_config(self.domains['domain1']['id'],
                                             new_config)
        self.assertRaises(exception.MultipleSQLDriversInConfig,
                          self.identity_api.domain_configs.get_domain_conf,
                          self.domains['domain1']['id'])
        self.domain_config_api.delete_config(self.domains['domain1']['id'])

        # Now we delete the domain
        domain['enabled'] = False
        self.resource_api.update_domain(domain['id'], domain)
        self.resource_api.delete_domain(domain['id'])

        # The registration should now be available
        self.domain_config_api.create_config(self.domains['domain1']['id'],
                                             new_config)
        self.identity_api.domain_configs.get_domain_conf(
            self.domains['domain1']['id'])

    def test_orphaned_registration_does_not_prevent_getting_sql_driver(self):
        """Ensure we self heal an orphaned sql registration."""

        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        domain = self.resource_api.create_domain(domain['id'], domain)
        new_config = {'identity': {'driver': 'sql'}}
        self.domain_config_api.create_config(domain['id'], new_config)
        self.identity_api.domain_configs.get_domain_conf(domain['id'])

        # First show that trying to set SQL for another driver fails
        self.domain_config_api.create_config(self.domains['domain1']['id'],
                                             new_config)
        self.assertRaises(exception.MultipleSQLDriversInConfig,
                          self.identity_api.domain_configs.get_domain_conf,
                          self.domains['domain1']['id'])

        # Now we delete the domain by using the backend driver directly,
        # which causes the domain to be deleted without any of the cleanup
        # that is in the manager (this is simulating a server process crashing
        # in the middle of a delete domain operation, and somehow leaving the
        # domain config settings in place, but the domain is deleted). We
        # should still be able to set another domain to SQL, since we should
        # self heal this issue.

        self.resource_api.driver.delete_domain(domain['id'])
        # Invalidate cache (so we will see the domain has gone)
        self.resource_api.get_domain.invalidate(
            self.resource_api, domain['id'])

        # The registration should now be available
        self.domain_config_api.create_config(self.domains['domain1']['id'],
                                             new_config)
        self.identity_api.domain_configs.get_domain_conf(
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
    def setUp(self):
        sqldb = self.useFixture(database.Database())
        super(DomainSpecificLDAPandSQLIdentity, self).setUp()
        self.initial_setup(sqldb)

    def initial_setup(self, sqldb):
        # We aren't setting up any initial data ahead of switching to
        # domain-specific operation, so make the switch straight away.
        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_config_dir=(
                unit.TESTCONF + '/domain_configs_one_sql_one_ldap'))
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

        self.load_backends()
        sqldb.recreate()

        self.domain_count = 2
        self.domain_specific_count = 2
        self.setup_initial_domains()
        self.users = {}

        self.ldapdb.clear()
        self.load_fixtures(default_fixtures)
        self.create_users_across_domains()

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

    def get_config(self, domain_id):
        # Get the config for this domain, will return CONF
        # if no specific config defined for this domain
        return self.identity_api.domain_configs.get_domain_conf(domain_id)

    def test_list_domains(self):
        self.skipTest(
            'N/A: Not relevant for multi ldap testing')

    def test_list_domains_non_default_domain_id(self):
        self.skipTest(
            'N/A: Not relevant for multi ldap testing')

    def test_domain_crud(self):
        self.skipTest(
            'N/A: Not relevant for multi ldap testing')

    def test_list_users(self):
        # Override the standard list users, since we have added an extra user
        # to the default domain, so the number of expected users is one more
        # than in the standard test.
        users = self.identity_api.list_users(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(len(default_fixtures.USERS) + 1, len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['id'])['id']
                                for user in default_fixtures.USERS)
        expected_user_ids.add(self.users['user0']['id'])
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
        # Check that I can read a user with the appropriate domain-selected
        # driver, but won't find it via any other domain driver

        self.check_user(self.users['user0'],
                        self.domains['domain_default']['id'], 200)
        self.check_user(self.users['user0'],
                        self.domains['domain1']['id'], exception.UserNotFound)

        self.check_user(self.users['user1'],
                        self.domains['domain1']['id'], 200)
        self.check_user(self.users['user1'],
                        self.domains['domain_default']['id'],
                        exception.UserNotFound)

        # Finally, going through the regular manager layer, make sure we
        # only see the right number of users in the non-default domain.

        self.assertThat(
            self.identity_api.list_users(
                domain_scope=self.domains['domain1']['id']),
            matchers.HasLength(1))

    def test_add_role_grant_to_user_and_project_404(self):
        self.skipTest('Blocked by bug 1101287')

    def test_get_role_grants_for_user_and_project_404(self):
        self.skipTest('Blocked by bug 1101287')

    def test_list_projects_for_user_with_grants(self):
        self.skipTest('Blocked by bug 1221805')

    def test_get_roles_for_user_and_project_user_group_same_id(self):
        self.skipTest('N/A: We never generate the same ID for a user and '
                      'group in our mapping table')

    def test_user_id_comma(self):
        self.skipTest('Only valid if it is guaranteed to be talking to '
                      'the fakeldap backend')

    def test_user_id_comma_grants(self):
        self.skipTest('Only valid if it is guaranteed to be talking to '
                      'the fakeldap backend')

    def test_user_enabled_ignored_disable_error(self):
        # Override.
        self.skipTest("Doesn't apply since LDAP config has no affect on the "
                      "SQL identity backend.")

    def test_group_enabled_ignored_disable_error(self):
        # Override.
        self.skipTest("Doesn't apply since LDAP config has no affect on the "
                      "SQL identity backend.")

    def test_project_enabled_ignored_disable_error(self):
        # Override
        self.skipTest("Doesn't apply since LDAP configuration is ignored for "
                      "SQL assignment backend.")

    def test_list_role_assignments_filtered_by_role(self):
        # Domain roles are supported by the SQL Assignment backend
        base = super(BaseLDAPIdentity, self)
        base.test_list_role_assignments_filtered_by_role()


class DomainSpecificSQLIdentity(DomainSpecificLDAPandSQLIdentity):
    """Class to test simplest use of domain-specific SQL driver.

    The simplest use of an SQL domain-specific backend is when it is used to
    augment the standard case when LDAP is the default driver defined in the
    main config file. This would allow, for example, service users to be
    stored in SQL while LDAP handles the rest. Hence we define:

    - The default driver uses the LDAP backend for the default domain
    - A separate SQL backend for domain1

    """
    def initial_setup(self, sqldb):
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

        self.load_backends()
        sqldb.recreate()

        self.domain_count = 2
        self.domain_specific_count = 1
        self.setup_initial_domains()
        self.users = {}

        self.load_fixtures(default_fixtures)
        self.create_users_across_domains()

        _assert_backends(self,
                         assignment='sql',
                         identity='ldap',
                         resource='sql')

    def config_overrides(self):
        super(DomainSpecificSQLIdentity, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='resource', driver='sql')
        self.config_fixture.config(group='assignment', driver='sql')

    def get_config(self, domain_id):
        if domain_id == CONF.identity.default_domain_id:
            return CONF
        else:
            return self.identity_api.domain_configs.get_domain_conf(domain_id)

    def test_default_sql_plus_sql_specific_driver_fails(self):
        # First confirm that if ldap is default driver, domain1 can be
        # loaded as sql
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='assignment', driver='sql')
        self.load_backends()
        # Make any identity call to initiate the lazy loading of configs
        self.identity_api.list_users(
            domain_scope=CONF.identity.default_domain_id)
        self.assertIsNotNone(self.get_config(self.domains['domain1']['id']))

        # Now re-initialize, but with sql as the identity driver
        self.config_fixture.config(group='identity', driver='sql')
        self.config_fixture.config(group='assignment', driver='sql')
        self.load_backends()
        # Make any identity call to initiate the lazy loading of configs, which
        # should fail since we would now have two sql drivers.
        self.assertRaises(exception.MultipleSQLDriversInConfig,
                          self.identity_api.list_users,
                          domain_scope=CONF.identity.default_domain_id)

    def test_multiple_sql_specific_drivers_fails(self):
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='assignment', driver='sql')
        self.load_backends()
        # Ensure default, domain1 and domain2 exist
        self.domain_count = 3
        self.setup_initial_domains()
        # Make any identity call to initiate the lazy loading of configs
        self.identity_api.list_users(
            domain_scope=CONF.identity.default_domain_id)
        # This will only load domain1, since the domain2 config file is
        # not stored in the same location
        self.assertIsNotNone(self.get_config(self.domains['domain1']['id']))

        # Now try and manually load a 2nd sql specific driver, for domain2,
        # which should fail.
        self.assertRaises(
            exception.MultipleSQLDriversInConfig,
            self.identity_api.domain_configs._load_config_from_file,
            self.resource_api,
            [unit.TESTCONF + '/domain_configs_one_extra_sql/' +
             'keystone.domain2.conf'],
            'domain2')


class LdapFilterTests(test_backend.FilterTests, unit.TestCase):

    def setUp(self):
        super(LdapFilterTests, self).setUp()
        sqldb = self.useFixture(database.Database())
        self.useFixture(ldapdb.LDAPDatabase())

        self.load_backends()
        self.load_fixtures(default_fixtures)
        sqldb.recreate()
        _assert_backends(self, assignment='ldap', identity='ldap')

    def config_overrides(self):
        super(LdapFilterTests, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(LdapFilterTests, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def test_list_users_in_group_filtered(self):
        # The LDAP identity driver currently does not support filtering on the
        # listing users for a given group, so will fail this test.
        try:
            super(LdapFilterTests, self).test_list_users_in_group_filtered()
        except matchers.MismatchError:
            return
        # We shouldn't get here...if we do, it means someone has implemented
        # filtering, so we can remove this test override.
        self.assertTrue(False)
