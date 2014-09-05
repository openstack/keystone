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
from testtools import matchers

from keystone import assignment
from keystone.common import cache
from keystone.common import ldap as common_ldap
from keystone.common.ldap import core as common_ldap_core
from keystone.common import sql
from keystone import config
from keystone import exception
from keystone import identity
from keystone.openstack.common.fixture import moxstubout
from keystone import tests
from keystone.tests import default_fixtures
from keystone.tests import fakeldap
from keystone.tests import test_backend


CONF = config.CONF


class BaseLDAPIdentity(test_backend.IdentityTests):
    def _get_domain_fixture(self):
        """Domains in LDAP are read-only, so just return the static one."""
        return self.assignment_api.get_domain(CONF.identity.default_domain_id)

    def clear_database(self):
        for shelf in fakeldap.FakeShelves:
            fakeldap.FakeShelves[shelf].clear()

    def reload_backends(self, domain_id):
        # Only one backend unless we are using separate domain backends
        self.load_backends()

    def get_config(self, domain_id):
        # Only one conf structure unless we are using separate domain backends
        return CONF

    def config_overrides(self):
        super(BaseLDAPIdentity, self).config_overrides()
        self.config_fixture.config(
            group='identity',
            driver='keystone.identity.backends.ldap.Identity')

    def config_files(self):
        config_files = super(BaseLDAPIdentity, self).config_files()
        config_files.append(tests.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def test_build_tree(self):
        """Regression test for building the tree names
        """
        user_api = identity.backends.ldap.UserApi(CONF)
        self.assertTrue(user_api)
        self.assertEqual("ou=Users,%s" % CONF.ldap.suffix, user_api.tree_dn)

    def test_configurable_allowed_user_actions(self):
        user = {'id': u'fäké1',
                'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                'tenants': ['bar']}
        self.identity_api.create_user(u'fäké1', user)
        user_ref = self.identity_api.get_user(u'fäké1')
        self.assertEqual(u'fäké1', user_ref['id'])

        user['password'] = u'fäképass2'
        self.identity_api.update_user(u'fäké1', user)

        self.identity_api.delete_user(u'fäké1')
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          u'fäké1')

    def test_configurable_forbidden_user_actions(self):
        conf = self.get_config(CONF.identity.default_domain_id)
        conf.ldap.user_allow_create = False
        conf.ldap.user_allow_update = False
        conf.ldap.user_allow_delete = False
        self.reload_backends(CONF.identity.default_domain_id)

        user = {'id': u'fäké1',
                'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                'tenants': ['bar']}
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.create_user,
                          u'fäké1',
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
        conf = self.get_config(CONF.identity.default_domain_id)
        conf.ldap.user_allow_create = False
        self.reload_backends(CONF.identity.default_domain_id)

        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.create_user,
                          self.user_foo['id'],
                          self.user_foo)

    def test_user_filter(self):
        user_ref = self.identity_api.get_user(self.user_foo['id'])
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)

        conf = self.get_config(user_ref['domain_id'])
        conf.ldap.user_filter = '(CN=DOES_NOT_MATCH)'
        self.reload_backends(user_ref['domain_id'])
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
        self.assertRaises(exception.NotFound,
                          self.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_project(self):
        new_domain = self._get_domain_fixture()
        new_group = {'id': uuid.uuid4().hex, 'domain_id': new_domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_api.create_group(new_group['id'], new_group)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'enabled': True,
                    'domain_id': new_domain['id']}
        self.identity_api.create_user(new_user['id'], new_user)
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
        self.assertRaises(exception.NotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          project_id=self.tenant_bar['id'],
                          role_id='member')

    def test_delete_user_grant_no_user(self):
        self.skipTest('Blocked by bug 1101287')

    def test_delete_group_grant_no_group(self):
        self.skipTest('Blocked by bug 1101287')

    def test_get_and_remove_role_grant_by_group_and_domain(self):
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
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'password': uuid.uuid4().hex, 'domain_id': domain['id'],
                 'enabled': True}
        self.identity_api.create_user(user1['id'], user1)
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
        domain = self._get_domain_fixture()
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': domain['id']}
        self.identity_api.create_user(new_user['id'], new_user)

        group1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': domain['id']}
        self.identity_api.create_group(group1['id'], group1)
        group2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': domain['id']}
        self.identity_api.create_group(group2['id'], group2)

        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.assignment_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.assignment_api.create_project(project2['id'], project2)

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
        self.assertEqual(2, len(user_projects))

    def test_create_duplicate_user_name_in_different_domains(self):
        self.skipTest('Blocked by bug 1101276')

    def test_create_duplicate_project_name_in_different_domains(self):
        self.skipTest('Blocked by bug 1101276')

    def test_create_duplicate_group_name_in_different_domains(self):
        self.skipTest(
            'N/A: LDAP does not support multiple domains')

    def test_move_user_between_domains(self):
        self.skipTest('Blocked by bug 1101276')

    def test_move_user_between_domains_with_clashing_names_fails(self):
        self.skipTest('Blocked by bug 1101276')

    def test_move_group_between_domains(self):
        self.skipTest(
            'N/A: LDAP does not support multiple domains')

    def test_move_group_between_domains_with_clashing_names_fails(self):
        self.skipTest('Blocked by bug 1101276')

    def test_move_project_between_domains(self):
        self.skipTest('Blocked by bug 1101276')

    def test_move_project_between_domains_with_clashing_names_fails(self):
        self.skipTest('Blocked by bug 1101276')

    def test_get_roles_for_user_and_domain(self):
        self.skipTest('N/A: LDAP does not support multiple domains')

    def test_list_role_assignments_unfiltered(self):
        new_domain = self._get_domain_fixture()
        new_user = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': new_domain['id']}
        self.identity_api.create_user(new_user['id'],
                                      new_user)
        new_group = {'id': uuid.uuid4().hex, 'domain_id': new_domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_api.create_group(new_group['id'], new_group)
        new_project = {'id': uuid.uuid4().hex,
                       'name': uuid.uuid4().hex,
                       'domain_id': new_domain['id']}
        self.assignment_api.create_project(new_project['id'], new_project)

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

    def test_list_role_assignments_dumb_member(self):
        self.config_fixture.config(group='ldap', use_dumb_member=True)
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        new_domain = self._get_domain_fixture()
        new_user = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': new_domain['id']}
        self.identity_api.create_user(new_user['id'],
                                      new_user)
        new_project = {'id': uuid.uuid4().hex,
                       'name': uuid.uuid4().hex,
                       'domain_id': new_domain['id']}
        self.assignment_api.create_project(new_project['id'], new_project)
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=new_project['id'],
                                         role_id='other')

        # Read back the list of assignments and ensure
        # that the LDAP dumb member isn't listed.
        assignment_ids = [a['user_id'] for a in
                          self.assignment_api.list_role_assignments()]
        dumb_id = common_ldap.BaseLdap._dn_to_id(CONF.ldap.dumb_member)
        self.assertNotIn(dumb_id, assignment_ids)

    def test_list_role_assignments_bad_role(self):
        self.skipTest('Blocked by bug 1221805')

    def test_multi_group_grants_on_project_domain(self):
        self.skipTest('Blocked by bug 1101287')

    def test_list_group_members_missing_entry(self):
        """List group members with deleted user.

        If a group has a deleted entry for a member, the non-deleted members
        are returned.

        """

        # Create a group
        group_id = None
        group = dict(name=uuid.uuid4().hex,
                     domain_id=CONF.identity.default_domain_id)
        group_id = self.identity_api.create_group(group_id, group)['id']

        # Create a couple of users and add them to the group.
        user_id = None
        user = dict(name=uuid.uuid4().hex, id=uuid.uuid4().hex,
                    domain_id=CONF.identity.default_domain_id)
        user_1_id = self.identity_api.create_user(user_id, user)['id']

        self.identity_api.add_user_to_group(user_1_id, group_id)

        user_id = None
        user = dict(name=uuid.uuid4().hex, id=uuid.uuid4().hex,
                    domain_id=CONF.identity.default_domain_id)
        user_2_id = self.identity_api.create_user(user_id, user)['id']

        self.identity_api.add_user_to_group(user_2_id, group_id)

        # Delete user 2
        # NOTE(blk-u): need to go directly to user interface to keep from
        # updating the group.
        driver = self.identity_api._select_identity_driver(
            user['domain_id'])
        driver.user.delete(user_2_id)

        # List group users and verify only user 1.
        res = self.identity_api.list_users_in_group(group_id)

        self.assertEqual(1, len(res), "Expected 1 entry (user_1)")
        self.assertEqual(user_1_id, res[0]['id'], "Expected user 1 id")

    def test_list_group_members_when_no_members(self):
        # List group members when there is no member in the group.
        # No exception should be raised.
        group = {
            'id': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex}
        self.identity_api.create_group(group['id'], group)

        # If this doesn't raise, then the test is successful.
        self.identity_api.list_users_in_group(group['id'])

    def test_list_domains(self):
        domains = self.assignment_api.list_domains()
        self.assertEqual(
            [assignment.calc_default_domain()],
            domains)

    def test_list_domains_non_default_domain_id(self):
        # If change the default_domain_id, the ID of the default domain
        # returned by list_domains changes is the new default_domain_id.

        new_domain_id = uuid.uuid4().hex
        self.config_fixture.config(group='identity',
                                   default_domain_id=new_domain_id)

        domains = self.assignment_api.list_domains()

        self.assertEqual(new_domain_id, domains[0]['id'])

    def test_authenticate_requires_simple_bind(self):
        user = {
            'id': 'no_meta',
            'name': 'NO_META',
            'domain_id': test_backend.DEFAULT_DOMAIN_ID,
            'password': 'no_meta2',
            'enabled': True,
        }
        self.identity_api.create_user(user['id'], user)
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
                          password=None,
                          domain_scope=user['domain_id'])

    # (spzala)The group and domain crud tests below override the standard ones
    # in test_backend.py so that we can exclude the update name test, since we
    # do not yet support the update of either group or domain names with LDAP.
    # In the tests below, the update is demonstrated by updating description.
    # Refer to bug 1136403 for more detail.
    def test_group_crud(self):
        group = {
            'id': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex}
        self.identity_api.create_group(group['id'], group)
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

    def test_create_user_none_mapping(self):
        # When create a user where an attribute maps to None, the entry is
        # created without that attribute and it doesn't fail with a TypeError.
        conf = self.get_config(CONF.identity.default_domain_id)
        conf.ldap.user_attribute_ignore = ['enabled', 'email',
                                           'tenants', 'tenantId']
        self.reload_backends(CONF.identity.default_domain_id)

        user = {'id': u'fäké1',
                'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                'default_project_id': 'maps_to_none',
                }

        # If this doesn't raise, then the test is successful.
        self.identity_api.create_user(u'fäké1', user)

    def test_unignored_user_none_mapping(self):
        # Ensure that an attribute that maps to None that is not explicitly
        # ignored in configuration is implicitly ignored without triggering
        # an error.
        conf = self.get_config(CONF.identity.default_domain_id)
        conf.ldap.user_attribute_ignore = ['enabled', 'email',
                                           'tenants', 'tenantId']
        self.reload_backends(CONF.identity.default_domain_id)

        user = {'id': u'fäké1',
                'name': u'fäké1',
                'password': u'fäképass1',
                'domain_id': CONF.identity.default_domain_id,
                }

        user_ref = self.identity_api.create_user(u'fäké1', user)

        # If this doesn't raise, then the test is successful.
        self.identity_api.get_user(user_ref['id'])

    def test_update_user_name(self):
        """A user's name cannot be changed through the LDAP driver."""
        self.assertRaises(exception.Conflict,
                          super(BaseLDAPIdentity, self).test_update_user_name)

    def test_arbitrary_attributes_are_returned_from_create_user(self):
        self.skipTest("Using arbitrary attributes doesn't work under LDAP")

    def test_arbitrary_attributes_are_returned_from_get_user(self):
        self.skipTest("Using arbitrary attributes doesn't work under LDAP")

    def test_new_arbitrary_attributes_are_returned_from_update_user(self):
        self.skipTest("Using arbitrary attributes doesn't work under LDAP")

    def test_updated_arbitrary_attributes_are_returned_from_update_user(self):
        self.skipTest("Using arbitrary attributes doesn't work under LDAP")

    def test_user_id_comma_grants(self):
        """Even if the user has a , in their ID, can get user and group grants.
        """

        # Create a user with a , in their ID
        # NOTE(blk-u): the DN for this user is hard-coded in fakeldap!
        user_id = u'Doe, John'
        user = {
            'id': user_id,
            'name': self.getUniqueString(),
            'password': self.getUniqueString(),
            'domain_id': CONF.identity.default_domain_id,
        }
        self.identity_api.create_user(user_id, user)

        # Grant the user a role on a project.

        role_id = 'member'
        project_id = self.tenant_baz['id']

        self.assignment_api.create_grant(role_id, user_id=user_id,
                                         project_id=project_id)

        role_ref = self.assignment_api.get_grant(role_id, user_id=user_id,
                                                 project_id=project_id)

        self.assertEqual(role_id, role_ref['id'])

    def test_utf8_conversion(self):
        value_unicode = u'fäké1'
        value_utf8 = value_unicode.encode('utf-8')

        result_utf8 = common_ldap_core.utf8_encode(value_unicode)
        self.assertEqual(value_utf8, result_utf8)

        result_utf8 = common_ldap_core.utf8_encode(value_utf8)
        self.assertEqual(value_utf8, result_utf8)

        result_unicode = common_ldap_core.utf8_decode(value_utf8)
        self.assertEqual(value_unicode, result_unicode)

        result_unicode = common_ldap_core.utf8_decode(value_unicode)
        self.assertEqual(value_unicode, result_unicode)

        self.assertRaises(TypeError,
                          common_ldap_core.utf8_encode,
                          100)

        result_unicode = common_ldap_core.utf8_decode(100)
        self.assertEqual(u'100', result_unicode)


class LDAPIdentity(BaseLDAPIdentity, tests.TestCase):
    def setUp(self):
        super(LDAPIdentity, self).setUp()
        self.clear_database()

        common_ldap.register_handler('fake://', fakeldap.FakeLdap)
        self.load_backends()
        self.load_fixtures(default_fixtures)

        fixture = self.useFixture(moxstubout.MoxStubout())
        self.mox = fixture.mox
        self.stubs = fixture.stubs

    def test_configurable_allowed_project_actions(self):
        tenant = {'id': u'fäké1', 'name': u'fäké1', 'enabled': True}
        self.assignment_api.create_project(u'fäké1', tenant)
        tenant_ref = self.assignment_api.get_project(u'fäké1')
        self.assertEqual(u'fäké1', tenant_ref['id'])

        tenant['enabled'] = False
        self.assignment_api.update_project(u'fäké1', tenant)

        self.assignment_api.delete_project(u'fäké1')
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_project,
                          u'fäké1')

    def test_configurable_subtree_delete(self):
        self.config_fixture.config(group='ldap', allow_subtree_delete=True)
        self.load_backends()

        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': CONF.identity.default_domain_id}
        self.assignment_api.create_project(project1['id'], project1)

        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assignment_api.create_role(role1['id'], role1)

        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': CONF.identity.default_domain_id,
                 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_api.create_user(user1['id'], user1)

        self.assignment_api.add_role_to_user_and_project(
            user_id=user1['id'],
            tenant_id=project1['id'],
            role_id=role1['id'])

        self.assignment_api.delete_project(project1['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_project,
                          project1['id'])

        self.assignment_api.create_project(project1['id'], project1)

        list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'],
            project1['id'])
        self.assertEqual(0, len(list))

    def test_configurable_forbidden_project_actions(self):
        CONF.ldap.tenant_allow_create = False
        CONF.ldap.tenant_allow_update = False
        CONF.ldap.tenant_allow_delete = False
        self.load_backends()

        tenant = {'id': u'fäké1', 'name': u'fäké1'}
        self.assertRaises(exception.ForbiddenAction,
                          self.assignment_api.create_project,
                          u'fäké1',
                          tenant)

        self.tenant_bar['enabled'] = False
        self.assertRaises(exception.ForbiddenAction,
                          self.assignment_api.update_project,
                          self.tenant_bar['id'],
                          self.tenant_bar)
        self.assertRaises(exception.ForbiddenAction,
                          self.assignment_api.delete_project,
                          self.tenant_bar['id'])

    def test_configurable_allowed_role_actions(self):
        role = {'id': u'fäké1', 'name': u'fäké1'}
        self.assignment_api.create_role(u'fäké1', role)
        role_ref = self.assignment_api.get_role(u'fäké1')
        self.assertEqual(u'fäké1', role_ref['id'])

        role['name'] = u'fäké2'
        self.assignment_api.update_role(u'fäké1', role)

        self.assignment_api.delete_role(u'fäké1')
        self.assertRaises(exception.RoleNotFound,
                          self.assignment_api.get_role,
                          u'fäké1')

    def test_configurable_forbidden_role_actions(self):
        CONF.ldap.role_allow_create = False
        CONF.ldap.role_allow_update = False
        CONF.ldap.role_allow_delete = False
        self.load_backends()

        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assertRaises(exception.ForbiddenAction,
                          self.assignment_api.create_role,
                          role['id'],
                          role)

        self.role_member['name'] = uuid.uuid4().hex
        self.assertRaises(exception.ForbiddenAction,
                          self.assignment_api.update_role,
                          self.role_member['id'],
                          self.role_member)

        self.assertRaises(exception.ForbiddenAction,
                          self.assignment_api.delete_role,
                          self.role_member['id'])

    def test_project_filter(self):
        tenant_ref = self.assignment_api.get_project(self.tenant_bar['id'])
        self.assertDictEqual(tenant_ref, self.tenant_bar)

        CONF.ldap.tenant_filter = '(CN=DOES_NOT_MATCH)'
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.tenant_filter  will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_role.invalidate(self.assignment_api,
                                                self.role_member['id'])
        self.assignment_api.get_role(self.role_member['id'])
        self.assignment_api.get_project.invalidate(self.assignment_api,
                                                   self.tenant_bar['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_project,
                          self.tenant_bar['id'])

    def test_role_filter(self):
        role_ref = self.assignment_api.get_role(self.role_member['id'])
        self.assertDictEqual(role_ref, self.role_member)

        CONF.ldap.role_filter = '(CN=DOES_NOT_MATCH)'
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.role_filter will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_role.invalidate(self.assignment_api,
                                                self.role_member['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.assignment_api.get_role,
                          self.role_member['id'])

    def test_dumb_member(self):
        self.config_fixture.config(group='ldap', use_dumb_member=True)
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        dumb_id = common_ldap.BaseLdap._dn_to_id(CONF.ldap.dumb_member)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          dumb_id)

    def test_project_attribute_mapping(self):
        CONF.ldap.tenant_name_attribute = 'ou'
        CONF.ldap.tenant_desc_attribute = 'description'
        CONF.ldap.tenant_enabled_attribute = 'enabled'
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.tenant_name_attribute,
        # CONF.ldap.tenant_desc_attribute, and
        # CONF.ldap.tenant_enabled_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_project.invalidate(self.assignment_api,
                                                   self.tenant_baz['id'])
        tenant_ref = self.assignment_api.get_project(self.tenant_baz['id'])
        self.assertEqual(self.tenant_baz['id'], tenant_ref['id'])
        self.assertEqual(self.tenant_baz['name'], tenant_ref['name'])
        self.assertEqual(
            self.tenant_baz['description'],
            tenant_ref['description'])
        self.assertEqual(self.tenant_baz['enabled'], tenant_ref['enabled'])

        CONF.ldap.tenant_name_attribute = 'description'
        CONF.ldap.tenant_desc_attribute = 'ou'
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.tenant_name_attribute,
        # CONF.ldap.tenant_desc_attribute, and
        # CONF.ldap.tenant_enabled_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_project.invalidate(self.assignment_api,
                                                   self.tenant_baz['id'])
        tenant_ref = self.assignment_api.get_project(self.tenant_baz['id'])
        self.assertEqual(self.tenant_baz['id'], tenant_ref['id'])
        self.assertEqual(self.tenant_baz['description'], tenant_ref['name'])
        self.assertEqual(self.tenant_baz['name'], tenant_ref['description'])
        self.assertEqual(self.tenant_baz['enabled'], tenant_ref['enabled'])

    def test_project_attribute_ignore(self):
        CONF.ldap.tenant_attribute_ignore = ['name',
                                             'description',
                                             'enabled']
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.tenant_attribute_ignore will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change configs values in tests
        # that could affect what the drivers would return up to the manager.
        # This solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_project.invalidate(self.assignment_api,
                                                   self.tenant_baz['id'])
        tenant_ref = self.assignment_api.get_project(self.tenant_baz['id'])
        self.assertEqual(self.tenant_baz['id'], tenant_ref['id'])
        self.assertNotIn('name', tenant_ref)
        self.assertNotIn('description', tenant_ref)
        self.assertNotIn('enabled', tenant_ref)

    def test_role_attribute_mapping(self):
        CONF.ldap.role_name_attribute = 'ou'
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.role_name_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_role.invalidate(self.assignment_api,
                                                self.role_member['id'])
        role_ref = self.assignment_api.get_role(self.role_member['id'])
        self.assertEqual(self.role_member['id'], role_ref['id'])
        self.assertEqual(self.role_member['name'], role_ref['name'])

        CONF.ldap.role_name_attribute = 'sn'
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.role_name_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_role.invalidate(self.assignment_api,
                                                self.role_member['id'])
        role_ref = self.assignment_api.get_role(self.role_member['id'])
        self.assertEqual(self.role_member['id'], role_ref['id'])
        self.assertNotIn('name', role_ref)

    def test_role_attribute_ignore(self):
        CONF.ldap.role_attribute_ignore = ['name']
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.role_attribute_ignore will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.assignment_api.get_role.invalidate(self.assignment_api,
                                                self.role_member['id'])
        role_ref = self.assignment_api.get_role(self.role_member['id'])
        self.assertEqual(self.role_member['id'], role_ref['id'])
        self.assertNotIn('name', role_ref)

    def test_user_enable_attribute_mask(self):
        CONF.ldap.user_enabled_mask = 2
        CONF.ldap.user_enabled_default = '512'
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)

        ldap_ = self.identity_api.driver.user.get_connection()

        def get_enabled_vals():
            user_dn = self.identity_api.driver.user._id_to_dn_string(u'fäké1')
            enabled_attr_name = CONF.ldap.user_enabled_attribute

            res = ldap_.search_s(user_dn,
                                 ldap.SCOPE_BASE,
                                 query=u'(sn=fäké1)')
            return res[0][1][enabled_attr_name]

        user = {'id': u'fäké1', 'name': u'fäké1', 'enabled': True,
                'domain_id': CONF.identity.default_domain_id}

        user_ref = self.identity_api.create_user(u'fäké1', user)

        # Use assertIs rather than assertTrue because assertIs will assert the
        # value is a Boolean as expected.
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = get_enabled_vals()
        self.assertEqual([512], enabled_vals)

        user_ref = self.identity_api.get_user(u'fäké1')
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

        user['enabled'] = False
        user_ref = self.identity_api.update_user(u'fäké1', user)
        self.assertIs(user_ref['enabled'], False)
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = get_enabled_vals()
        self.assertEqual([514], enabled_vals)

        user_ref = self.identity_api.get_user(u'fäké1')
        self.assertIs(user_ref['enabled'], False)
        self.assertNotIn('enabled_nomask', user_ref)

        user['enabled'] = True
        user_ref = self.identity_api.update_user(u'fäké1', user)
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

        enabled_vals = get_enabled_vals()
        self.assertEqual([512], enabled_vals)

        user_ref = self.identity_api.get_user(u'fäké1')
        self.assertIs(user_ref['enabled'], True)
        self.assertNotIn('enabled_nomask', user_ref)

    def test_user_api_get_connection_no_user_password(self):
        """Don't bind in case the user and password are blank."""
        # Ensure the username/password are in-fact blank
        self.config_fixture.config(group='ldap', user=None, password=None)
        user_api = identity.backends.ldap.UserApi(CONF)
        self.stubs.Set(fakeldap, 'FakeLdap',
                       self.mox.CreateMock(fakeldap.FakeLdap))
        common_ldap.register_handler('fake://', fakeldap.FakeLdap)
        # we have to track all calls on 'conn' to make sure that
        # conn.simple_bind_s is not called
        conn = self.mox.CreateMockAnything()
        conn = fakeldap.FakeLdap(CONF.ldap.url,
                                 0,
                                 alias_dereferencing=None,
                                 tls_cacertdir=None,
                                 tls_cacertfile=None,
                                 tls_req_cert=2,
                                 use_tls=False,
                                 chase_referrals=None).AndReturn(conn)
        self.mox.ReplayAll()

        user_api.get_connection(user=None, password=None)

    def test_chase_referrals_off(self):
        self.config_fixture.config(
            group='ldap',
            url='fake://memory',
            chase_referrals=False)
        user_api = identity.backends.ldap.UserApi(CONF)
        self.stubs.Set(fakeldap, 'FakeLdap',
                       self.mox.CreateMock(fakeldap.FakeLdap))
        common_ldap.register_handler('fake://', fakeldap.FakeLdap)
        user = uuid.uuid4().hex
        password = uuid.uuid4().hex
        conn = self.mox.CreateMockAnything()
        conn = fakeldap.FakeLdap(CONF.ldap.url,
                                 0,
                                 alias_dereferencing=None,
                                 tls_cacertdir=None,
                                 tls_cacertfile=None,
                                 tls_req_cert=2,
                                 use_tls=False,
                                 chase_referrals=False).AndReturn(conn)
        conn.simple_bind_s(user, password).AndReturn(None)
        self.mox.ReplayAll()

        user_api.get_connection(user=user, password=password)

    def test_chase_referrals_on(self):
        self.config_fixture.config(
            group='ldap',
            url='fake://memory',
            chase_referrals=True)
        user_api = identity.backends.ldap.UserApi(CONF)
        self.stubs.Set(fakeldap, 'FakeLdap',
                       self.mox.CreateMock(fakeldap.FakeLdap))
        common_ldap.register_handler('fake://', fakeldap.FakeLdap)
        user = uuid.uuid4().hex
        password = uuid.uuid4().hex
        conn = self.mox.CreateMockAnything()
        conn = fakeldap.FakeLdap(CONF.ldap.url,
                                 0,
                                 alias_dereferencing=None,
                                 tls_cacertdir=None,
                                 tls_cacertfile=None,
                                 tls_req_cert=2,
                                 use_tls=False,
                                 chase_referrals=True).AndReturn(conn)
        conn.simple_bind_s(user, password).AndReturn(None)
        self.mox.ReplayAll()

        user_api.get_connection(user=user, password=password)

    def test_wrong_ldap_scope(self):
        CONF.ldap.query_scope = uuid.uuid4().hex
        self.assertRaisesRegexp(
            ValueError,
            'Invalid LDAP scope: %s. *' % CONF.ldap.query_scope,
            identity.backends.ldap.Identity)

    def test_wrong_alias_dereferencing(self):
        CONF.ldap.alias_dereferencing = uuid.uuid4().hex
        self.assertRaisesRegexp(
            ValueError,
            'Invalid LDAP deref option: %s\.' % CONF.ldap.alias_dereferencing,
            identity.backends.ldap.Identity)

    def test_user_extra_attribute_mapping(self):
        CONF.ldap.user_additional_attribute_mapping = ['description:name']
        self.load_backends()
        user = {
            'id': 'extra_attributes',
            'name': 'EXTRA_ATTRIBUTES',
            'password': 'extra',
            'domain_id': CONF.identity.default_domain_id
        }
        self.identity_api.create_user(user['id'], user)
        dn, attrs = self.identity_api.driver.user._ldap_get(user['id'])
        self.assertTrue(user['name'] in attrs['description'])

    def test_user_extra_attribute_mapping_description_is_returned(self):
        # Given a mapping like description:description, the description is
        # returned.

        self.config_fixture.config(
            group='ldap',
            user_additional_attribute_mapping=['description:description'])
        self.load_backends()

        description = uuid.uuid4().hex
        user = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': description,
            'password': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id
        }
        self.identity_api.create_user(user['id'], user)
        res = self.identity_api.driver.user.get_all()

        new_user = [u for u in res if u['id'] == user['id']][0]
        self.assertThat(new_user['description'], matchers.Equals(description))

    @mock.patch.object(common_ldap_core.BaseLdap, '_ldap_get')
    def test_user_mixed_case_attribute(self, mock_ldap_get):
        # Mock the search results to return attribute names
        # with unexpected case.
        mock_ldap_get.return_value = (
            'cn=junk,dc=example,dc=com',
            {
                'sN': [uuid.uuid4().hex],
                'eMaIl': [uuid.uuid4().hex]
            }
        )
        user = self.identity_api.get_user('junk')
        self.assertEqual(mock_ldap_get.return_value[1]['sN'][0],
                         user['name'])
        self.assertEqual(mock_ldap_get.return_value[1]['eMaIl'][0],
                         user['email'])

    def test_binary_attribute_values(self):
        result = [(
            'cn=junk,dc=example,dc=com',
            {
                'cn': ['junk'],
                'sn': [uuid.uuid4().hex],
                'mail': [uuid.uuid4().hex],
                'binary_attr': ['\x00\xFF\x00\xFF']
            }
        ), ]
        py_result = common_ldap_core.convert_ldap_result(result)
        # The attribute containing the binary value should
        # not be present in the converted result.
        self.assertNotIn('binary_attr', py_result[0][1])

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
                          self.assignment_api.create_domain,
                          domain['id'],
                          domain)
        self.assertRaises(exception.Conflict,
                          self.assignment_api.create_domain,
                          CONF.identity.default_domain_id,
                          domain)
        self.assertRaises(exception.DomainNotFound,
                          self.assignment_api.get_domain,
                          domain['id'])

        domain['description'] = uuid.uuid4().hex
        self.assertRaises(exception.DomainNotFound,
                          self.assignment_api.update_domain,
                          domain['id'],
                          domain)
        self.assertRaises(exception.Forbidden,
                          self.assignment_api.update_domain,
                          CONF.identity.default_domain_id,
                          domain)
        self.assertRaises(exception.DomainNotFound,
                          self.assignment_api.get_domain,
                          domain['id'])
        self.assertRaises(exception.DomainNotFound,
                          self.assignment_api.delete_domain,
                          domain['id'])
        self.assertRaises(exception.Forbidden,
                          self.assignment_api.delete_domain,
                          CONF.identity.default_domain_id)
        self.assertRaises(exception.DomainNotFound,
                          self.assignment_api.get_domain,
                          domain['id'])

    def test_create_domain_case_sensitivity(self):
        # domains are read-only, so case sensitivity isn't an issue
        ref = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex}
        self.assertRaises(exception.Forbidden,
                          self.assignment_api.create_domain,
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
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': CONF.identity.default_domain_id,
                   'description': uuid.uuid4().hex, 'enabled': True
                   }
        self.assignment_api.create_project(project['id'], project)
        project_ref = self.assignment_api.get_project(project['id'])

        self.assertDictEqual(project_ref, project)

        project['description'] = uuid.uuid4().hex
        self.assignment_api.update_project(project['id'], project)
        project_ref = self.assignment_api.get_project(project['id'])
        self.assertDictEqual(project_ref, project)

        self.assignment_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_project,
                          project['id'])

    @tests.skip_if_cache_disabled('assignment')
    def test_cache_layer_project_crud(self):
        # NOTE(morganfainberg): LDAP implementation does not currently support
        # updating project names.  This method override provides a different
        # update test.
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': CONF.identity.default_domain_id,
                   'description': uuid.uuid4().hex}
        project_id = project['id']
        # Create a project
        self.assignment_api.create_project(project_id, project)
        self.assignment_api.get_project(project_id)
        updated_project = copy.deepcopy(project)
        updated_project['description'] = uuid.uuid4().hex
        # Update project, bypassing assignment_api manager
        self.assignment_api.driver.update_project(project_id,
                                                  updated_project)
        # Verify get_project still returns the original project_ref
        self.assertDictContainsSubset(
            project, self.assignment_api.get_project(project_id))
        # Invalidate cache
        self.assignment_api.get_project.invalidate(self.assignment_api,
                                                   project_id)
        # Verify get_project now returns the new project
        self.assertDictContainsSubset(
            updated_project,
            self.assignment_api.get_project(project_id))
        # Update project using the assignment_api manager back to original
        self.assignment_api.update_project(project['id'], project)
        # Verify get_project returns the original project_ref
        self.assertDictContainsSubset(
            project, self.assignment_api.get_project(project_id))
        # Delete project bypassing assignment_api
        self.assignment_api.driver.delete_project(project_id)
        # Verify get_project still returns the project_ref
        self.assertDictContainsSubset(
            project, self.assignment_api.get_project(project_id))
        # Invalidate cache
        self.assignment_api.get_project.invalidate(self.assignment_api,
                                                   project_id)
        # Verify ProjectNotFound now raised
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_project,
                          project_id)
        # recreate project
        self.assignment_api.create_project(project_id, project)
        self.assignment_api.get_project(project_id)
        # delete project
        self.assignment_api.delete_project(project_id)
        # Verify ProjectNotFound is raised
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_project,
                          project_id)

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        # This is a partial implementation of the standard test that
        # is defined in test_backend.py.  It omits both domain and
        # group grants. since neither of these are yet supported by
        # the ldap backend.

        role_list = []
        for _ in range(2):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.assignment_api.create_role(role['id'], role)
            role_list.append(role)

        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': CONF.identity.default_domain_id,
                 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_api.create_user(user1['id'], user1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': CONF.identity.default_domain_id}
        self.assignment_api.create_project(project1['id'], project1)

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

    def test_create_grant_no_user(self):
        self.skipTest('Blocked by bug 1101287')

    def test_create_grant_no_group(self):
        self.skipTest('Blocked by bug 1101287')

    def test_get_default_domain_by_name(self):
        domain = self._get_domain_fixture()

        domain_ref = self.assignment_api.get_domain_by_name(domain['name'])
        self.assertEqual(domain_ref, domain)


class LDAPIdentityEnabledEmulation(LDAPIdentity):
    def setUp(self):
        super(LDAPIdentityEnabledEmulation, self).setUp()
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        for obj in [self.tenant_bar, self.tenant_baz, self.user_foo,
                    self.user_two, self.user_badguy]:
            obj.setdefault('enabled', True)

    def config_files(self):
        config_files = super(LDAPIdentityEnabledEmulation, self).config_files()
        config_files.append(tests.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def config_overrides(self):
        super(LDAPIdentityEnabledEmulation, self).config_overrides()
        self.config_fixture.config(group='ldap',
                                   user_enabled_emulation=True,
                                   tenant_enabled_emulation=True)

    def test_project_crud(self):
        # NOTE(topol): LDAPIdentityEnabledEmulation will create an
        #              enabled key in the project dictionary so this
        #              method override handles this side-effect
        project = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'description': uuid.uuid4().hex}

        self.assignment_api.create_project(project['id'], project)
        project_ref = self.assignment_api.get_project(project['id'])

        # self.assignment_api.create_project adds an enabled
        # key with a value of True when LDAPIdentityEnabledEmulation
        # is used so we now add this expected key to the project dictionary
        project['enabled'] = True
        self.assertDictEqual(project_ref, project)

        project['description'] = uuid.uuid4().hex
        self.assignment_api.update_project(project['id'], project)
        project_ref = self.assignment_api.get_project(project['id'])
        self.assertDictEqual(project_ref, project)

        self.assignment_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_project,
                          project['id'])

    def test_user_crud(self):
        user = {
            'id': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'password': uuid.uuid4().hex}
        self.identity_api.create_user(user['id'], user)
        user['enabled'] = True
        user_ref = self.identity_api.get_user(user['id'])
        del user['password']
        user_ref_dict = dict((x, user_ref[x]) for x in user_ref)
        self.assertDictEqual(user_ref_dict, user)

        user['password'] = uuid.uuid4().hex
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        del user['password']
        user_ref_dict = dict((x, user_ref[x]) for x in user_ref)
        self.assertDictEqual(user_ref_dict, user)

        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])

    def test_user_enable_attribute_mask(self):
        self.skipTest(
            "Enabled emulation conflicts with enabled mask")


class LdapIdentitySqlAssignment(BaseLDAPIdentity, tests.SQLDriverOverrides,
                                tests.TestCase):

    def config_files(self):
        config_files = super(LdapIdentitySqlAssignment, self).config_files()
        config_files.append(tests.dirs.tests_conf('backend_ldap_sql.conf'))
        return config_files

    def setUp(self):
        super(LdapIdentitySqlAssignment, self).setUp()
        self.clear_database()
        self.load_backends()
        cache.configure_cache_region(cache.REGION)
        self.engine = sql.get_engine()
        self.addCleanup(sql.cleanup)

        sql.ModelBase.metadata.create_all(bind=self.engine)
        self.addCleanup(sql.ModelBase.metadata.drop_all, bind=self.engine)

        self.load_fixtures(default_fixtures)
        #defaulted by the data load
        self.user_foo['enabled'] = True

    def config_overrides(self):
        super(LdapIdentitySqlAssignment, self).config_overrides()
        self.config_fixture.config(
            group='identity',
            driver='keystone.identity.backends.ldap.Identity')
        self.config_fixture.config(
            group='assignment',
            driver='keystone.assignment.backends.sql.Assignment')

    def test_domain_crud(self):
        pass

    def test_list_domains(self):
        domains = self.assignment_api.list_domains()
        self.assertEqual([assignment.calc_default_domain()], domains)

    def test_list_domains_non_default_domain_id(self):
        # If change the default_domain_id, the ID of the default domain
        # returned by list_domains doesn't change because the SQL identity
        # backend reads it from the database, which doesn't get updated by
        # config change.

        orig_default_domain_id = CONF.identity.default_domain_id

        new_domain_id = uuid.uuid4().hex
        self.config_fixture.config(group='identity',
                                   default_domain_id=new_domain_id)

        domains = self.assignment_api.list_domains()

        self.assertEqual(orig_default_domain_id, domains[0]['id'])

    def test_project_filter(self):
        self.skipTest(
            'N/A: Not part of SQL backend')

    def test_role_filter(self):
        self.skipTest(
            'N/A: Not part of SQL backend')

    def test_add_role_grant_to_user_and_project_404(self):
        self.skipTest('Blocked by bug 1101287')

    def test_get_role_grants_for_user_and_project_404(self):
        self.skipTest('Blocked by bug 1101287')

    def test_list_projects_for_user_with_grants(self):
        self.skipTest('Blocked by bug 1221805')


class MultiLDAPandSQLIdentity(BaseLDAPIdentity, tests.SQLDriverOverrides,
                              tests.TestCase):
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
        super(MultiLDAPandSQLIdentity, self).setUp()

        self.load_backends()

        self.engine = sql.get_engine()
        self.addCleanup(sql.cleanup)

        sql.ModelBase.metadata.create_all(bind=self.engine)
        self.addCleanup(sql.ModelBase.metadata.drop_all, bind=self.engine)

        self._setup_domain_test_data()

        # All initial domain data setup complete, time to switch on support
        # for separate backends per domain.

        self.config_fixture.config(group='identity',
                                   domain_specific_drivers_enabled=True,
                                   domain_config_dir=tests.TESTSDIR)

        self._set_domain_configs()
        self.clear_database()
        self.load_fixtures(default_fixtures)

    def config_overrides(self):
        super(MultiLDAPandSQLIdentity, self).config_overrides()
        # Make sure identity and assignment are actually SQL drivers,
        # BaseLDAPIdentity sets these options to use LDAP.
        self.config_fixture.config(
            group='identity',
            driver='keystone.identity.backends.sql.Identity')
        self.config_fixture.config(
            group='assignment',
            driver='keystone.assignment.backends.sql.Assignment')

    def _setup_domain_test_data(self):

        def create_domain(domain):
            try:
                ref = self.assignment_api.create_domain(
                    domain['id'], domain)
            except exception.Conflict:
                ref = (
                    self.assignment_api.get_domain_by_name(domain['name']))
            return ref

        self.domain_default = create_domain(assignment.calc_default_domain())
        self.domain1 = create_domain(
            {'id': uuid.uuid4().hex, 'name': 'domain1'})
        self.domain2 = create_domain(
            {'id': uuid.uuid4().hex, 'name': 'domain2'})
        self.domain3 = create_domain(
            {'id': uuid.uuid4().hex, 'name': 'domain3'})
        self.domain4 = create_domain(
            {'id': uuid.uuid4().hex, 'name': 'domain4'})

    def _set_domain_configs(self):
        # We need to load the domain configs explicitly to ensure the
        # test overrides are included.
        self.identity_api.domain_configs._load_config(
            self.identity_api.assignment_api,
            [tests.dirs.tests_conf('keystone.Default.conf')],
            'Default')
        self.identity_api.domain_configs._load_config(
            self.identity_api.assignment_api,
            [tests.dirs.tests_conf('keystone.domain1.conf')],
            'domain1')
        self.identity_api.domain_configs._load_config(
            self.identity_api.assignment_api,
            [tests.dirs.tests_conf('keystone.domain2.conf')],
            'domain2')

    def reload_backends(self, domain_id):
        # Just reload the driver for this domain - which will pickup
        # any updated cfg
        self.identity_api.domain_configs.reload_domain_driver(
            self.identity_api.assignment_api, domain_id)

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

    def test_domain_segregation(self):
        """Test that separate configs have segregated the domain.

        Test Plan:

        - Create a user in each of the domains
        - Make sure that you can only find a given user in its
          relevant domain
        - Make sure that for a backend that supports multiple domains
          you can get the users via any of the domain scopes

        """
        def create_user(domain_id):
            user = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain_id,
                    'password': uuid.uuid4().hex,
                    'enabled': True}
            self.identity_api.create_user(user['id'], user)
            return user

        userd = create_user(CONF.identity.default_domain_id)
        user1 = create_user(self.domain1['id'])
        user2 = create_user(self.domain2['id'])
        user3 = create_user(self.domain3['id'])
        user4 = create_user(self.domain4['id'])

        # Now check that I can read user1 with the appropriate domain
        # scope, but won't find it if the wrong scope is used

        ref = self.identity_api.get_user(
            userd['id'], domain_scope=CONF.identity.default_domain_id)
        del userd['password']
        self.assertDictEqual(ref, userd)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          userd['id'],
                          domain_scope=self.domain1['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          userd['id'],
                          domain_scope=self.domain2['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          userd['id'],
                          domain_scope=self.domain3['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          userd['id'],
                          domain_scope=self.domain4['id'])

        ref = self.identity_api.get_user(
            user1['id'], domain_scope=self.domain1['id'])
        del user1['password']
        self.assertDictEqual(ref, user1)
        ref = self.identity_api.get_user(
            user2['id'], domain_scope=self.domain2['id'])
        del user2['password']
        self.assertDictEqual(ref, user2)

        # Domains 3 and 4 share the same backend, so you should be
        # able to see user3 and 4 from either

        ref = self.identity_api.get_user(
            user3['id'], domain_scope=self.domain3['id'])
        del user3['password']
        self.assertDictEqual(ref, user3)
        ref = self.identity_api.get_user(
            user4['id'], domain_scope=self.domain4['id'])
        del user4['password']
        self.assertDictEqual(ref, user4)
        ref = self.identity_api.get_user(
            user3['id'], domain_scope=self.domain4['id'])
        self.assertDictEqual(ref, user3)
        ref = self.identity_api.get_user(
            user4['id'], domain_scope=self.domain3['id'])
        self.assertDictEqual(ref, user4)

    def test_scanning_of_config_dir(self):
        """Test the Manager class scans the config directory.

        The setup for the main tests above load the domain configs directly
        so that the test overrides can be included. This test just makes sure
        that the standard config directory scanning does pick up the relevant
        domain config files.

        """
        # Confirm that config has drivers_enabled as True, which we will
        # check has been set to False later in this test
        self.assertTrue(config.CONF.identity.domain_specific_drivers_enabled)
        self.load_backends()
        # Execute any command to trigger the lazy loading of domain configs
        self.identity_api.list_users(domain_scope=self.domain1['id'])
        # ...and now check the domain configs have been set up
        self.assertIn('default', self.identity_api.domain_configs)
        self.assertIn(self.domain1['id'], self.identity_api.domain_configs)
        self.assertIn(self.domain2['id'], self.identity_api.domain_configs)
        self.assertNotIn(self.domain3['id'], self.identity_api.domain_configs)
        self.assertNotIn(self.domain4['id'], self.identity_api.domain_configs)

        # Finally check that a domain specific config contains items from both
        # the primary config and the domain specific config
        conf = self.identity_api.domain_configs.get_domain_conf(
            self.domain1['id'])
        # This should now be false, as is the default, since this is not
        # set in the standard primary config file
        self.assertFalse(conf.identity.domain_specific_drivers_enabled)
        # ..and make sure a domain-specifc options is also set
        self.assertEqual('fake://memory1', conf.ldap.url)

    def test_add_role_grant_to_user_and_project_404(self):
        self.skipTest('Blocked by bug 1101287')

    def test_get_role_grants_for_user_and_project_404(self):
        self.skipTest('Blocked by bug 1101287')

    def test_list_projects_for_user_with_grants(self):
        self.skipTest('Blocked by bug 1221805')
