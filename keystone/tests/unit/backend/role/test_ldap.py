# -*- coding: utf-8 -*-
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

from oslo_config import cfg

from keystone import exception
from keystone.tests import unit
from keystone.tests.unit.backend import core_ldap
from keystone.tests.unit.backend.role import core as core_role
from keystone.tests.unit import default_fixtures


CONF = cfg.CONF


class LdapRoleCommon(core_ldap.BaseBackendLdapCommon, core_role.RoleTests):
    """Tests that should be run in every LDAP configuration.

    Include additional tests that are unique to LDAP (or need to be overridden)
    which should be run for all the various LDAP configurations we test.

    """
    pass


class LdapRole(LdapRoleCommon, core_ldap.BaseBackendLdap, unit.TestCase):
    """Test in an all-LDAP configuration.

    Include additional tests that are unique to LDAP (or need to be overridden)
    which only need to be run in a basic LDAP configurations.

    """
    def test_configurable_allowed_role_actions(self):
        role = {'id': u'fäké1', 'name': u'fäké1'}
        self.role_api.create_role(u'fäké1', role)
        role_ref = self.role_api.get_role(u'fäké1')
        self.assertEqual(u'fäké1', role_ref['id'])

        role['name'] = u'fäké2'
        self.role_api.update_role(u'fäké1', role)

        self.role_api.delete_role(u'fäké1')
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          u'fäké1')

    def test_configurable_forbidden_role_actions(self):
        self.config_fixture.config(
            group='ldap', role_allow_create=False, role_allow_update=False,
            role_allow_delete=False)
        self.load_backends()

        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assertRaises(exception.ForbiddenAction,
                          self.role_api.create_role,
                          role['id'],
                          role)

        self.role_member['name'] = uuid.uuid4().hex
        self.assertRaises(exception.ForbiddenAction,
                          self.role_api.update_role,
                          self.role_member['id'],
                          self.role_member)

        self.assertRaises(exception.ForbiddenAction,
                          self.role_api.delete_role,
                          self.role_member['id'])

    def test_role_filter(self):
        role_ref = self.role_api.get_role(self.role_member['id'])
        self.assertDictEqual(role_ref, self.role_member)

        self.config_fixture.config(group='ldap',
                                   role_filter='(CN=DOES_NOT_MATCH)')
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.role_filter will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.role_api.get_role.invalidate(self.role_api,
                                          self.role_member['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          self.role_member['id'])

    def test_role_attribute_mapping(self):
        self.config_fixture.config(group='ldap', role_name_attribute='ou')
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.role_name_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.role_api.get_role.invalidate(self.role_api,
                                          self.role_member['id'])
        role_ref = self.role_api.get_role(self.role_member['id'])
        self.assertEqual(self.role_member['id'], role_ref['id'])
        self.assertEqual(self.role_member['name'], role_ref['name'])

        self.config_fixture.config(group='ldap', role_name_attribute='sn')
        self.load_backends()
        # NOTE(morganfainberg): CONF.ldap.role_name_attribute will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.role_api.get_role.invalidate(self.role_api,
                                          self.role_member['id'])
        role_ref = self.role_api.get_role(self.role_member['id'])
        self.assertEqual(self.role_member['id'], role_ref['id'])
        self.assertNotIn('name', role_ref)

    def test_role_attribute_ignore(self):
        self.config_fixture.config(group='ldap',
                                   role_attribute_ignore=['name'])
        self.clear_database()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        # NOTE(morganfainberg): CONF.ldap.role_attribute_ignore will not be
        # dynamically changed at runtime. This invalidate is a work-around for
        # the expectation that it is safe to change config values in tests that
        # could affect what the drivers would return up to the manager.  This
        # solves this assumption when working with aggressive (on-create)
        # cache population.
        self.role_api.get_role.invalidate(self.role_api,
                                          self.role_member['id'])
        role_ref = self.role_api.get_role(self.role_member['id'])
        self.assertEqual(self.role_member['id'], role_ref['id'])
        self.assertNotIn('name', role_ref)


class LdapIdentitySqlEverythingElseRole(
    core_ldap.BaseBackendLdapIdentitySqlEverythingElse, LdapRoleCommon,
        unit.TestCase):
    """Test Identity in LDAP, Everything else in SQL."""
    pass


class LdapIdentitySqlEverythingElseWithMappingRole(
    LdapIdentitySqlEverythingElseRole,
        core_ldap.BaseBackendLdapIdentitySqlEverythingElseWithMapping):
    """Test ID mapping of default LDAP backend."""
    pass
