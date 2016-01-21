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

from oslo_config import cfg

from keystone.tests import unit
from keystone.tests.unit.backend import core_ldap
from keystone.tests.unit.backend.role import core as core_role


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
        self.skipTest("An all-LDAP configuration is no longer supported")

    def test_configurable_forbidden_role_actions(self):
        self.skipTest("An all-LDAP configuration is no longer supported")

    def test_role_filter(self):
        self.skipTest("An all-LDAP configuration is no longer supported")

    def test_role_attribute_mapping(self):
        self.skipTest("An all-LDAP configuration is no longer supported")

    def test_role_attribute_ignore(self):
        self.skipTest("An all-LDAP configuration is no longer supported")


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
