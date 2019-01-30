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

import ldap


from keystone.common import cache
from keystone.common import provider_api
import keystone.conf
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.ksfixtures import ldapdb


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


def create_group_container(identity_api):
    # Create the groups base entry (ou=Groups,cn=example,cn=com)
    group_api = identity_api.driver.group
    conn = group_api.get_connection()
    dn = 'ou=Groups,cn=example,cn=com'
    conn.add_s(dn, [('objectclass', ['organizationalUnit']),
                    ('ou', ['Groups'])])


class BaseBackendLdapCommon(object):
    """Mixin class to set up generic LDAP backends."""

    def setUp(self):
        super(BaseBackendLdapCommon, self).setUp()
        self.useFixture(ldapdb.LDAPDatabase())

        self.load_backends()
        self.load_fixtures(default_fixtures)

    def _get_domain_fixture(self):
        """Return the static domain, since domains in LDAP are read-only."""
        return PROVIDERS.resource_api.get_domain(
            CONF.identity.default_domain_id
        )

    def get_config(self, domain_id):
        # Only one conf structure unless we are using separate domain backends
        return CONF

    def config_overrides(self):
        super(BaseBackendLdapCommon, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')

    def config_files(self):
        config_files = super(BaseBackendLdapCommon, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap.conf'))
        return config_files

    def get_user_enabled_vals(self, user):
        user_dn = (
            PROVIDERS.identity_api.driver.user._id_to_dn_string(
                user['id']
            )
        )
        enabled_attr_name = CONF.ldap.user_enabled_attribute

        ldap_ = PROVIDERS.identity_api.driver.user.get_connection()
        res = ldap_.search_s(user_dn,
                             ldap.SCOPE_BASE,
                             u'(sn=%s)' % user['name'])
        if enabled_attr_name in res[0][1]:
            return res[0][1][enabled_attr_name]
        else:
            return None


class BaseBackendLdap(object):
    """Mixin class to set up an all-LDAP configuration."""

    def setUp(self):
        # NOTE(dstanek): The database must be setup prior to calling the
        # parent's setUp. The parent's setUp uses services (like
        # credentials) that require a database.
        self.useFixture(database.Database())
        super(BaseBackendLdap, self).setUp()

    def load_fixtures(self, fixtures):
        # Override super impl since need to create group container.
        create_group_container(PROVIDERS.identity_api)
        super(BaseBackendLdap, self).load_fixtures(fixtures)


class BaseBackendLdapIdentitySqlEverythingElse(unit.SQLDriverOverrides):
    """Mixin base for Identity LDAP, everything else SQL backend tests."""

    def config_files(self):
        config_files = super(BaseBackendLdapIdentitySqlEverythingElse,
                             self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap_sql.conf'))
        return config_files

    def setUp(self):
        sqldb = self.useFixture(database.Database())
        super(BaseBackendLdapIdentitySqlEverythingElse, self).setUp()
        self.load_backends()
        cache.configure_cache()

        sqldb.recreate()
        self.load_fixtures(default_fixtures)
        # defaulted by the data load
        self.user_foo['enabled'] = True

    def config_overrides(self):
        super(BaseBackendLdapIdentitySqlEverythingElse,
              self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='resource', driver='sql')
        self.config_fixture.config(group='assignment', driver='sql')


class BaseBackendLdapIdentitySqlEverythingElseWithMapping(object):
    """Mixin base class to test mapping of default LDAP backend.

    The default configuration is not to enable mapping when using a single
    backend LDAP driver.  However, a cloud provider might want to enable
    the mapping, hence hiding the LDAP IDs from any clients of keystone.
    Setting backward_compatible_ids to False will enable this mapping.

    """

    def config_overrides(self):
        super(BaseBackendLdapIdentitySqlEverythingElseWithMapping,
              self).config_overrides()
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)
