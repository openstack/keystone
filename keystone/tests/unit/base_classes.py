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

from oslo_config import fixture as config_fixture

from keystone.cmd import bootstrap
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.tests.unit import core
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TestCaseWithBootstrap(core.BaseTestCase):
    """A simpler version of TestCase that uses bootstrap.

    Re-implementation of TestCase that doesn't load a bunch of fixtures by
    hand and instead uses the bootstrap process. This makes it so that our base
    tests have the same things available to us as operators after they run
    bootstrap. It also makes our tests DRY and pushes setup required for
    specific tests into the actual test class, instead of pushing it into a
    generic structure that gets loaded for every test.

    """

    def setUp(self):
        self.useFixture(database.Database())
        super(TestCaseWithBootstrap, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        CONF(args=[], project='keystone')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys,
            )
        )

        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_receipts',
                CONF.fernet_receipts.max_active_keys,
            )
        )

        self.bootstrapper = bootstrap.Bootstrapper()
        self.addCleanup(provider_api.ProviderAPIs._clear_registry_instances)
        self.addCleanup(self.clean_default_domain)
        self.bootstrapper.admin_password = 'password'
        self.bootstrapper.admin_username = 'admin'
        self.bootstrapper.project_name = 'admin'
        self.bootstrapper.admin_role_name = 'admin'
        self.bootstrapper.service_name = 'keystone'
        self.bootstrapper.public_url = 'http://localhost/identity/'
        self.bootstrapper.immutable_roles = True

        try:
            PROVIDERS.resource_api.create_domain(
                default_fixtures.ROOT_DOMAIN['id'],
                default_fixtures.ROOT_DOMAIN,
            )
        except exception.Conflict:
            pass

        self.bootstrapper.bootstrap()

    def clean_default_domain(self):
        PROVIDERS.resource_api.update_domain(
            CONF.identity.default_domain_id, {'enabled': False}
        )
        PROVIDERS.resource_api.delete_domain(CONF.identity.default_domain_id)
