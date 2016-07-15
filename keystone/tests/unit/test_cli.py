# Copyright 2014 IBM Corp.
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

import os
import uuid

import fixtures
import mock
from oslo_config import fixture as config_fixture
from oslo_log import log
from oslotest import mockpatch
from six.moves import range
from testtools import matchers

from keystone.cmd import cli
from keystone.common import dependency
from keystone.common.sql import migration_helpers
import keystone.conf
from keystone.i18n import _
from keystone.identity.mapping_backends import mapping as identity_mapping
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.ksfixtures import ldapdb


CONF = keystone.conf.CONF


class CliTestCase(unit.SQLDriverOverrides, unit.TestCase):
    def config_files(self):
        config_files = super(CliTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def test_token_flush(self):
        self.useFixture(database.Database())
        self.load_backends()
        cli.TokenFlush.main()

    # NOTE(ravelar): the following method tests that the token_flush command,
    # when used in conjunction with an unsupported token driver like kvs,
    # will yield a LOG.warning message informing the user that the
    # command had no effect.
    def test_token_flush_excepts_not_implemented_and_logs_warning(self):
        self.useFixture(database.Database())
        self.load_backends()
        self.config_fixture.config(group='token', driver='memcache')
        log_info = self.useFixture(fixtures.FakeLogger(level=log.WARN))
        cli.TokenFlush.main()
        self.assertIn("token_flush command had no effect", log_info.output)


class CliNoConfigTestCase(unit.BaseTestCase):

    def setUp(self):
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)
        self.useFixture(mockpatch.Patch(
            'oslo_config.cfg.find_config_files', return_value=[]))
        super(CliNoConfigTestCase, self).setUp()

        # NOTE(crinkle): the command call doesn't have to actually work,
        # that's what the other unit tests are for. So just mock it out.
        class FakeConfCommand(object):
            def __init__(self):
                self.cmd_class = mock.Mock()
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', FakeConfCommand()))

        self.logging = self.useFixture(fixtures.FakeLogger(level=log.WARN))

    def test_cli(self):
        expected_msg = 'Config file not found, using default configs.'
        cli.main(argv=['keystone-manage', 'db_sync'])
        self.assertThat(self.logging.output, matchers.Contains(expected_msg))


class CliBootStrapTestCase(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        self.useFixture(database.Database())
        super(CliBootStrapTestCase, self).setUp()

    def config_files(self):
        self.config_fixture.register_cli_opt(cli.command_opt)
        config_files = super(CliBootStrapTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def config(self, config_files):
        CONF(args=['bootstrap', '--bootstrap-password', uuid.uuid4().hex],
             project='keystone',
             default_config_files=config_files)

    def test_bootstrap(self):
        bootstrap = cli.BootStrap()
        self._do_test_bootstrap(bootstrap)

    def _do_test_bootstrap(self, bootstrap):
        bootstrap.do_bootstrap()
        project = bootstrap.resource_manager.get_project_by_name(
            bootstrap.project_name,
            'default')
        user = bootstrap.identity_manager.get_user_by_name(
            bootstrap.username,
            'default')
        role = bootstrap.role_manager.get_role(bootstrap.role_id)
        role_list = (
            bootstrap.assignment_manager.get_roles_for_user_and_project(
                user['id'],
                project['id']))
        self.assertIs(len(role_list), 1)
        self.assertEqual(role_list[0], role['id'])
        # NOTE(morganfainberg): Pass an empty context, it isn't used by
        # `authenticate` method.
        bootstrap.identity_manager.authenticate(
            self.make_request(),
            user['id'],
            bootstrap.password)

        if bootstrap.region_id:
            region = bootstrap.catalog_manager.get_region(bootstrap.region_id)
            self.assertEqual(self.region_id, region['id'])

        if bootstrap.service_id:
            svc = bootstrap.catalog_manager.get_service(bootstrap.service_id)
            self.assertEqual(self.service_name, svc['name'])

            self.assertEqual(set(['admin', 'public', 'internal']),
                             set(bootstrap.endpoints))

            urls = {'public': self.public_url,
                    'internal': self.internal_url,
                    'admin': self.admin_url}

            for interface, url in urls.items():
                endpoint_id = bootstrap.endpoints[interface]
                endpoint = bootstrap.catalog_manager.get_endpoint(endpoint_id)

                self.assertEqual(self.region_id, endpoint['region_id'])
                self.assertEqual(url, endpoint['url'])
                self.assertEqual(svc['id'], endpoint['service_id'])
                self.assertEqual(interface, endpoint['interface'])

    def test_bootstrap_is_idempotent(self):
        # NOTE(morganfainberg): Ensure we can run bootstrap multiple times
        # without erroring.
        bootstrap = cli.BootStrap()
        self._do_test_bootstrap(bootstrap)
        self._do_test_bootstrap(bootstrap)

    def test_bootstrap_recovers_user(self):
        bootstrap = cli.BootStrap()
        self._do_test_bootstrap(bootstrap)

        # Completely lock the user out.
        user_id = bootstrap.identity_manager.get_user_by_name(
            bootstrap.username,
            'default')['id']
        bootstrap.identity_manager.update_user(
            user_id,
            {'enabled': False,
             'password': uuid.uuid4().hex})

        # The second bootstrap run will recover the account.
        self._do_test_bootstrap(bootstrap)

        # Sanity check that the original password works again.
        bootstrap.identity_manager.authenticate(
            self.make_request(),
            user_id,
            bootstrap.password)


class CliBootStrapTestCaseWithEnvironment(CliBootStrapTestCase):

    def config(self, config_files):
        CONF(args=['bootstrap'], project='keystone',
             default_config_files=config_files)

    def setUp(self):
        super(CliBootStrapTestCaseWithEnvironment, self).setUp()
        self.password = uuid.uuid4().hex
        self.username = uuid.uuid4().hex
        self.project_name = uuid.uuid4().hex
        self.role_name = uuid.uuid4().hex
        self.service_name = uuid.uuid4().hex
        self.public_url = uuid.uuid4().hex
        self.internal_url = uuid.uuid4().hex
        self.admin_url = uuid.uuid4().hex
        self.region_id = uuid.uuid4().hex
        self.default_domain = {
            'id': CONF.identity.default_domain_id,
            'name': 'Default',
        }
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_PASSWORD',
                                         newvalue=self.password))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_USERNAME',
                                         newvalue=self.username))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_PROJECT_NAME',
                                         newvalue=self.project_name))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_ROLE_NAME',
                                         newvalue=self.role_name))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_SERVICE_NAME',
                                         newvalue=self.service_name))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_PUBLIC_URL',
                                         newvalue=self.public_url))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_INTERNAL_URL',
                                         newvalue=self.internal_url))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_ADMIN_URL',
                                         newvalue=self.admin_url))
        self.useFixture(
            fixtures.EnvironmentVariable('OS_BOOTSTRAP_REGION_ID',
                                         newvalue=self.region_id))

    def test_assignment_created_with_user_exists(self):
        # test assignment can be created if user already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        user_ref = unit.new_user_ref(self.default_domain['id'],
                                     name=self.username,
                                     password=self.password)
        bootstrap.identity_manager.create_user(user_ref)
        self._do_test_bootstrap(bootstrap)

    def test_assignment_created_with_project_exists(self):
        # test assignment can be created if project already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        project_ref = unit.new_project_ref(self.default_domain['id'],
                                           name=self.project_name)
        bootstrap.resource_manager.create_project(project_ref['id'],
                                                  project_ref)
        self._do_test_bootstrap(bootstrap)

    def test_assignment_created_with_role_exists(self):
        # test assignment can be created if role already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        role = unit.new_role_ref(name=self.role_name)
        bootstrap.role_manager.create_role(role['id'], role)
        self._do_test_bootstrap(bootstrap)

    def test_assignment_created_with_region_exists(self):
        # test assignment can be created if role already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        region = unit.new_region_ref(id=self.region_id)
        bootstrap.catalog_manager.create_region(region)
        self._do_test_bootstrap(bootstrap)

    def test_endpoints_created_with_service_exists(self):
        # test assignment can be created if role already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        service = unit.new_service_ref(name=self.service_name)
        bootstrap.catalog_manager.create_service(service['id'], service)
        self._do_test_bootstrap(bootstrap)

    def test_endpoints_created_with_endpoint_exists(self):
        # test assignment can be created if role already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        service = unit.new_service_ref(name=self.service_name)
        bootstrap.catalog_manager.create_service(service['id'], service)

        region = unit.new_region_ref(id=self.region_id)
        bootstrap.catalog_manager.create_region(region)

        endpoint = unit.new_endpoint_ref(interface='public',
                                         service_id=service['id'],
                                         url=self.public_url,
                                         region_id=self.region_id)
        bootstrap.catalog_manager.create_endpoint(endpoint['id'], endpoint)

        self._do_test_bootstrap(bootstrap)


class CliDomainConfigAllTestCase(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        self.useFixture(database.Database())
        super(CliDomainConfigAllTestCase, self).setUp()
        self.load_backends()
        self.config_fixture.config(
            group='identity',
            domain_config_dir=unit.TESTCONF + '/domain_configs_multi_ldap')
        self.domain_count = 3
        self.setup_initial_domains()

    def config_files(self):
        self.config_fixture.register_cli_opt(cli.command_opt)
        config_files = super(CliDomainConfigAllTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def cleanup_domains(self):
        for domain in self.domains:
            if domain == 'domain_default':
                # Not allowed to delete the default domain, but should at least
                # delete any domain-specific config for it.
                self.domain_config_api.delete_config(
                    CONF.identity.default_domain_id)
                continue
            this_domain = self.domains[domain]
            this_domain['enabled'] = False
            self.resource_api.update_domain(this_domain['id'], this_domain)
            self.resource_api.delete_domain(this_domain['id'])
        self.domains = {}

    def config(self, config_files):
        CONF(args=['domain_config_upload', '--all'], project='keystone',
             default_config_files=config_files)

    def setup_initial_domains(self):

        def create_domain(domain):
            return self.resource_api.create_domain(domain['id'], domain)

        self.domains = {}
        self.addCleanup(self.cleanup_domains)
        for x in range(1, self.domain_count):
            domain = 'domain%s' % x
            self.domains[domain] = create_domain(
                {'id': uuid.uuid4().hex, 'name': domain})
        self.default_domain = unit.new_domain_ref(
            description=u'The default domain',
            id=CONF.identity.default_domain_id,
            name=u'Default')
        self.domains['domain_default'] = create_domain(self.default_domain)

    def test_config_upload(self):
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
                         'list_limit': '101'}
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

        # Clear backend dependencies, since cli loads these manually
        dependency.reset()
        cli.DomainConfigUpload.main()

        res = self.domain_config_api.get_config_with_sensitive_info(
            CONF.identity.default_domain_id)
        self.assertEqual(default_config, res)
        res = self.domain_config_api.get_config_with_sensitive_info(
            self.domains['domain1']['id'])
        self.assertEqual(domain1_config, res)
        res = self.domain_config_api.get_config_with_sensitive_info(
            self.domains['domain2']['id'])
        self.assertEqual(domain2_config, res)


class CliDomainConfigSingleDomainTestCase(CliDomainConfigAllTestCase):

    def config(self, config_files):
        CONF(args=['domain_config_upload', '--domain-name', 'Default'],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        # The values below are the same as in the domain_configs_multi_ldap
        # directory of test config_files.
        default_config = {
            'ldap': {'url': 'fake://memory',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=example,cn=com'},
            'identity': {'driver': 'ldap'}
        }

        # Clear backend dependencies, since cli loads these manually
        dependency.reset()
        cli.DomainConfigUpload.main()

        res = self.domain_config_api.get_config_with_sensitive_info(
            CONF.identity.default_domain_id)
        self.assertEqual(default_config, res)
        res = self.domain_config_api.get_config_with_sensitive_info(
            self.domains['domain1']['id'])
        self.assertEqual({}, res)
        res = self.domain_config_api.get_config_with_sensitive_info(
            self.domains['domain2']['id'])
        self.assertEqual({}, res)

    def test_no_overwrite_config(self):
        # Create a config for the default domain
        default_config = {
            'ldap': {'url': uuid.uuid4().hex},
            'identity': {'driver': 'ldap'}
        }
        self.domain_config_api.create_config(
            CONF.identity.default_domain_id, default_config)

        # Now try and upload the settings in the configuration file for the
        # default domain
        dependency.reset()
        with mock.patch('six.moves.builtins.print') as mock_print:
            self.assertRaises(unit.UnexpectedExit, cli.DomainConfigUpload.main)
            file_name = ('keystone.%s.conf' % self.default_domain['name'])
            error_msg = _(
                'Domain: %(domain)s already has a configuration defined - '
                'ignoring file: %(file)s.') % {
                    'domain': self.default_domain['name'],
                    'file': os.path.join(CONF.identity.domain_config_dir,
                                         file_name)}
            mock_print.assert_has_calls([mock.call(error_msg)])

        res = self.domain_config_api.get_config(
            CONF.identity.default_domain_id)
        # The initial config should not have been overwritten
        self.assertEqual(default_config, res)


class CliDomainConfigNoOptionsTestCase(CliDomainConfigAllTestCase):

    def config(self, config_files):
        CONF(args=['domain_config_upload'],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        dependency.reset()
        with mock.patch('six.moves.builtins.print') as mock_print:
            self.assertRaises(unit.UnexpectedExit, cli.DomainConfigUpload.main)
            mock_print.assert_has_calls(
                [mock.call(
                    _('At least one option must be provided, use either '
                      '--all or --domain-name'))])


class CliDomainConfigTooManyOptionsTestCase(CliDomainConfigAllTestCase):

    def config(self, config_files):
        CONF(args=['domain_config_upload', '--all', '--domain-name',
                   'Default'],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        dependency.reset()
        with mock.patch('six.moves.builtins.print') as mock_print:
            self.assertRaises(unit.UnexpectedExit, cli.DomainConfigUpload.main)
            mock_print.assert_has_calls(
                [mock.call(_('The --all option cannot be used with '
                             'the --domain-name option'))])


class CliDomainConfigInvalidDomainTestCase(CliDomainConfigAllTestCase):

    def config(self, config_files):
        self.invalid_domain_name = uuid.uuid4().hex
        CONF(args=['domain_config_upload', '--domain-name',
                   self.invalid_domain_name],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        dependency.reset()
        with mock.patch('six.moves.builtins.print') as mock_print:
            self.assertRaises(unit.UnexpectedExit, cli.DomainConfigUpload.main)
            file_name = 'keystone.%s.conf' % self.invalid_domain_name
            error_msg = (_(
                'Invalid domain name: %(domain)s found in config file name: '
                '%(file)s - ignoring this file.') % {
                    'domain': self.invalid_domain_name,
                    'file': os.path.join(CONF.identity.domain_config_dir,
                                         file_name)})
            mock_print.assert_has_calls([mock.call(error_msg)])


class TestDomainConfigFinder(unit.BaseTestCase):

    def setUp(self):
        super(TestDomainConfigFinder, self).setUp()
        self.logging = self.useFixture(fixtures.LoggerFixture())

    @mock.patch('os.walk')
    def test_finder_ignores_files(self, mock_walk):
        mock_walk.return_value = [
            ['.', [], ['file.txt', 'keystone.conf', 'keystone.domain0.conf']],
        ]

        domain_configs = list(cli._domain_config_finder('.'))

        expected_domain_configs = [('./keystone.domain0.conf', 'domain0')]
        self.assertThat(domain_configs,
                        matchers.Equals(expected_domain_configs))

        expected_msg_template = ('Ignoring file (%s) while scanning '
                                 'domain config directory')
        self.assertThat(
            self.logging.output,
            matchers.Contains(expected_msg_template % 'file.txt'))
        self.assertThat(
            self.logging.output,
            matchers.Contains(expected_msg_template % 'keystone.conf'))


class CliDBSyncTestCase(unit.BaseTestCase):

    class FakeConfCommand(object):
        def __init__(self, parent):
            self.extension = False
            self.expand = parent.command_expand
            self.migrate = parent.command_migrate
            self.contract = parent.command_contract
            self.version = None

    def setUp(self):
        super(CliDBSyncTestCase, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)
        migration_helpers.offline_sync_database_to_version = mock.Mock()
        migration_helpers.expand_schema = mock.Mock()
        migration_helpers.migrate_data = mock.Mock()
        migration_helpers.contract_schema = mock.Mock()
        self.command_expand = False
        self.command_migrate = False
        self.command_contract = False

    def _assert_correct_call(self, mocked_function):
        for func in [migration_helpers.offline_sync_database_to_version,
                     migration_helpers.expand_schema,
                     migration_helpers.migrate_data,
                     migration_helpers.contract_schema]:
            if func == mocked_function:
                self.assertTrue(func.called)
            else:
                self.assertFalse(func.called)

    def test_db_sync(self):
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(
            migration_helpers.offline_sync_database_to_version)

    def test_db_sync_expand(self):
        self.command_expand = True
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(migration_helpers.expand_schema)

    def test_db_sync_migrate(self):
        self.command_migrate = True
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(migration_helpers.migrate_data)

    def test_db_sync_contract(self):
        self.command_contract = True
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(migration_helpers.contract_schema)


class TestMappingPopulate(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        sqldb = self.useFixture(database.Database())
        super(TestMappingPopulate, self).setUp()
        self.ldapdb = self.useFixture(ldapdb.LDAPDatabase())
        self.ldapdb.clear()

        self.load_backends()

        sqldb.recreate()
        self.load_fixtures(default_fixtures)

    def config_files(self):
        self.config_fixture.register_cli_opt(cli.command_opt)
        config_files = super(TestMappingPopulate, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap_sql.conf'))
        return config_files

    def config_overrides(self):
        super(TestMappingPopulate, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def config(self, config_files):
        CONF(args=['mapping_populate', '--domain-name', 'Default'],
             project='keystone',
             default_config_files=config_files)

    def test_mapping_populate(self):
        # mapping_populate should create id mappings. Test plan:
        # 0. Purge mappings
        # 1. Fetch user list directly via backend. It will not create any
        #    mappings because it bypasses identity manager
        # 2. Verify that users have no public_id yet
        # 3. Execute mapping_populate. It should create id mappings
        # 4. For the same users verify that they have public_id now
        purge_filter = {}
        self.id_mapping_api.purge_mappings(purge_filter)
        hints = None
        users = self.identity_api.driver.list_users(hints)
        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNone(self.id_mapping_api.get_public_id(local_entity))

        dependency.reset()  # backends are loaded again in the command handler
        cli.MappingPopulate.main()

        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNotNone(
                self.id_mapping_api.get_public_id(local_entity))
