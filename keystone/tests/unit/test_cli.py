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

import logging
import os
import uuid

import fixtures
import mock
import oslo_config.fixture
from oslo_log import log
from oslotest import mockpatch
from six.moves import configparser
from six.moves import range
from testtools import matchers

from keystone.auth import controllers
from keystone.cmd import cli
from keystone.cmd.doctor import caching
from keystone.cmd.doctor import credential
from keystone.cmd.doctor import database as doc_database
from keystone.cmd.doctor import debug
from keystone.cmd.doctor import federation
from keystone.cmd.doctor import ldap
from keystone.cmd.doctor import security_compliance
from keystone.cmd.doctor import tokens
from keystone.cmd.doctor import tokens_fernet
from keystone.common import dependency
from keystone.common.sql import upgrades
import keystone.conf
from keystone import exception
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
        self.config_fixture.config(group='token', driver='kvs')
        log_info = self.useFixture(fixtures.FakeLogger(level=log.WARN))
        cli.TokenFlush.main()
        self.assertIn("token_flush command had no effect", log_info.output)


class CliNoConfigTestCase(unit.BaseTestCase):

    def setUp(self):
        self.config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
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
        self.assertIs(1, len(role_list))
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

    def test_bootstrap_is_idempotent_when_password_does_not_change(self):
        # NOTE(morganfainberg): Ensure we can run bootstrap with the same
        # configuration multiple times without erroring.
        bootstrap = cli.BootStrap()
        self._do_test_bootstrap(bootstrap)
        v3_token_controller = controllers.Auth()
        v3_password_data = {
            'identity': {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": bootstrap.username,
                        "password": bootstrap.password,
                        "domain": {
                            "id": CONF.identity.default_domain_id
                        }
                    }
                }
            }
        }
        auth_response = v3_token_controller.authenticate_for_token(
            self.make_request(), v3_password_data)
        token = auth_response.headers['X-Subject-Token']
        self._do_test_bootstrap(bootstrap)
        # build validation request
        request = self.make_request(is_admin=True)
        request.context_dict['subject_token_id'] = token
        # Make sure the token we authenticate for is still valid.
        v3_token_controller.validate_token(request)

    def test_bootstrap_is_not_idempotent_when_password_does_change(self):
        # NOTE(lbragstad): Ensure bootstrap isn't idempotent when run with
        # different arguments or configuration values.
        bootstrap = cli.BootStrap()
        self._do_test_bootstrap(bootstrap)
        v3_token_controller = controllers.Auth()
        v3_password_data = {
            'identity': {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": bootstrap.username,
                        "password": bootstrap.password,
                        "domain": {
                            "id": CONF.identity.default_domain_id
                        }
                    }
                }
            }
        }
        auth_response = v3_token_controller.authenticate_for_token(
            self.make_request(), v3_password_data)
        token = auth_response.headers['X-Subject-Token']
        os.environ['OS_BOOTSTRAP_PASSWORD'] = uuid.uuid4().hex
        self._do_test_bootstrap(bootstrap)
        # build validation request
        request = self.make_request(is_admin=True)
        request.context_dict['subject_token_id'] = token
        # Since the user account was recovered with a different password, we
        # shouldn't be able to validate this token. Bootstrap should have
        # persisted a revocation event because the user's password was updated.
        # Since this token was obtained using the original password, it should
        # now be invalid.
        self.assertRaises(
            exception.TokenNotFound,
            v3_token_controller.validate_token,
            request
        )

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

    def test_bootstrap_creates_default_role(self):
        bootstrap = cli.BootStrap()
        try:
            role = bootstrap.role_manager.get_role(CONF.member_role_id)
            self.fail('Member Role is created and should not be.')
        except exception.RoleNotFound:
            pass

        self._do_test_bootstrap(bootstrap)
        role = bootstrap.role_manager.get_role(CONF.member_role_id)
        self.assertEqual(role['name'], CONF.member_role_name)
        self.assertEqual(role['id'], CONF.member_role_id)


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
        # test assignment can be created if region already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        region = unit.new_region_ref(id=self.region_id)
        bootstrap.catalog_manager.create_region(region)
        self._do_test_bootstrap(bootstrap)

    def test_endpoints_created_with_service_exists(self):
        # test assignment can be created if service already exists.
        bootstrap = cli.BootStrap()
        bootstrap.resource_manager.create_domain(self.default_domain['id'],
                                                 self.default_domain)
        service = unit.new_service_ref(name=self.service_name)
        bootstrap.catalog_manager.create_service(service['id'], service)
        self._do_test_bootstrap(bootstrap)

    def test_endpoints_created_with_endpoint_exists(self):
        # test assignment can be created if endpoint already exists.
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
        self.logging = self.useFixture(
            fixtures.FakeLogger(level=logging.INFO))

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
        self.config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)
        upgrades.offline_sync_database_to_version = mock.Mock()
        upgrades.expand_schema = mock.Mock()
        upgrades.migrate_data = mock.Mock()
        upgrades.contract_schema = mock.Mock()
        self.command_expand = False
        self.command_migrate = False
        self.command_contract = False

    def _assert_correct_call(self, mocked_function):
        for func in [upgrades.offline_sync_database_to_version,
                     upgrades.expand_schema,
                     upgrades.migrate_data,
                     upgrades.contract_schema]:
            if func == mocked_function:
                self.assertTrue(func.called)
            else:
                self.assertFalse(func.called)

    def test_db_sync(self):
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(
            upgrades.offline_sync_database_to_version)

    def test_db_sync_expand(self):
        self.command_expand = True
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(upgrades.expand_schema)

    def test_db_sync_migrate(self):
        self.command_migrate = True
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(upgrades.migrate_data)

    def test_db_sync_contract(self):
        self.command_contract = True
        self.useFixture(mockpatch.PatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(upgrades.contract_schema)


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

    def test_bad_domain_name(self):
        CONF(args=['mapping_populate', '--domain-name', uuid.uuid4().hex],
             project='keystone')
        dependency.reset()  # backends are loaded again in the command handler
        # NOTE: assertEqual is used on purpose. assertFalse passes with None.
        self.assertEqual(False, cli.MappingPopulate.main())


class CliDomainConfigUploadNothing(unit.BaseTestCase):

    def setUp(self):
        super(CliDomainConfigUploadNothing, self).setUp()

        config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
        config_fixture.register_cli_opt(cli.command_opt)

        # NOTE(dstanek): since this is not testing any database
        # functionality there is no need to go through the motions and
        # setup a test database.
        def fake_load_backends(self):
            self.resource_manager = mock.Mock()
        self.useFixture(mockpatch.PatchObject(
            cli.DomainConfigUploadFiles, 'load_backends', fake_load_backends))

        tempdir = self.useFixture(fixtures.TempDir())
        config_fixture.config(group='identity', domain_config_dir=tempdir.path)

        self.logging = self.useFixture(
            fixtures.FakeLogger(level=logging.DEBUG))

    def test_uploading_all_from_an_empty_directory(self):
        CONF(args=['domain_config_upload', '--all'], project='keystone',
             default_config_files=[])
        cli.DomainConfigUpload.main()

        expected_msg = ('No domain configs uploaded from %r' %
                        CONF.identity.domain_config_dir)
        self.assertThat(self.logging.output,
                        matchers.Contains(expected_msg))


class CachingDoctorTests(unit.TestCase):

    def test_symptom_caching_disabled(self):
        # Symptom Detected: Caching disabled
        self.config_fixture.config(group='cache', enabled=False)
        self.assertTrue(caching.symptom_caching_disabled())

        # No Symptom Detected: Caching is enabled
        self.config_fixture.config(group='cache', enabled=True)
        self.assertFalse(caching.symptom_caching_disabled())

    def test_caching_symptom_caching_enabled_without_a_backend(self):
        # Success Case: Caching enabled and backend configured
        self.config_fixture.config(group='cache', enabled=True)
        self.config_fixture.config(group='cache', backend='dogpile.cache.null')
        self.assertTrue(caching.symptom_caching_enabled_without_a_backend())

        # Failure Case 1: Caching disabled and backend not configured
        self.config_fixture.config(group='cache', enabled=False)
        self.config_fixture.config(group='cache', backend='dogpile.cache.null')
        self.assertFalse(caching.symptom_caching_enabled_without_a_backend())

        # Failure Case 2: Caching disabled and backend configured
        self.config_fixture.config(group='cache', enabled=False)
        self.config_fixture.config(group='cache',
                                   backend='dogpile.cache.memory')
        self.assertFalse(caching.symptom_caching_enabled_without_a_backend())

        # Failure Case 3: Caching enabled and backend configured
        self.config_fixture.config(group='cache', enabled=True)
        self.config_fixture.config(group='cache',
                                   backend='dogpile.cache.memory')
        self.assertFalse(caching.symptom_caching_enabled_without_a_backend())


class CredentialDoctorTests(unit.TestCase):

    def test_credential_and_fernet_key_repositories_match(self):
        # Symptom Detected: Key repository paths are not unique
        directory = self.useFixture(fixtures.TempDir()).path
        self.config_fixture.config(group='credential',
                                   key_repository=directory)
        self.config_fixture.config(group='fernet_tokens',
                                   key_repository=directory)
        self.assertTrue(credential.symptom_unique_key_repositories())

    def test_credential_and_fernet_key_repositories_are_unique(self):
        # No Symptom Detected: Key repository paths are unique
        self.config_fixture.config(group='credential',
                                   key_repository='/etc/keystone/cred-repo')
        self.config_fixture.config(group='fernet_tokens',
                                   key_repository='/etc/keystone/fernet-repo')
        self.assertFalse(credential.symptom_unique_key_repositories())

    @mock.patch('keystone.cmd.doctor.credential.utils')
    def test_usability_of_cred_fernet_key_repo_raised(self, mock_utils):
        # Symptom Detected: credential fernet key repository is world readable
        self.config_fixture.config(group='credential', provider='fernet')
        mock_utils.FernetUtils().validate_key_repository.return_value = False
        self.assertTrue(
            credential.symptom_usability_of_credential_fernet_key_repository())

    @mock.patch('keystone.cmd.doctor.credential.utils')
    def test_usability_of_cred_fernet_key_repo_not_raised(self, mock_utils):
        # No Symptom Detected: Custom driver is used
        self.config_fixture.config(group='credential', provider='my-driver')
        mock_utils.FernetUtils().validate_key_repository.return_value = True
        self.assertFalse(
            credential.symptom_usability_of_credential_fernet_key_repository())

        # No Symptom Detected: key repository is not world readable
        self.config_fixture.config(group='credential', provider='fernet')
        mock_utils.FernetUtils().validate_key_repository.return_value = True
        self.assertFalse(
            credential.symptom_usability_of_credential_fernet_key_repository())

    @mock.patch('keystone.cmd.doctor.credential.utils')
    def test_keys_in_credential_fernet_key_repository_raised(self, mock_utils):
        # Symptom Detected: Key repo is empty
        self.config_fixture.config(group='credential', provider='fernet')
        mock_utils.FernetUtils().load_keys.return_value = False
        self.assertTrue(
            credential.symptom_keys_in_credential_fernet_key_repository())

    @mock.patch('keystone.cmd.doctor.credential.utils')
    def test_keys_in_credential_fernet_key_repository_not_raised(
            self, mock_utils):
        # No Symptom Detected: Custom driver is used
        self.config_fixture.config(group='credential', provider='my-driver')
        mock_utils.FernetUtils().load_keys.return_value = True
        self.assertFalse(
            credential.symptom_keys_in_credential_fernet_key_repository())

        # No Symptom Detected: Key repo is not empty, fernet is current driver
        self.config_fixture.config(group='credential', provider='fernet')
        mock_utils.FernetUtils().load_keys.return_value = True
        self.assertFalse(
            credential.symptom_keys_in_credential_fernet_key_repository())


class DatabaseDoctorTests(unit.TestCase):

    def test_symptom_is_raised_if_database_connection_is_SQLite(self):
        # Symptom Detected: Database connection is sqlite
        self.config_fixture.config(
            group='database',
            connection='sqlite:///mydb')
        self.assertTrue(
            doc_database.symptom_database_connection_is_not_SQLite())

        # No Symptom Detected: Database connection is MySQL
        self.config_fixture.config(
            group='database',
            connection='mysql+mysqlconnector://admin:secret@localhost/mydb')
        self.assertFalse(
            doc_database.symptom_database_connection_is_not_SQLite())


class DebugDoctorTests(unit.TestCase):

    def test_symptom_debug_mode_is_enabled(self):
        # Symptom Detected: Debug mode is enabled
        self.config_fixture.config(debug=True)
        self.assertTrue(debug.symptom_debug_mode_is_enabled())

        # No Symptom Detected: Debug mode is disabled
        self.config_fixture.config(debug=False)
        self.assertFalse(debug.symptom_debug_mode_is_enabled())


class FederationDoctorTests(unit.TestCase):

    def test_symptom_comma_in_SAML_public_certificate_path(self):
        # Symptom Detected: There is a comma in path to public cert file
        self.config_fixture.config(group='saml', certfile='file,cert.pem')
        self.assertTrue(
            federation.symptom_comma_in_SAML_public_certificate_path())

        # No Symptom Detected: There is no comma in the path
        self.config_fixture.config(group='saml', certfile='signing_cert.pem')
        self.assertFalse(
            federation.symptom_comma_in_SAML_public_certificate_path())

    def test_symptom_comma_in_SAML_private_key_file_path(self):
        # Symptom Detected: There is a comma in path to private key file
        self.config_fixture.config(group='saml', keyfile='file,key.pem')
        self.assertTrue(
            federation.symptom_comma_in_SAML_private_key_file_path())

        # No Symptom Detected: There is no comma in the path
        self.config_fixture.config(group='saml', keyfile='signing_key.pem')
        self.assertFalse(
            federation.symptom_comma_in_SAML_private_key_file_path())


class LdapDoctorTests(unit.TestCase):

    def test_user_enabled_emulation_dn_ignored_raised(self):
        # Symptom when user_enabled_emulation_dn is being ignored because the
        # user did not enable the user_enabled_emulation
        self.config_fixture.config(group='ldap', user_enabled_emulation=False)
        self.config_fixture.config(
            group='ldap',
            user_enabled_emulation_dn='cn=enabled_users,dc=example,dc=com')
        self.assertTrue(
            ldap.symptom_LDAP_user_enabled_emulation_dn_ignored())

    def test_user_enabled_emulation_dn_ignored_not_raised(self):
        # No symptom when configuration set properly
        self.config_fixture.config(group='ldap', user_enabled_emulation=True)
        self.config_fixture.config(
            group='ldap',
            user_enabled_emulation_dn='cn=enabled_users,dc=example,dc=com')
        self.assertFalse(
            ldap.symptom_LDAP_user_enabled_emulation_dn_ignored())
        # No symptom when both configurations disabled
        self.config_fixture.config(group='ldap', user_enabled_emulation=False)
        self.config_fixture.config(group='ldap',
                                   user_enabled_emulation_dn=None)
        self.assertFalse(
            ldap.symptom_LDAP_user_enabled_emulation_dn_ignored())

    def test_user_enabled_emulation_use_group_config_ignored_raised(self):
        # Symptom when user enabled emulation isn't enabled but group_config is
        # enabled
        self.config_fixture.config(group='ldap', user_enabled_emulation=False)
        self.config_fixture.config(
            group='ldap',
            user_enabled_emulation_use_group_config=True)
        self.assertTrue(
            ldap.
            symptom_LDAP_user_enabled_emulation_use_group_config_ignored())

    def test_user_enabled_emulation_use_group_config_ignored_not_raised(self):
        # No symptom when configuration deactivated
        self.config_fixture.config(group='ldap', user_enabled_emulation=False)
        self.config_fixture.config(
            group='ldap',
            user_enabled_emulation_use_group_config=False)
        self.assertFalse(
            ldap.
            symptom_LDAP_user_enabled_emulation_use_group_config_ignored())
        # No symptom when configurations set properly
        self.config_fixture.config(group='ldap', user_enabled_emulation=True)
        self.config_fixture.config(
            group='ldap',
            user_enabled_emulation_use_group_config=True)
        self.assertFalse(
            ldap.
            symptom_LDAP_user_enabled_emulation_use_group_config_ignored())

    def test_group_members_are_ids_disabled_raised(self):
        # Symptom when objectclass is set to posixGroup but members_are_ids are
        # not enabled
        self.config_fixture.config(group='ldap',
                                   group_objectclass='posixGroup')
        self.config_fixture.config(group='ldap',
                                   group_members_are_ids=False)
        self.assertTrue(ldap.symptom_LDAP_group_members_are_ids_disabled())

    def test_group_members_are_ids_disabled_not_raised(self):
        # No symptom when the configurations are set properly
        self.config_fixture.config(group='ldap',
                                   group_objectclass='posixGroup')
        self.config_fixture.config(group='ldap',
                                   group_members_are_ids=True)
        self.assertFalse(ldap.symptom_LDAP_group_members_are_ids_disabled())
        # No symptom when configuration deactivated
        self.config_fixture.config(group='ldap',
                                   group_objectclass='groupOfNames')
        self.config_fixture.config(group='ldap',
                                   group_members_are_ids=False)
        self.assertFalse(ldap.symptom_LDAP_group_members_are_ids_disabled())

    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_file_based_domain_specific_configs_raised(self, mocked_isdir,
                                                       mocked_listdir):
        self.config_fixture.config(
            group='identity',
            domain_specific_drivers_enabled=True)
        self.config_fixture.config(
            group='identity',
            domain_configurations_from_database=False)

        # Symptom if there is no existing directory
        mocked_isdir.return_value = False
        self.assertTrue(ldap.symptom_LDAP_file_based_domain_specific_configs())

        # Symptom if there is an invalid filename inside the domain directory
        mocked_isdir.return_value = True
        mocked_listdir.return_value = ['openstack.domains.conf']
        self.assertTrue(ldap.symptom_LDAP_file_based_domain_specific_configs())

    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_file_based_domain_specific_configs_not_raised(self, mocked_isdir,
                                                           mocked_listdir):
        # No symptom if both configurations deactivated
        self.config_fixture.config(
            group='identity',
            domain_specific_drivers_enabled=False)
        self.config_fixture.config(
            group='identity',
            domain_configurations_from_database=False)
        self.assertFalse(
            ldap.symptom_LDAP_file_based_domain_specific_configs())

        # No symptom if directory exists with no invalid filenames
        self.config_fixture.config(
            group='identity',
            domain_specific_drivers_enabled=True)
        self.config_fixture.config(
            group='identity',
            domain_configurations_from_database=False)
        mocked_isdir.return_value = True
        mocked_listdir.return_value = ['keystone.domains.conf']
        self.assertFalse(
            ldap.symptom_LDAP_file_based_domain_specific_configs())

    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    @mock.patch('keystone.cmd.doctor.ldap.configparser.ConfigParser')
    def test_file_based_domain_specific_configs_formatted_correctly_raised(
            self, mocked_parser, mocked_isdir, mocked_listdir):
        symptom = ('symptom_LDAP_file_based_domain_specific_configs'
                   '_formatted_correctly')
        # Symptom Detected: Ldap domain specific configuration files are not
        # formatted correctly
        self.config_fixture.config(
            group='identity',
            domain_specific_drivers_enabled=True)
        self.config_fixture.config(
            group='identity',
            domain_configurations_from_database=False)
        mocked_isdir.return_value = True

        mocked_listdir.return_value = ['keystone.domains.conf']
        mock_instance = mock.MagicMock()
        mock_instance.read.side_effect = configparser.Error('No Section')
        mocked_parser.return_value = mock_instance

        self.assertTrue(getattr(ldap, symptom)())

    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_file_based_domain_specific_configs_formatted_correctly_not_raised(
            self, mocked_isdir, mocked_listdir):
        symptom = ('symptom_LDAP_file_based_domain_specific_configs'
                   '_formatted_correctly')
        # No Symptom Detected: Domain_specific drivers is not enabled
        self.config_fixture.config(
            group='identity',
            domain_specific_drivers_enabled=False)
        self.assertFalse(getattr(ldap, symptom)())

        # No Symptom Detected: Domain configuration from database is enabled
        self.config_fixture.config(
            group='identity',
            domain_specific_drivers_enabled=True)
        self.assertFalse(getattr(ldap, symptom)())
        self.config_fixture.config(
            group='identity',
            domain_configurations_from_database=True)
        self.assertFalse(getattr(ldap, symptom)())

        # No Symptom Detected: The directory in domain_config_dir doesn't exist
        mocked_isdir.return_value = False
        self.assertFalse(getattr(ldap, symptom)())

        # No Symptom Detected: domain specific drivers are enabled, domain
        # configurations from database are disabled, directory exists, and no
        # exceptions found.
        self.config_fixture.config(
            group='identity',
            domain_configurations_from_database=False)
        mocked_isdir.return_value = True
        # An empty directory should not raise this symptom
        self.assertFalse(getattr(ldap, symptom)())

        # Test again with a file inside the directory
        mocked_listdir.return_value = ['keystone.domains.conf']
        self.assertFalse(getattr(ldap, symptom)())


class SecurityComplianceDoctorTests(unit.TestCase):

    def test_minimum_password_age_greater_than_password_expires_days(self):
        # Symptom Detected: Minimum password age is greater than the password
        # expires days. Both values are positive integers greater than zero.
        self.config_fixture.config(group='security_compliance',
                                   minimum_password_age=2)
        self.config_fixture.config(group='security_compliance',
                                   password_expires_days=1)
        self.assertTrue(
            security_compliance.
            symptom_minimum_password_age_greater_than_expires_days())

    def test_minimum_password_age_equal_to_password_expires_days(self):
        # Symptom Detected: Minimum password age is equal to the password
        # expires days. Both values are positive integers greater than zero.
        self.config_fixture.config(group='security_compliance',
                                   minimum_password_age=1)
        self.config_fixture.config(group='security_compliance',
                                   password_expires_days=1)
        self.assertTrue(
            security_compliance.
            symptom_minimum_password_age_greater_than_expires_days())

    def test_minimum_password_age_less_than_password_expires_days(self):
        # No Symptom Detected: Minimum password age is less than password
        # expires days. Both values are positive integers greater than zero.
        self.config_fixture.config(group='security_compliance',
                                   minimum_password_age=1)
        self.config_fixture.config(group='security_compliance',
                                   password_expires_days=2)
        self.assertFalse(
            security_compliance.
            symptom_minimum_password_age_greater_than_expires_days())

    def test_minimum_password_age_and_password_expires_days_deactivated(self):
        # No Symptom Detected: Both values are deactivated to 0
        self.config_fixture.config(group='security_compliance',
                                   minimum_password_age=0)
        self.config_fixture.config(group='security_compliance',
                                   password_expires_days=0)
        self.assertFalse(
            security_compliance.
            symptom_minimum_password_age_greater_than_expires_days())

    def test_invalid_password_regular_expression(self):
        # Symptom Detected: Regular expression is invalid
        self.config_fixture.config(
            group='security_compliance',
            password_regex='^^(??=.*\d)$')
        self.assertTrue(
            security_compliance.symptom_invalid_password_regular_expression())

    def test_valid_password_regular_expression(self):
        # No Symptom Detected: Regular expression is valid
        self.config_fixture.config(
            group='security_compliance',
            password_regex='^(?=.*\d)(?=.*[a-zA-Z]).{7,}$')
        self.assertFalse(
            security_compliance.symptom_invalid_password_regular_expression())

    def test_password_regular_expression_deactivated(self):
        # No Symptom Detected: Regular expression deactivated to None
        self.config_fixture.config(
            group='security_compliance',
            password_regex=None)
        self.assertFalse(
            security_compliance.symptom_invalid_password_regular_expression())

    def test_password_regular_expression_description_not_set(self):
        # Symptom Detected: Regular expression is set but description is not
        self.config_fixture.config(
            group='security_compliance',
            password_regex='^(?=.*\d)(?=.*[a-zA-Z]).{7,}$')
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=None)
        self.assertTrue(
            security_compliance.
            symptom_password_regular_expression_description_not_set())

    def test_password_regular_expression_description_set(self):
        # No Symptom Detected: Regular expression and description are set
        desc = '1 letter, 1 digit, and a minimum length of 7 is required'
        self.config_fixture.config(
            group='security_compliance',
            password_regex='^(?=.*\d)(?=.*[a-zA-Z]).{7,}$')
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=desc)
        self.assertFalse(
            security_compliance.
            symptom_password_regular_expression_description_not_set())

    def test_password_regular_expression_description_deactivated(self):
        # No Symptom Detected: Regular expression and description are
        # deactivated to None
        self.config_fixture.config(
            group='security_compliance', password_regex=None)
        self.config_fixture.config(
            group='security_compliance', password_regex_description=None)
        self.assertFalse(
            security_compliance.
            symptom_password_regular_expression_description_not_set())


class TokensDoctorTests(unit.TestCase):

    def test_unreasonable_max_token_size_raised(self):
        # Symptom Detected: the max_token_size for uuid is not 32
        self.config_fixture.config(group='token', provider='uuid')
        self.config_fixture.config(max_token_size=33)
        self.assertTrue(tokens.symptom_unreasonable_max_token_size())

        # Symptom Detected: the max_token_size for fernet is greater than 255
        self.config_fixture.config(group='token', provider='fernet')
        self.config_fixture.config(max_token_size=256)
        self.assertTrue(tokens.symptom_unreasonable_max_token_size())

    def test_unreasonable_max_token_size_not_raised(self):
        # No Symptom Detected: the max_token_size for uuid is 32
        self.config_fixture.config(group='token', provider='uuid')
        self.config_fixture.config(max_token_size=32)
        self.assertFalse(tokens.symptom_unreasonable_max_token_size())

        # No Symptom Detected: the max_token_size for fernet is 255 or less
        self.config_fixture.config(group='token', provider='fernet')
        self.config_fixture.config(max_token_size=255)
        self.assertFalse(tokens.symptom_unreasonable_max_token_size())


class TokenFernetDoctorTests(unit.TestCase):

    @mock.patch('keystone.cmd.doctor.tokens_fernet.utils')
    def test_usability_of_Fernet_key_repository_raised(self, mock_utils):
        # Symptom Detected: Fernet key repo is world readable
        self.config_fixture.config(group='token', provider='fernet')
        mock_utils.FernetUtils().validate_key_repository.return_value = False
        self.assertTrue(
            tokens_fernet.symptom_usability_of_Fernet_key_repository())

    @mock.patch('keystone.cmd.doctor.tokens_fernet.utils')
    def test_usability_of_Fernet_key_repository_not_raised(self, mock_utils):
        # No Symptom Detected: UUID is used instead of fernet
        self.config_fixture.config(group='token', provider='uuid')
        mock_utils.FernetUtils().validate_key_repository.return_value = False
        self.assertFalse(
            tokens_fernet.symptom_usability_of_Fernet_key_repository())

        # No Symptom Detected: configs set properly, key repo is not world
        # readable but is user readable
        self.config_fixture.config(group='token', provider='fernet')
        mock_utils.FernetUtils().validate_key_repository.return_value = True
        self.assertFalse(
            tokens_fernet.symptom_usability_of_Fernet_key_repository())

    @mock.patch('keystone.cmd.doctor.tokens_fernet.utils')
    def test_keys_in_Fernet_key_repository_raised(self, mock_utils):
        # Symptom Detected: Fernet key repository is empty
        self.config_fixture.config(group='token', provider='fernet')
        mock_utils.FernetUtils().load_keys.return_value = False
        self.assertTrue(
            tokens_fernet.symptom_keys_in_Fernet_key_repository())

    @mock.patch('keystone.cmd.doctor.tokens_fernet.utils')
    def test_keys_in_Fernet_key_repository_not_raised(self, mock_utils):
        # No Symptom Detected: UUID is used instead of fernet
        self.config_fixture.config(group='token', provider='uuid')
        mock_utils.FernetUtils().load_keys.return_value = True
        self.assertFalse(
            tokens_fernet.symptom_usability_of_Fernet_key_repository())

        # No Symptom Detected: configs set properly, key repo has been
        # populated with keys
        self.config_fixture.config(group='token', provider='fernet')
        mock_utils.FernetUtils().load_keys.return_value = True
        self.assertFalse(
            tokens_fernet.symptom_usability_of_Fernet_key_repository())
