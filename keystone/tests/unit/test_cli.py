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

import copy
import datetime
import logging
import os
from unittest import mock
import uuid

import argparse
import configparser
import fixtures
import freezegun
import http.client
import oslo_config.fixture
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_upgradecheck import upgradecheck
from testtools import matchers

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
from keystone.cmd import status
from keystone.common import provider_api
from keystone.common.sql import upgrades
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.identity.mapping_backends import mapping as identity_mapping
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.ksfixtures import ldapdb
from keystone.tests.unit.ksfixtures import policy
from keystone.tests.unit.ksfixtures import temporaryfile
from keystone.tests.unit import mapping_fixtures


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class CliLoggingTestCase(unit.BaseTestCase):

    def setUp(self):
        self.config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)
        self.useFixture(fixtures.MockPatch(
            'oslo_config.cfg.find_config_files', return_value=[]))
        fd = self.useFixture(temporaryfile.SecureTempFile())
        self.fake_config_file = fd.file_name
        super(CliLoggingTestCase, self).setUp()

        # NOTE(crinkle): the command call doesn't have to actually work,
        # that's what the other unit tests are for. So just mock it out.
        class FakeConfCommand(object):
            def __init__(self):
                self.cmd_class = mock.Mock()
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', FakeConfCommand()))

        self.logging = self.useFixture(fixtures.FakeLogger(level=log.WARN))

    def test_absent_config_logs_warning(self):
        expected_msg = 'Config file not found, using default configs.'
        cli.main(argv=['keystone-manage', 'db_sync'])
        self.assertThat(self.logging.output, matchers.Contains(expected_msg))

    def test_present_config_does_not_log_warning(self):
        fake_argv = [
            'keystone-manage', '--config-file', self.fake_config_file, 'doctor'
        ]
        cli.main(argv=fake_argv)
        expected_msg = 'Config file not found, using default configs.'
        self.assertNotIn(expected_msg, self.logging.output)


class CliBootStrapTestCase(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        self.useFixture(database.Database())
        super(CliBootStrapTestCase, self).setUp()
        self.bootstrap = cli.BootStrap()

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
        self._do_test_bootstrap(self.bootstrap)

    def _do_test_bootstrap(self, bootstrap):
        try:
            PROVIDERS.resource_api.create_domain(
                default_fixtures.ROOT_DOMAIN['id'],
                default_fixtures.ROOT_DOMAIN)
        except exception.Conflict:
            pass

        bootstrap.do_bootstrap()
        project = PROVIDERS.resource_api.get_project_by_name(
            bootstrap.project_name,
            'default')
        user = PROVIDERS.identity_api.get_user_by_name(
            bootstrap.username,
            'default')
        admin_role = PROVIDERS.role_api.get_role(bootstrap.role_id)
        reader_role = PROVIDERS.role_api.get_role(bootstrap.reader_role_id)
        member_role = PROVIDERS.role_api.get_role(bootstrap.member_role_id)
        role_list = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user['id'],
                project['id']))
        self.assertIs(3, len(role_list))
        self.assertIn(admin_role['id'], role_list)
        self.assertIn(reader_role['id'], role_list)
        self.assertIn(member_role['id'], role_list)
        system_roles = (
            PROVIDERS.assignment_api.list_system_grants_for_user(
                user['id']
            )
        )
        self.assertIs(1, len(system_roles))
        self.assertEqual(system_roles[0]['id'], admin_role['id'])
        # NOTE(morganfainberg): Pass an empty context, it isn't used by
        # `authenticate` method.
        with self.make_request():
            PROVIDERS.identity_api.authenticate(
                user['id'],
                bootstrap.password)

        if bootstrap.region_id:
            region = PROVIDERS.catalog_api.get_region(bootstrap.region_id)
            self.assertEqual(self.region_id, region['id'])

        if bootstrap.service_id:
            svc = PROVIDERS.catalog_api.get_service(bootstrap.service_id)
            self.assertEqual(self.service_name, svc['name'])

            self.assertEqual(set(['admin', 'public', 'internal']),
                             set(bootstrap.endpoints))

            urls = {'public': self.public_url,
                    'internal': self.internal_url,
                    'admin': self.admin_url}

            for interface, url in urls.items():
                endpoint_id = bootstrap.endpoints[interface]
                endpoint = PROVIDERS.catalog_api.get_endpoint(endpoint_id)

                self.assertEqual(self.region_id, endpoint['region_id'])
                self.assertEqual(url, endpoint['url'])
                self.assertEqual(svc['id'], endpoint['service_id'])
                self.assertEqual(interface, endpoint['interface'])

    def test_bootstrap_is_idempotent_when_password_does_not_change(self):
        # NOTE(morganfainberg): Ensure we can run bootstrap with the same
        # configuration multiple times without erroring.
        self._do_test_bootstrap(self.bootstrap)
        app = self.loadapp()
        v3_password_data = {
            'auth': {
                'identity': {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.bootstrap.username,
                            "password": self.bootstrap.password,
                            "domain": {
                                "id": CONF.identity.default_domain_id
                            }
                        }
                    }
                }
            }
        }
        with app.test_client() as c:
            auth_response = c.post('/v3/auth/tokens',
                                   json=v3_password_data)
            token = auth_response.headers['X-Subject-Token']
        self._do_test_bootstrap(self.bootstrap)
        # build validation request
        with app.test_client() as c:
            # Get a new X-Auth-Token
            r = c.post(
                '/v3/auth/tokens',
                json=v3_password_data)

            # Validate the old token with our new X-Auth-Token.
            c.get('/v3/auth/tokens',
                  headers={'X-Auth-Token': r.headers['X-Subject-Token'],
                           'X-Subject-Token': token})
        admin_role = PROVIDERS.role_api.get_role(self.bootstrap.role_id)
        reader_role = PROVIDERS.role_api.get_role(
            self.bootstrap.reader_role_id)
        member_role = PROVIDERS.role_api.get_role(
            self.bootstrap.member_role_id)
        self.assertEqual(admin_role['options'], {'immutable': True})
        self.assertEqual(member_role['options'], {'immutable': True})
        self.assertEqual(reader_role['options'], {'immutable': True})

    def test_bootstrap_is_not_idempotent_when_password_does_change(self):
        # NOTE(lbragstad): Ensure bootstrap isn't idempotent when run with
        # different arguments or configuration values.
        self._do_test_bootstrap(self.bootstrap)
        app = self.loadapp()
        v3_password_data = {
            'auth': {
                'identity': {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.bootstrap.username,
                            "password": self.bootstrap.password,
                            "domain": {
                                "id": CONF.identity.default_domain_id
                            }
                        }
                    }
                }
            }
        }
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_time:
            with app.test_client() as c:
                auth_response = c.post('/v3/auth/tokens',
                                       json=v3_password_data)
                token = auth_response.headers['X-Subject-Token']
            new_passwd = uuid.uuid4().hex
            os.environ['OS_BOOTSTRAP_PASSWORD'] = new_passwd
            self._do_test_bootstrap(self.bootstrap)
            v3_password_data['auth']['identity']['password']['user'][
                'password'] = new_passwd
            # Move time forward a second to avoid rev. event capturing the new
            # auth-token since we're within a single second (possibly) for the
            # test case.
            frozen_time.tick(delta=datetime.timedelta(seconds=1))
            # Validate the old token
            with app.test_client() as c:
                # Get a new X-Auth-Token
                r = c.post('/v3/auth/tokens', json=v3_password_data)
                # Since the user account was recovered with a different
                # password, we shouldn't be able to validate this token.
                # Bootstrap should have persisted a revocation event because
                # the user's password was updated. Since this token was
                # obtained using the original password, it should now be
                # invalid.
                c.get('/v3/auth/tokens',
                      headers={'X-Auth-Token': r.headers['X-Subject-Token'],
                               'X-Subject-Token': token},
                      expected_status_code=http.client.NOT_FOUND)

    def test_bootstrap_recovers_user(self):
        self._do_test_bootstrap(self.bootstrap)

        # Completely lock the user out.
        user_id = PROVIDERS.identity_api.get_user_by_name(
            self.bootstrap.username,
            'default')['id']
        PROVIDERS.identity_api.update_user(
            user_id,
            {'enabled': False,
             'password': uuid.uuid4().hex})

        # The second bootstrap run will recover the account.
        self._do_test_bootstrap(self.bootstrap)

        # Sanity check that the original password works again.
        with self.make_request():
            PROVIDERS.identity_api.authenticate(
                user_id,
                self.bootstrap.password)

    def test_bootstrap_with_explicit_immutable_roles(self):
        CONF(args=['bootstrap',
                   '--bootstrap-password', uuid.uuid4().hex,
                   '--immutable-roles'],
             project='keystone')
        self._do_test_bootstrap(self.bootstrap)
        admin_role = PROVIDERS.role_api.get_role(self.bootstrap.role_id)
        reader_role = PROVIDERS.role_api.get_role(
            self.bootstrap.reader_role_id)
        member_role = PROVIDERS.role_api.get_role(
            self.bootstrap.member_role_id)
        self.assertTrue(admin_role['options']['immutable'])
        self.assertTrue(member_role['options']['immutable'])
        self.assertTrue(reader_role['options']['immutable'])

    def test_bootstrap_with_default_immutable_roles(self):
        CONF(args=['bootstrap',
                   '--bootstrap-password', uuid.uuid4().hex],
             project='keystone')
        self._do_test_bootstrap(self.bootstrap)
        admin_role = PROVIDERS.role_api.get_role(self.bootstrap.role_id)
        reader_role = PROVIDERS.role_api.get_role(
            self.bootstrap.reader_role_id)
        member_role = PROVIDERS.role_api.get_role(
            self.bootstrap.member_role_id)
        self.assertTrue(admin_role['options']['immutable'])
        self.assertTrue(member_role['options']['immutable'])
        self.assertTrue(reader_role['options']['immutable'])

    def test_bootstrap_with_no_immutable_roles(self):
        CONF(args=['bootstrap',
                   '--bootstrap-password', uuid.uuid4().hex,
                   '--no-immutable-roles'],
             project='keystone')
        self._do_test_bootstrap(self.bootstrap)
        admin_role = PROVIDERS.role_api.get_role(self.bootstrap.role_id)
        reader_role = PROVIDERS.role_api.get_role(
            self.bootstrap.reader_role_id)
        member_role = PROVIDERS.role_api.get_role(
            self.bootstrap.member_role_id)
        self.assertNotIn('immutable', admin_role['options'])
        self.assertNotIn('immutable', member_role['options'])
        self.assertNotIn('immutable', reader_role['options'])

    def test_bootstrap_with_ambiguous_role_names(self):
        # bootstrap system to create the default admin role
        self._do_test_bootstrap(self.bootstrap)

        # create a domain-specific roles that share the same names as the
        # default roles created by keystone-manage bootstrap
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        domain = PROVIDERS.resource_api.create_domain(domain['id'], domain)
        domain_roles = {}

        for name in ['admin', 'member', 'reader']:
            domain_role = {
                'domain_id': domain['id'],
                'id': uuid.uuid4().hex,
                'name': name
            }
            domain_roles[name] = PROVIDERS.role_api.create_role(
                domain_role['id'], domain_role
            )

            # ensure subsequent bootstrap attempts don't fail because of
            # ambiguity
            self._do_test_bootstrap(self.bootstrap)


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

        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)

    def test_assignment_created_with_user_exists(self):
        # test assignment can be created if user already exists.
        PROVIDERS.resource_api.create_domain(self.default_domain['id'],
                                             self.default_domain)
        user_ref = unit.new_user_ref(self.default_domain['id'],
                                     name=self.username,
                                     password=self.password)
        PROVIDERS.identity_api.create_user(user_ref)

        self._do_test_bootstrap(self.bootstrap)

    def test_assignment_created_with_project_exists(self):
        # test assignment can be created if project already exists.
        PROVIDERS.resource_api.create_domain(self.default_domain['id'],
                                             self.default_domain)
        project_ref = unit.new_project_ref(self.default_domain['id'],
                                           name=self.project_name)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        self._do_test_bootstrap(self.bootstrap)

    def test_assignment_created_with_role_exists(self):
        # test assignment can be created if role already exists.
        PROVIDERS.resource_api.create_domain(self.default_domain['id'],
                                             self.default_domain)
        role = unit.new_role_ref(name=self.role_name)
        PROVIDERS.role_api.create_role(role['id'], role)
        self._do_test_bootstrap(self.bootstrap)

    def test_assignment_created_with_region_exists(self):
        # test assignment can be created if region already exists.
        PROVIDERS.resource_api.create_domain(self.default_domain['id'],
                                             self.default_domain)
        region = unit.new_region_ref(id=self.region_id)
        PROVIDERS.catalog_api.create_region(region)
        self._do_test_bootstrap(self.bootstrap)

    def test_endpoints_created_with_service_exists(self):
        # test assignment can be created if service already exists.
        PROVIDERS.resource_api.create_domain(self.default_domain['id'],
                                             self.default_domain)
        service = unit.new_service_ref(name=self.service_name)
        PROVIDERS.catalog_api.create_service(service['id'], service)
        self._do_test_bootstrap(self.bootstrap)

    def test_endpoints_created_with_endpoint_exists(self):
        # test assignment can be created if endpoint already exists.
        PROVIDERS.resource_api.create_domain(self.default_domain['id'],
                                             self.default_domain)
        service = unit.new_service_ref(name=self.service_name)
        PROVIDERS.catalog_api.create_service(service['id'], service)

        region = unit.new_region_ref(id=self.region_id)
        PROVIDERS.catalog_api.create_region(region)

        endpoint = unit.new_endpoint_ref(interface='public',
                                         service_id=service['id'],
                                         url=self.public_url,
                                         region_id=self.region_id)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)

        self._do_test_bootstrap(self.bootstrap)

    def test_endpoints_created_with_new_endpoints(self):
        service = unit.new_service_ref(name=self.service_name, type='identity')
        PROVIDERS.catalog_api.create_service(service['id'], service)
        region = unit.new_region_ref(id=self.region_id)
        PROVIDERS.catalog_api.create_region(region)
        endpoint = unit.new_endpoint_ref(interface='public',
                                         service_id=service['id'],
                                         url=uuid.uuid4().hex,
                                         region_id=self.region_id)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)

        self._do_test_bootstrap(self.bootstrap)
        updated_endpoint = PROVIDERS.catalog_api.get_endpoint(endpoint['id'])
        self.assertEqual(updated_endpoint['url'], self.bootstrap.public_url)


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
                PROVIDERS.domain_config_api.delete_config(
                    CONF.identity.default_domain_id)
                continue
            this_domain = self.domains[domain]
            this_domain['enabled'] = False
            PROVIDERS.resource_api.update_domain(
                this_domain['id'], this_domain
            )
            PROVIDERS.resource_api.delete_domain(this_domain['id'])
        self.domains = {}

    def config(self, config_files):
        CONF(args=['domain_config_upload', '--all'], project='keystone',
             default_config_files=config_files)

    def setup_initial_domains(self):

        def create_domain(domain):
            return PROVIDERS.resource_api.create_domain(domain['id'], domain)

        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)

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
        provider_api.ProviderAPIs._clear_registry_instances()
        cli.DomainConfigUpload.main()

        res = PROVIDERS.domain_config_api.get_config_with_sensitive_info(
            CONF.identity.default_domain_id)
        self.assertEqual(default_config, res)
        res = PROVIDERS.domain_config_api.get_config_with_sensitive_info(
            self.domains['domain1']['id'])
        self.assertEqual(domain1_config, res)
        res = PROVIDERS.domain_config_api.get_config_with_sensitive_info(
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
        provider_api.ProviderAPIs._clear_registry_instances()
        cli.DomainConfigUpload.main()

        res = PROVIDERS.domain_config_api.get_config_with_sensitive_info(
            CONF.identity.default_domain_id)
        self.assertEqual(default_config, res)
        res = PROVIDERS.domain_config_api.get_config_with_sensitive_info(
            self.domains['domain1']['id'])
        self.assertEqual({}, res)
        res = PROVIDERS.domain_config_api.get_config_with_sensitive_info(
            self.domains['domain2']['id'])
        self.assertEqual({}, res)

    def test_no_overwrite_config(self):
        # Create a config for the default domain
        default_config = {
            'ldap': {'url': uuid.uuid4().hex},
            'identity': {'driver': 'ldap'}
        }
        PROVIDERS.domain_config_api.create_config(
            CONF.identity.default_domain_id, default_config)

        # Now try and upload the settings in the configuration file for the
        # default domain
        provider_api.ProviderAPIs._clear_registry_instances()
        with mock.patch('builtins.print') as mock_print:
            self.assertRaises(unit.UnexpectedExit, cli.DomainConfigUpload.main)
            file_name = ('keystone.%s.conf' % self.default_domain['name'])
            error_msg = _(
                'Domain: %(domain)s already has a configuration defined - '
                'ignoring file: %(file)s.') % {
                    'domain': self.default_domain['name'],
                    'file': os.path.join(CONF.identity.domain_config_dir,
                                         file_name)}
            mock_print.assert_has_calls([mock.call(error_msg)])

        res = PROVIDERS.domain_config_api.get_config(
            CONF.identity.default_domain_id)
        # The initial config should not have been overwritten
        self.assertEqual(default_config, res)


class CliDomainConfigNoOptionsTestCase(CliDomainConfigAllTestCase):

    def config(self, config_files):
        CONF(args=['domain_config_upload'],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        provider_api.ProviderAPIs._clear_registry_instances()
        with mock.patch('builtins.print') as mock_print:
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
        provider_api.ProviderAPIs._clear_registry_instances()
        with mock.patch('builtins.print') as mock_print:
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
        provider_api.ProviderAPIs._clear_registry_instances()
        with mock.patch('builtins.print') as mock_print:
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
            self.check = parent.command_check
            self.expand = parent.command_expand
            self.migrate = parent.command_migrate
            self.contract = parent.command_contract
            self.version = None

    def setUp(self):
        super().setUp()
        self.config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)

        self.patchers = patchers = [
            mock.patch.object(upgrades, "offline_sync_database_to_version"),
            mock.patch.object(upgrades, "expand_schema"),
            mock.patch.object(upgrades, "migrate_data"),
            mock.patch.object(upgrades, "contract_schema"),
        ]
        for p in patchers:
            p.start()
        self.command_check = False
        self.command_expand = False
        self.command_migrate = False
        self.command_contract = False

    def tearDown(self):
        for p in self.patchers:
            p.stop()
        super().tearDown()

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
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(
            upgrades.offline_sync_database_to_version)

    def test_db_sync_expand(self):
        self.command_expand = True
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(upgrades.expand_schema)

    def test_db_sync_migrate(self):
        self.command_migrate = True
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        cli.DbSync.main()
        self._assert_correct_call(upgrades.migrate_data)

    def test_db_sync_contract(self):
        self.command_contract = True
        self.useFixture(fixtures.MockPatchObject(
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
        PROVIDERS.id_mapping_api.purge_mappings(purge_filter)
        hints = None
        users = PROVIDERS.identity_api.driver.list_users(hints)
        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNone(
                PROVIDERS.id_mapping_api.get_public_id(local_entity)
            )

        # backends are loaded again in the command handler
        provider_api.ProviderAPIs._clear_registry_instances()
        cli.MappingPopulate.main()

        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNotNone(
                PROVIDERS.id_mapping_api.get_public_id(local_entity))

    def test_bad_domain_name(self):
        CONF(args=['mapping_populate', '--domain-name', uuid.uuid4().hex],
             project='keystone')
        # backends are loaded again in the command handler
        provider_api.ProviderAPIs._clear_registry_instances()
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
        self.useFixture(fixtures.MockPatchObject(
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

    @mock.patch('keystone.cmd.doctor.caching.cache.CACHE_REGION')
    def test_symptom_connection_to_memcached(self, cache_mock):
        self.config_fixture.config(group='cache', enabled=True)
        self.config_fixture.config(
            group='cache',
            memcache_servers=['alpha.com:11211', 'beta.com:11211']
        )
        self.config_fixture.config(
            group='cache', backend='dogpile.cache.memcached'
        )

        # No symptom detected: Caching driver can connect to both memcached
        # servers
        cache_mock.actual_backend.client.get_stats.return_value = (
            [('alpha.com', {}), ('beta.com', {})]
        )
        self.assertFalse(caching.symptom_connection_to_memcached())

        # Symptom detected: Caching driver can't connect to either memcached
        # server
        cache_mock.actual_backend.client.get_stats.return_value = []
        self.assertTrue(caching.symptom_connection_to_memcached())

        # Symptom detected: Caching driver can't connect to one memcached
        # server
        cache_mock.actual_backend.client.get_stats.return_value = [
            ('alpha.com', {})
        ]
        self.assertTrue(caching.symptom_connection_to_memcached())

        self.config_fixture.config(
            group='cache',
            memcache_servers=['alpha.com:11211', 'beta.com:11211']
        )
        self.config_fixture.config(
            group='cache', backend='oslo_cache.memcache_pool'
        )

        # No symptom detected: Caching driver can connect to both memcached
        # servers
        cache_mock.actual_backend.client.get_stats.return_value = (
            [('alpha.com', {}), ('beta.com', {})]
        )
        self.assertFalse(caching.symptom_connection_to_memcached())

        # Symptom detected: Caching driver can't connect to either memcached
        # server
        cache_mock.actual_backend.client.get_stats.return_value = []
        self.assertTrue(caching.symptom_connection_to_memcached())

        # Symptom detected: Caching driver can't connect to one memcached
        # server
        cache_mock.actual_backend.client.get_stats.return_value = [
            ('alpha.com', {})
        ]
        self.assertTrue(caching.symptom_connection_to_memcached())


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
        # No Symptom Detected: when minimum_password_age's default value is 0
        # and password_expires_days' default value is None
        self.assertFalse(
            security_compliance.
            symptom_minimum_password_age_greater_than_expires_days())

    def test_invalid_password_regular_expression(self):
        # Symptom Detected: Regular expression is invalid
        self.config_fixture.config(
            group='security_compliance',
            password_regex=r'^^(??=.*\d)$')
        self.assertTrue(
            security_compliance.symptom_invalid_password_regular_expression())

    def test_valid_password_regular_expression(self):
        # No Symptom Detected: Regular expression is valid
        self.config_fixture.config(
            group='security_compliance',
            password_regex=r'^(?=.*\d)(?=.*[a-zA-Z]).{7,}$')
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
            password_regex=r'^(?=.*\d)(?=.*[a-zA-Z]).{7,}$')
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
            password_regex=r'^(?=.*\d)(?=.*[a-zA-Z]).{7,}$')
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


class TestMappingPurge(unit.SQLDriverOverrides, unit.BaseTestCase):

    class FakeConfCommand(object):
        def __init__(self, parent):
            self.extension = False
            self.all = parent.command_all
            self.type = parent.command_type
            self.domain_name = parent.command_domain_name
            self.local_id = parent.command_local_id
            self.public_id = parent.command_public_id

    def setUp(self):
        # Set up preset cli options and a parser
        super(TestMappingPurge, self).setUp()
        self.config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)
        # For unit tests that should not throw any erorrs,
        # Use the argument parser to test that the combinations work
        parser_test = argparse.ArgumentParser()
        subparsers = parser_test.add_subparsers()
        self.parser = cli.MappingPurge.add_argument_parser(subparsers)

    def test_mapping_purge_with_no_arguments_fails(self):
        # Make sure the logic in main() actually catches no argument error
        self.command_type = None
        self.command_all = False
        self.command_domain_name = None
        self.command_local_id = None
        self.command_public_id = None
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        self.assertRaises(ValueError, cli.MappingPurge.main)

    def test_mapping_purge_with_all_and_other_argument_fails(self):
        # Make sure the logic in main() actually catches invalid combinations
        self.command_type = 'user'
        self.command_all = True
        self.command_domain_name = None
        self.command_local_id = None
        self.command_public_id = None
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        self.assertRaises(ValueError, cli.MappingPurge.main)

    def test_mapping_purge_with_only_all_passes(self):
        args = (['--all'])
        res = self.parser.parse_args(args)
        self.assertTrue(vars(res)['all'])

    def test_mapping_purge_with_domain_name_argument_succeeds(self):
        args = (['--domain-name', uuid.uuid4().hex])
        self.parser.parse_args(args)

    def test_mapping_purge_with_public_id_argument_succeeds(self):
        args = (['--public-id', uuid.uuid4().hex])
        self.parser.parse_args(args)

    def test_mapping_purge_with_local_id_argument_succeeds(self):
        args = (['--local-id', uuid.uuid4().hex])
        self.parser.parse_args(args)

    def test_mapping_purge_with_type_argument_succeeds(self):
        args = (['--type', 'user'])
        self.parser.parse_args(args)
        args = (['--type', 'group'])
        self.parser.parse_args(args)

    def test_mapping_purge_with_invalid_argument_fails(self):
        args = (['--invalid-option', 'some value'])
        self.assertRaises(unit.UnexpectedExit, self.parser.parse_args, args)

    def test_mapping_purge_with_all_other_combinations_passes(self):
        args = (['--type', 'user', '--local-id', uuid.uuid4().hex])
        self.parser.parse_args(args)
        args.append('--domain-name')
        args.append('test')
        self.parser.parse_args(args)
        args.append('--public-id')
        args.append(uuid.uuid4().hex)
        self.parser.parse_args(args)

    @mock.patch.object(keystone.identity.MappingManager, 'purge_mappings')
    def test_mapping_purge_type_user(self, purge_mock):
        # Make sure the logic in main() actually catches no argument error
        self.command_type = 'user'
        self.command_all = False
        self.command_domain_name = None
        self.command_local_id = uuid.uuid4().hex
        self.command_public_id = uuid.uuid4().hex
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))

        def fake_load_backends():
            return dict(
                id_mapping_api=keystone.identity.core.MappingManager,
                resource_api=None)

        self.useFixture(fixtures.MockPatch(
            'keystone.server.backends.load_backends',
            side_effect=fake_load_backends))

        cli.MappingPurge.main()
        purge_mock.assert_called_with({'entity_type': 'user',
                                       'local_id': self.command_local_id,
                                       'public_id': self.command_public_id})


class TestUserMappingPurgeFunctional(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        sqldb = self.useFixture(database.Database())
        super(TestUserMappingPurgeFunctional, self).setUp()
        self.ldapdb = self.useFixture(ldapdb.LDAPDatabase())
        self.ldapdb.clear()

        self.load_backends()

        sqldb.recreate()
        self.load_fixtures(default_fixtures)

    def config_files(self):
        self.config_fixture.register_cli_opt(cli.command_opt)
        config_files = super(
            TestUserMappingPurgeFunctional, self
        ).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap_sql.conf'))
        return config_files

    def config_overrides(self):
        super(TestUserMappingPurgeFunctional, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def config(self, config_files):
        CONF(args=['mapping_purge', '--type', 'user'],
             project='keystone',
             default_config_files=config_files)

    def test_purge_by_user_type(self):
        # Grab the list of the users from the backend directly to avoid
        # populating the public_ids for each user. We do this so we can grab
        # the local_id of a user before it's overwritten by the public_id.
        hints = None
        users = PROVIDERS.identity_api.driver.list_users(hints)

        # Create a new group in the backend directly. We do this so that we
        # have control over the local_id, which is `id` here. After creating
        # the group, let's list them so the id_mapping_api creates the public
        # id appropriately.
        group_ref = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id
        }
        PROVIDERS.identity_api.driver.create_group(group_ref['id'], group_ref)
        PROVIDERS.identity_api.list_groups()

        # Make sure all users and groups have public ids by querying the
        # id_mapping_api.
        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNotNone(
                PROVIDERS.id_mapping_api.get_public_id(local_entity))

        group_entity = {
            'domain_id': CONF.identity.default_domain_id,
            'local_id': group_ref['id'],
            'entity_type': identity_mapping.EntityType.GROUP}
        self.assertIsNotNone(
            PROVIDERS.id_mapping_api.get_public_id(group_entity)
        )

        # Purge all users mappings
        provider_api.ProviderAPIs._clear_registry_instances()
        cli.MappingPurge.main()

        # Check that all the user mappings were purged
        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNone(
                PROVIDERS.id_mapping_api.get_public_id(local_entity)
            )

        # Make sure the group mapping still exists
        self.assertIsNotNone(
            PROVIDERS.id_mapping_api.get_public_id(group_entity)
        )


class TestGroupMappingPurgeFunctional(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        sqldb = self.useFixture(database.Database())
        super(TestGroupMappingPurgeFunctional, self).setUp()
        self.ldapdb = self.useFixture(ldapdb.LDAPDatabase())
        self.ldapdb.clear()

        self.load_backends()

        sqldb.recreate()
        self.load_fixtures(default_fixtures)

    def config_files(self):
        self.config_fixture.register_cli_opt(cli.command_opt)
        config_files = super(
            TestGroupMappingPurgeFunctional, self
        ).config_files()
        config_files.append(unit.dirs.tests_conf('backend_ldap_sql.conf'))
        return config_files

    def config_overrides(self):
        super(TestGroupMappingPurgeFunctional, self).config_overrides()
        self.config_fixture.config(group='identity', driver='ldap')
        self.config_fixture.config(group='identity_mapping',
                                   backward_compatible_ids=False)

    def config(self, config_files):
        CONF(args=['mapping_purge', '--type', 'group'],
             project='keystone',
             default_config_files=config_files)

    def test_purge_by_group_type(self):
        # Grab the list of the users from the backend directly to avoid
        # populating the public_ids for each user. We do this so we can grab
        # the local_id of a user before it's overwritten by the public_id.
        hints = None
        users = PROVIDERS.identity_api.driver.list_users(hints)

        # Create a new group in the backend directly. We do this so that we
        # have control over the local_id, which is `id` here. After creating
        # the group, let's list them so the id_mapping_api creates the public
        # id appropriately.
        group_ref = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id
        }
        PROVIDERS.identity_api.driver.create_group(group_ref['id'], group_ref)
        PROVIDERS.identity_api.list_groups()

        # Make sure all users and groups have public ids by querying the
        # id_mapping_api.
        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNotNone(
                PROVIDERS.id_mapping_api.get_public_id(local_entity))

        group_entity = {
            'domain_id': CONF.identity.default_domain_id,
            'local_id': group_ref['id'],
            'entity_type': identity_mapping.EntityType.GROUP}
        self.assertIsNotNone(
            PROVIDERS.id_mapping_api.get_public_id(group_entity)
        )

        # Purge group mappings
        provider_api.ProviderAPIs._clear_registry_instances()
        cli.MappingPurge.main()

        # Make sure the group mapping was purged
        self.assertIsNone(
            PROVIDERS.id_mapping_api.get_public_id(group_entity)
        )

        # Check that all the user mappings still exist
        for user in users:
            local_entity = {
                'domain_id': CONF.identity.default_domain_id,
                'local_id': user['id'],
                'entity_type': identity_mapping.EntityType.USER}
            self.assertIsNotNone(
                PROVIDERS.id_mapping_api.get_public_id(local_entity)
            )


class TestTrustFlush(unit.SQLDriverOverrides, unit.BaseTestCase):

    class FakeConfCommand(object):
        def __init__(self, parent):
            self.extension = False
            self.project_id = parent.command_project_id
            self.trustor_user_id = parent.command_trustor_user_id
            self.trustee_user_id = parent.command_trustee_user_id
            self.date = parent.command_date

    def setUp(self):
        # Set up preset cli options and a parser
        super(TestTrustFlush, self).setUp()
        self.useFixture(database.Database())
        self.config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)
        # For unit tests that should not throw any errors,
        # Use the argument parser to test that the combinations work
        parser_test = argparse.ArgumentParser()
        subparsers = parser_test.add_subparsers()
        self.parser = cli.TrustFlush.add_argument_parser(subparsers)

    def config_files(self):
        config_files = super(TestTrustFlush, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def test_trust_flush(self):
        self.command_project_id = None
        self.command_trustor_user_id = None
        self.command_trustee_user_id = None
        self.command_date = datetime.datetime.utcnow()
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))

        def fake_load_backends():
            return dict(
                trust_api=keystone.trust.core.Manager())

        self.useFixture(fixtures.MockPatch(
            'keystone.server.backends.load_backends',
            side_effect=fake_load_backends))
        trust = cli.TrustFlush()
        trust.main()

    def test_trust_flush_with_invalid_date(self):
        self.command_project_id = None
        self.command_trustor_user_id = None
        self.command_trustee_user_id = None
        self.command_date = '4/10/92'
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))

        def fake_load_backends():
            return dict(
                trust_api=keystone.trust.core.Manager())

        self.useFixture(fixtures.MockPatch(
            'keystone.server.backends.load_backends',
            side_effect=fake_load_backends))
        # Clear backend dependencies, since cli loads these manually
        provider_api.ProviderAPIs._clear_registry_instances()
        trust = cli.TrustFlush()
        self.assertRaises(ValueError, trust.main)


class TestMappingEngineTester(unit.BaseTestCase):

    class FakeConfCommand(object):
        def __init__(self, parent):
            self.extension = False
            self.rules = parent.command_rules
            self.input = parent.command_input
            self.prefix = parent.command_prefix
            self.engine_debug = parent.command_engine_debug

    def setUp(self):
        # Set up preset cli options and a parser
        super(TestMappingEngineTester, self).setUp()
        self.mapping_id = uuid.uuid4().hex
        self.rules_pathname = None
        self.rules = None
        self.assertion_pathname = None
        self.assertion = None
        self.logging = self.useFixture(fixtures.LoggerFixture())
        self.useFixture(database.Database())
        self.config_fixture = self.useFixture(oslo_config.fixture.Config(CONF))
        self.config_fixture.register_cli_opt(cli.command_opt)
        # For unit tests that should not throw any erorrs,
        # Use the argument parser to test that the combinations work
        parser_test = argparse.ArgumentParser()
        subparsers = parser_test.add_subparsers()
        self.parser = cli.MappingEngineTester.add_argument_parser(subparsers)

    def config_files(self):
        config_files = super(TestMappingEngineTester, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def test_mapping_engine_tester_with_invalid_rules_file(self):
        tempfilejson = self.useFixture(temporaryfile.SecureTempFile())
        tmpinvalidfile = tempfilejson.file_name
        # Here the data required for rules should be in JSON format
        # whereas the file contains text.
        with open(tmpinvalidfile, 'w') as f:
            f.write("This is an invalid data")
        self.command_rules = tmpinvalidfile
        self.command_input = tmpinvalidfile
        self.command_prefix = None
        self.command_engine_debug = True
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        mapping_engine = cli.MappingEngineTester()
        self.assertRaises(SystemExit, mapping_engine.main)

    def test_mapping_engine_tester_with_invalid_input_file(self):
        tempfilejson = self.useFixture(temporaryfile.SecureTempFile())
        tmpfilejsonname = tempfilejson.file_name
        updated_mapping = copy.deepcopy(mapping_fixtures.MAPPING_SMALL)
        with open(tmpfilejsonname, 'w') as f:
            f.write(jsonutils.dumps(updated_mapping))
        self.command_rules = tmpfilejsonname
        # Here invalid.csv does not exist
        self.command_input = "invalid.csv"
        self.command_prefix = None
        self.command_engine_debug = True
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        mapping_engine = cli.MappingEngineTester()
        self.assertRaises(SystemExit, mapping_engine.main)

    def test_mapping_engine_tester(self):
        tempfilejson = self.useFixture(temporaryfile.SecureTempFile())
        tmpfilejsonname = tempfilejson.file_name
        updated_mapping = copy.deepcopy(mapping_fixtures.MAPPING_SMALL)
        with open(tmpfilejsonname, 'w') as f:
            f.write(jsonutils.dumps(updated_mapping))
        self.command_rules = tmpfilejsonname
        tempfile = self.useFixture(temporaryfile.SecureTempFile())
        tmpfilename = tempfile.file_name
        with open(tmpfilename, 'w') as f:
            f.write("\n")
            f.write("UserName:me\n")
            f.write("orgPersonType:NoContractor\n")
            f.write("LastName:Bo\n")
            f.write("FirstName:Jill\n")
        self.command_input = tmpfilename
        self.command_prefix = None
        self.command_engine_debug = True
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        mapping_engine = cli.MappingEngineTester()
        with mock.patch('builtins.print') as mock_print:
            mapping_engine.main()
            self.assertEqual(mock_print.call_count, 3)
            call = mock_print.call_args_list[0]
            args, kwargs = call
            self.assertTrue(args[0].startswith('Using Rules:'))
            call = mock_print.call_args_list[1]
            args, kwargs = call
            self.assertTrue(args[0].startswith('Using Assertion:'))
            call = mock_print.call_args_list[2]
            args, kwargs = call
            expected = {
                "group_names": [],
                "user": {
                    "type": "ephemeral",
                    "name": "me"
                },
                "projects": [],
                "group_ids": ["0cd5e9"]
            }
            self.assertEqual(jsonutils.loads(args[0]), expected)

    def test_mapping_engine_tester_with_invalid_data(self):
        tempfilejson = self.useFixture(temporaryfile.SecureTempFile())
        tmpfilejsonname = tempfilejson.file_name
        updated_mapping = copy.deepcopy(mapping_fixtures.MAPPING_SMALL)
        with open(tmpfilejsonname, 'w') as f:
            f.write(jsonutils.dumps(updated_mapping))
        self.command_rules = tmpfilejsonname
        tempfile = self.useFixture(temporaryfile.SecureTempFile())
        tmpfilename = tempfile.file_name
        # Here we do not have any value matching to type 'Email'
        # and condition in mapping_engine_test_rules.json
        with open(tmpfilename, 'w') as f:
            f.write("\n")
            f.write("UserName: me\n")
            f.write("Email: No@example.com\n")
        self.command_input = tmpfilename
        self.command_prefix = None
        self.command_engine_debug = True
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        mapping_engine = cli.MappingEngineTester()
        self.assertRaises(exception.ValidationError,
                          mapping_engine.main)

    def test_mapping_engine_tester_logs_direct_maps(self):
        tempfilejson = self.useFixture(temporaryfile.SecureTempFile())
        tmpfilejsonname = tempfilejson.file_name
        updated_mapping = copy.deepcopy(mapping_fixtures.MAPPING_SMALL)
        with open(tmpfilejsonname, 'w') as f:
            f.write(jsonutils.dumps(updated_mapping))
        self.command_rules = tmpfilejsonname
        tempfile = self.useFixture(temporaryfile.SecureTempFile())
        tmpfilename = tempfile.file_name
        with open(tmpfilename, 'w') as f:
            f.write("\n")
            f.write("UserName:me\n")
            f.write("orgPersonType:NoContractor\n")
            f.write("LastName:Bo\n")
            f.write("FirstName:Jill\n")
        self.command_input = tmpfilename
        self.command_prefix = None
        self.command_engine_debug = True
        self.useFixture(fixtures.MockPatchObject(
            CONF, 'command', self.FakeConfCommand(self)))
        mapping_engine = cli.MappingEngineTester()
        logging = self.useFixture(fixtures.FakeLogger(level=log.DEBUG))
        mapping_engine.main()
        expected_msg = "direct_maps: [['me']]"
        self.assertThat(logging.output, matchers.Contains(expected_msg))


class CliStatusTestCase(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        self.useFixture(database.Database())
        super(CliStatusTestCase, self).setUp()
        self.load_backends()
        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            policy.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )
        self.checks = status.Checks()

    def test_check_safe_trust_policies(self):
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:list_trusts': '',
                'identity:delete_trust': '',
                'identity:get_trust': '',
                'identity:list_roles_for_trust': '',
                'identity:get_role_for_trust': ''
            }
            f.write(jsonutils.dumps(overridden_policies))
        result = self.checks.check_trust_policies_are_not_empty()
        self.assertEqual(upgradecheck.Code.FAILURE, result.code)
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:list_trusts': 'rule:admin_required',
                'identity:delete_trust': 'rule:admin_required',
                'identity:get_trust': 'rule:admin_required',
                'identity:list_roles_for_trust': 'rule:admin_required',
                'identity:get_role_for_trust': 'rule:admin_required'
            }
            f.write(jsonutils.dumps(overridden_policies))
        result = self.checks.check_trust_policies_are_not_empty()
        self.assertEqual(upgradecheck.Code.SUCCESS, result.code)
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {}
            f.write(jsonutils.dumps(overridden_policies))
        result = self.checks.check_trust_policies_are_not_empty()
        self.assertEqual(upgradecheck.Code.SUCCESS, result.code)

    def test_check_immutable_roles(self):
        role_ref = unit.new_role_ref(name='admin')
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        result = self.checks.check_default_roles_are_immutable()
        self.assertEqual(upgradecheck.Code.FAILURE, result.code)
        role_ref['options'] = {'immutable': True}
        PROVIDERS.role_api.update_role(role_ref['id'], role_ref)
        result = self.checks.check_default_roles_are_immutable()
        self.assertEqual(upgradecheck.Code.SUCCESS, result.code)
        # Check domain-specific roles are not reported
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'],
            default_fixtures.ROOT_DOMAIN)
        domain_ref = unit.new_domain_ref()
        domain = PROVIDERS.resource_api.create_domain(
            domain_ref['id'], domain_ref)
        role_ref = unit.new_role_ref(name='admin', domain_id=domain['id'])
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        result = self.checks.check_default_roles_are_immutable()
        self.assertEqual(upgradecheck.Code.SUCCESS, result.code)
