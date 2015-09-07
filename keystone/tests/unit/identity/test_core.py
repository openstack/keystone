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

"""Unit tests for core identity behavior."""

import itertools
import os
import uuid

import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture

from keystone import exception
from keystone import identity
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import database


CONF = cfg.CONF


class TestDomainConfigs(unit.BaseTestCase):

    def setUp(self):
        super(TestDomainConfigs, self).setUp()
        self.addCleanup(CONF.reset)

        self.tmp_dir = unit.dirs.tmp()

        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config_fixture.config(domain_config_dir=self.tmp_dir,
                                   group='identity')

    def test_config_for_nonexistent_domain(self):
        """Having a config for a non-existent domain will be ignored.

        There are no assertions in this test because there are no side
        effects. If there is a config file for a domain that does not
        exist it should be ignored.

        """
        domain_id = uuid.uuid4().hex
        domain_config_filename = os.path.join(self.tmp_dir,
                                              'keystone.%s.conf' % domain_id)
        self.addCleanup(lambda: os.remove(domain_config_filename))
        with open(domain_config_filename, 'w'):
            """Write an empty config file."""

        e = exception.DomainNotFound(domain_id=domain_id)
        mock_assignment_api = mock.Mock()
        mock_assignment_api.get_domain_by_name.side_effect = e

        domain_config = identity.DomainConfigs()
        fake_standard_driver = None
        domain_config.setup_domain_drivers(fake_standard_driver,
                                           mock_assignment_api)

    def test_config_for_dot_name_domain(self):
        # Ensure we can get the right domain name which has dots within it
        # from filename.
        domain_config_filename = os.path.join(self.tmp_dir,
                                              'keystone.abc.def.com.conf')
        with open(domain_config_filename, 'w'):
            """Write an empty config file."""
        self.addCleanup(os.remove, domain_config_filename)

        with mock.patch.object(identity.DomainConfigs,
                               '_load_config_from_file') as mock_load_config:
            domain_config = identity.DomainConfigs()
            fake_assignment_api = None
            fake_standard_driver = None
            domain_config.setup_domain_drivers(fake_standard_driver,
                                               fake_assignment_api)
            mock_load_config.assert_called_once_with(fake_assignment_api,
                                                     [domain_config_filename],
                                                     'abc.def.com')

    def test_config_for_multiple_sql_backend(self):
        domains_config = identity.DomainConfigs()

        # Create the right sequence of is_sql in the drivers being
        # requested to expose the bug, which is that a False setting
        # means it forgets previous True settings.
        drivers = []
        files = []
        for idx, is_sql in enumerate((True, False, True)):
            drv = mock.Mock(is_sql=is_sql)
            drivers.append(drv)
            name = 'dummy.{0}'.format(idx)
            files.append(''.join((
                identity.DOMAIN_CONF_FHEAD,
                name,
                identity.DOMAIN_CONF_FTAIL)))

        walk_fake = lambda *a, **kwa: (
            ('/fake/keystone/domains/config', [], files), )

        generic_driver = mock.Mock(is_sql=False)

        assignment_api = mock.Mock()
        id_factory = itertools.count()
        assignment_api.get_domain_by_name.side_effect = (
            lambda name: {'id': next(id_factory), '_': 'fake_domain'})
        load_driver_mock = mock.Mock(side_effect=drivers)

        with mock.patch.object(os, 'walk', walk_fake):
            with mock.patch.object(identity.cfg, 'ConfigOpts'):
                with mock.patch.object(domains_config, '_load_driver',
                                       load_driver_mock):
                    self.assertRaises(
                        exception.MultipleSQLDriversInConfig,
                        domains_config.setup_domain_drivers,
                        generic_driver, assignment_api)

                    self.assertEqual(3, load_driver_mock.call_count)


class TestDatabaseDomainConfigs(unit.TestCase):

    def setUp(self):
        super(TestDatabaseDomainConfigs, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

    def test_domain_config_in_database_disabled_by_default(self):
        self.assertFalse(CONF.identity.domain_configurations_from_database)

    def test_loading_config_from_database(self):
        self.config_fixture.config(domain_configurations_from_database=True,
                                   group='identity')
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        # Override two config options for our domain
        conf = {'ldap': {'url': uuid.uuid4().hex,
                         'suffix': uuid.uuid4().hex,
                         'use_tls': 'True'},
                'identity': {
                    'driver': 'ldap'}}
        self.domain_config_api.create_config(domain['id'], conf)
        fake_standard_driver = None
        domain_config = identity.DomainConfigs()
        domain_config.setup_domain_drivers(fake_standard_driver,
                                           self.resource_api)
        # Make sure our two overrides are in place, and others are not affected
        res = domain_config.get_domain_conf(domain['id'])
        self.assertEqual(conf['ldap']['url'], res.ldap.url)
        self.assertEqual(conf['ldap']['suffix'], res.ldap.suffix)
        self.assertEqual(CONF.ldap.query_scope, res.ldap.query_scope)

        # Make sure the override is not changing the type of the config value
        use_tls_type = type(CONF.ldap.use_tls)
        self.assertEqual(use_tls_type(conf['ldap']['use_tls']),
                         res.ldap.use_tls)

        # Now turn off using database domain configuration and check that the
        # default config file values are now seen instead of the overrides.
        CONF.set_override('domain_configurations_from_database', False,
                          'identity')
        domain_config = identity.DomainConfigs()
        domain_config.setup_domain_drivers(fake_standard_driver,
                                           self.resource_api)
        res = domain_config.get_domain_conf(domain['id'])
        self.assertEqual(CONF.ldap.url, res.ldap.url)
        self.assertEqual(CONF.ldap.suffix, res.ldap.suffix)
        self.assertEqual(CONF.ldap.use_tls, res.ldap.use_tls)
        self.assertEqual(CONF.ldap.query_scope, res.ldap.query_scope)
