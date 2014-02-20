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

import os
import uuid

import mock
import testtools

from keystone import config
from keystone import exception
from keystone import identity
from keystone import tests


CONF = config.CONF


class TestDomainConfigs(testtools.TestCase):

    def setUp(self):
        super(TestDomainConfigs, self).setUp()
        self.addCleanup(CONF.reset)

        self.tmp_dir = tests.dirs.tmp()
        CONF.set_override('domain_config_dir', self.tmp_dir, 'identity')

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
