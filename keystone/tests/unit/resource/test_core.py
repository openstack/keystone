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
from oslotest import mockpatch

from keystone import exception
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import database


CONF = cfg.CONF


class TestResourceManagerNoFixtures(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        super(TestResourceManagerNoFixtures, self).setUp()
        self.useFixture(database.Database(self.sql_driver_version_overrides))
        self.load_backends()

    def test_ensure_default_domain_exists(self):
        # When there's no default domain, ensure_default_domain_exists creates
        # it.

        # First make sure there's no default domain.
        self.assertRaises(
            exception.DomainNotFound,
            self.resource_api.get_domain, CONF.identity.default_domain_id)

        self.resource_api.ensure_default_domain_exists()
        default_domain = self.resource_api.get_domain(
            CONF.identity.default_domain_id)

        expected_domain = {
            'id': CONF.identity.default_domain_id,
            'name': 'Default',
            'enabled': True,
            'description': 'Domain created automatically to support V2.0 '
                           'operations.',
        }
        self.assertEqual(expected_domain, default_domain)

    def test_ensure_default_domain_exists_already_exists(self):
        # When there's already a default domain, ensure_default_domain_exists
        # doesn't do anything.

        name = uuid.uuid4().hex
        description = uuid.uuid4().hex
        domain_attrs = {
            'id': CONF.identity.default_domain_id,
            'name': name,
            'description': description,
        }
        self.resource_api.create_domain(CONF.identity.default_domain_id,
                                        domain_attrs)

        self.resource_api.ensure_default_domain_exists()

        default_domain = self.resource_api.get_domain(
            CONF.identity.default_domain_id)

        expected_domain = {
            'id': CONF.identity.default_domain_id,
            'name': name,
            'enabled': True,
            'description': description,
        }

        self.assertEqual(expected_domain, default_domain)

    def test_ensure_default_domain_exists_fails(self):
        # When there's an unexpected exception creating domain it's passed on.

        self.useFixture(mockpatch.PatchObject(
            self.resource_api, 'create_domain',
            side_effect=exception.UnexpectedError))

        self.assertRaises(exception.UnexpectedError,
                          self.resource_api.ensure_default_domain_exists)
