# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

from keystone import exception
from keystone import tests
from keystone.tests import default_fixtures
from keystone.tests import test_backend


DEFAULT_CATALOG_TEMPLATES = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    'default_catalog.templates'))


class TestTemplatedCatalog(tests.TestCase, test_backend.CatalogTests):

    DEFAULT_FIXTURE = {
        'RegionOne': {
            'compute': {
                'adminURL': 'http://localhost:8774/v1.1/bar',
                'publicURL': 'http://localhost:8774/v1.1/bar',
                'internalURL': 'http://localhost:8774/v1.1/bar',
                'name': "'Compute Service'",
                'id': '2'
            },
            'identity': {
                'adminURL': 'http://localhost:35357/v2.0',
                'publicURL': 'http://localhost:5000/v2.0',
                'internalURL': 'http://localhost:35357/v2.0',
                'name': "'Identity Service'",
                'id': '1'
            }
        }
    }

    def setUp(self):
        super(TestTemplatedCatalog, self).setUp()
        self.opt_in_group('catalog', template_file=DEFAULT_CATALOG_TEMPLATES)
        self.load_backends()
        self.load_fixtures(default_fixtures)

    def test_get_catalog(self):
        catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
        self.assertDictEqual(catalog_ref, self.DEFAULT_FIXTURE)

    def test_malformed_catalog_throws_error(self):
        (self.catalog_api.driver.templates
         ['RegionOne']['compute']['adminURL']) = \
            'http://localhost:$(compute_port)s/v1.1/$(tenant)s'
        self.assertRaises(exception.MalformedEndpoint,
                          self.catalog_api.get_catalog,
                          'fake-user',
                          'fake-tenant')
