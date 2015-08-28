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

import mock

from keystone import catalog
from keystone.common import manager
from keystone.tests import unit


class TestCreateLegacyDriver(unit.BaseTestCase):

    @mock.patch('oslo_log.versionutils.report_deprecated_feature')
    def test_class_is_properly_deprecated(self, mock_reporter):
        Driver = manager.create_legacy_driver(catalog.CatalogDriverV8)

        # NOTE(dstanek): I want to subvert the requirement for this
        # class to implement all of the abstractmethods.
        Driver.__abstractmethods__ = set()
        impl = Driver()

        details = {
            'as_of': 'Liberty',
            'what': 'keystone.catalog.core.Driver',
            'in_favor_of': 'keystone.catalog.core.CatalogDriverV8',
            'remove_in': 'N',
        }
        mock_reporter.assert_called_with(mock.ANY, mock.ANY, details)

        self.assertIsInstance(impl, catalog.CatalogDriverV8)
