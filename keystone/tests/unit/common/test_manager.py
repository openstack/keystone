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
        # class to implement all of the abstract methods.
        Driver.__abstractmethods__ = set()
        impl = Driver()

        details = {
            'as_of': 'Liberty',
            'what': 'keystone.catalog.core.Driver',
            'in_favor_of': 'keystone.catalog.core.CatalogDriverV8',
            'remove_in': mock.ANY,
        }
        mock_reporter.assert_called_with(mock.ANY, mock.ANY, details)
        self.assertEqual('N', mock_reporter.call_args[0][2]['remove_in'][0])

        self.assertIsInstance(impl, catalog.CatalogDriverV8)

    class Manager(manager.Manager):

        def __init__(self, driver):
            # NOTE(dstanek): I am not calling the parent's __init__ on
            # purpose. I don't want to trigger the dynamic loading of a
            # driver, I want to provide my own.
            self.driver = driver

    def test_property_passthru(self):
        """Manager delegating property call to a driver through __getattr__."""
        class Driver(object):

            def __init__(self):
                self.counter = 0

            @property
            def p(self):
                self.counter += 1
                return self.counter

        mgr = self.Manager(Driver())
        # each property call should return a new value
        self.assertNotEqual(mgr.p, mgr.p)

    def test_callable_passthru(self):
        class Driver(object):

            class Inner(object):
                pass

            def method(self):
                pass

        drv = Driver()
        mgr = self.Manager(drv)
        self.assertEqual(drv.Inner, mgr.Inner)
        self.assertEqual(drv.method, mgr.method)
