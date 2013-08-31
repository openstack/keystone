# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import inspect
import testtools

from keystone import assignment
from keystone import catalog
from keystone.contrib import endpoint_filter
from keystone.contrib import oauth1
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import token


class TestDrivers(testtools.TestCase):
    """Asserts that drivers are written as expected.

    Public methods on drivers should raise keystone.exception.NotImplemented,
    which renders to the API as a HTTP 501 Not Implemented.

    """

    def assertMethodNotImplemented(self, f):
        """Asserts that a given method raises 501 Not Implemented.

        Provides each argument with a value of None, ignoring optional
        arguments.
        """
        args = inspect.getargspec(f).args
        args.remove('self')
        kwargs = dict(zip(args, [None] * len(args)))
        self.assertRaises(exception.NotImplemented, f, **kwargs)

    def assertInterfaceNotImplemented(self, interface):
        """Public methods on an interface class should not be implemented."""
        for name in dir(interface):
            method = getattr(interface, name)
            if name[0] != '_' and callable(method):
                self.assertMethodNotImplemented(method)

    def test_assignment_driver_unimplemented(self):
        interface = assignment.Driver()
        self.assertInterfaceNotImplemented(interface)

    def test_catalog_driver_unimplemented(self):
        interface = catalog.Driver()
        self.assertInterfaceNotImplemented(interface)

    def test_identity_driver_unimplemented(self):
        interface = identity.Driver()
        self.assertInterfaceNotImplemented(interface)

    def test_policy_driver_unimplemented(self):
        interface = policy.Driver()
        self.assertInterfaceNotImplemented(interface)

    def test_token_driver_unimplemented(self):
        interface = token.Driver()
        self.assertInterfaceNotImplemented(interface)

    def test_oauth1_driver_unimplemented(self):
        interface = oauth1.Driver()
        self.assertInterfaceNotImplemented(interface)

    def test_endpoint_filter_driver_unimplemented(self):
        interface = endpoint_filter.Driver()
        self.assertInterfaceNotImplemented(interface)
