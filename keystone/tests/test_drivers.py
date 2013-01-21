import inspect
import unittest2 as unittest

from keystone import assignment
from keystone import catalog
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import token


class TestDrivers(unittest.TestCase):
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
        with self.assertRaises(exception.NotImplemented):
            f(**kwargs)

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
