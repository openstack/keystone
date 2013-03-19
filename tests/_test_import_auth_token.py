"""This is an isolated test to prevent unexpected imports.

This module must be run in isolation, e.g.:

  $ ./run_tests.sh _test_import_auth_token.py

This module can be removed when keystone.middleware.auth_token is removed.

"""

import unittest


class TestAuthToken(unittest.TestCase):
    def test_import(self):
        # a consuming service like nova would import oslo.config first
        from oslo.config import cfg
        conf = cfg.CONF

        # define some config options
        conf.register_opt(cfg.BoolOpt('debug', default=False))

        # and then import auth_token as a filter
        from keystone.middleware import auth_token
        self.assertTrue(auth_token)
