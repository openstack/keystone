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

"""This is an isolated test to prevent unexpected imports.

This module must be run in isolation, e.g.:

  $ ./run_tests.sh _test_import_auth_token.py

This module can be removed when keystone.middleware.auth_token is removed.

"""

import testtools


class TestAuthToken(testtools.TestCase):
    def test_import(self):
        # a consuming service like nova would import oslo.config first
        from oslo.config import cfg
        conf = cfg.CONF

        # define some config options
        conf.register_opt(cfg.BoolOpt('debug', default=False))

        # and then import auth_token as a filter
        from keystone.middleware import auth_token
        self.assertTrue(auth_token)
