# Copyright (c) 2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ast
import unittest2 as unittest

from keystone import config
from keystone import utils

CONF = config.CONF


class ConfigTestCase(unittest.TestCase):
    """
    Base class to test keystone/config.py
    """
    def __init__(self, *args, **kwargs):
        super(ConfigTestCase, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_old_config_syntax(self):
        options = {
            'verbose': True,
            'debug': False,
            'backends': "keystone.backends.sqlalchemy",
            'keystone.backends.sqlalchemy': {
                # in-memory db
                'sql_connection': 'sqlite://',
                'backend_entities':
                    "['UserRoleAssociation', 'Endpoints', 'Role', 'Tenant', "
                    "'Tenant', 'User', 'Credentials', 'EndpointTemplates', "
                    "'Token', 'Service']",
            },
            'extensions': 'osksadm, oskscatalog, hpidm',
            'keystone-admin-role': 'Admin',
            'keystone-service-admin-role': 'KeystoneServiceAdmin',
            'hash-password': 'True',
        }
        utils.set_configuration(options)
        self.assertTrue(CONF.verbose)
        self.assertFalse(CONF.debug)
        self.assertIn('hpidm', [ext.strip() for ext in CONF.extensions])
        self.assertIn('keystone.backends.sqlalchemy', CONF.backends)
        self.assertTrue(CONF.hash_password)
        self.assertEquals(CONF['keystone.backends.sqlalchemy'].sql_connection,
                          'sqlite://')
        self.assertIsInstance(ast.literal_eval(
                CONF['keystone.backends.sqlalchemy'].backend_entities),
                list)


if __name__ == '__main__':
    unittest.main()
