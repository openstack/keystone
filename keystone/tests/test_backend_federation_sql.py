# Copyright 2013 OpenStack Foundation
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

from keystone.common import sql
from keystone import config
from keystone.tests import test_backend_sql

CONF = config.CONF


class SqlFederation(test_backend_sql.SqlModels):
    """Set of tests for checking SQL Federation."""

    def test_identity_provider(self):
        cols = (('id', sql.String, 64),
                ('enabled', sql.Boolean, None),
                ('description', sql.Text, None))
        self.assertExpectedSchema('identity_provider', cols)

    def test_federated_protocol(self):
        cols = (('id', sql.String, 64),
                ('idp_id', sql.String, 64),
                ('mapping_id', sql.String, 64))
        self.assertExpectedSchema('federation_protocol', cols)
