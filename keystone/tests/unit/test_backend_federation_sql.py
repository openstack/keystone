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
from keystone.tests.unit import test_backend_sql


class SqlFederation(test_backend_sql.SqlModels):
    """Set of tests for checking SQL Federation."""

    def test_identity_provider(self):
        cols = (('id', sql.String, 64),
                ('domain_id', sql.String, 64),
                ('enabled', sql.Boolean, None),
                ('description', sql.Text, None),
                ('authorization_ttl', sql.Integer, None))
        self.assertExpectedSchema('identity_provider', cols)

    def test_idp_remote_ids(self):
        cols = (('idp_id', sql.String, 64),
                ('remote_id', sql.String, 255))
        self.assertExpectedSchema('idp_remote_ids', cols)

    def test_federated_protocol(self):
        cols = (('id', sql.String, 64),
                ('idp_id', sql.String, 64),
                ('mapping_id', sql.String, 64),
                ('remote_id_attribute', sql.String, 64))
        self.assertExpectedSchema('federation_protocol', cols)

    def test_mapping(self):
        cols = (('id', sql.String, 64),
                ('rules', sql.JsonBlob, None))
        self.assertExpectedSchema('mapping', cols)

    def test_service_provider(self):
        cols = (('auth_url', sql.String, 256),
                ('id', sql.String, 64),
                ('enabled', sql.Boolean, None),
                ('description', sql.Text, None),
                ('relay_state_prefix', sql.String, 256),
                ('sp_url', sql.String, 256))
        self.assertExpectedSchema('service_provider', cols)
