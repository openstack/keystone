# Copyright 2014 IBM Corp.
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
from keystone.tests.unit import test_backend_endpoint_policy
from keystone.tests.unit import test_backend_sql


class SqlPolicyAssociationTable(test_backend_sql.SqlModels):
    """Set of tests for checking SQL Policy Association Mapping."""

    def test_policy_association_mapping(self):
        cols = (('id', sql.String, 64),
                ('policy_id', sql.String, 64),
                ('endpoint_id', sql.String, 64),
                ('service_id', sql.String, 64),
                ('region_id', sql.String, 64))
        self.assertExpectedSchema('policy_association', cols)


class SqlPolicyAssociationTests(
    test_backend_sql.SqlTests,
        test_backend_endpoint_policy.PolicyAssociationTests):

    def load_fixtures(self, fixtures):
        super(SqlPolicyAssociationTests, self).load_fixtures(fixtures)
        self.load_sample_data()
