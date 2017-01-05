# Copyright 2016 Red Hat, Inc.
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

from tempest.common import credentials_factory as common_creds
from tempest import test

from keystone_tempest_plugin import clients


class BaseIdentityTest(test.BaseTestCase):

    # The version of the identity that will be used in the tests.
    identity_version = 'v3'

    # NOTE(rodrigods): for now, all tests are in the admin scope, if
    # necessary, another class can be created to handle non-admin tests.
    credential_type = 'identity_admin'

    @classmethod
    def setup_clients(cls):
        super(BaseIdentityTest, cls).setup_clients()
        credentials = common_creds.get_configured_admin_credentials(
            cls.credential_type, identity_version=cls.identity_version)
        cls.keystone_manager = clients.Manager(credentials)
        cls.auth_client = cls.keystone_manager.auth_client
        cls.idps_client = cls.keystone_manager.identity_providers_client
        cls.mappings_client = cls.keystone_manager.mapping_rules_client
        cls.saml2_client = cls.keystone_manager.saml2_client
        cls.sps_client = cls.keystone_manager.service_providers_client
        cls.tokens_client = cls.keystone_manager.token_v3_client
