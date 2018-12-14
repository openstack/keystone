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

import uuid

from six.moves import http_client

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            system_reader
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.reader_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=system_reader['password'],
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _create_protocol_and_deps(self):
        identity_provider = unit.new_identity_provider_ref()
        identity_provider = PROVIDERS.federation_api.create_idp(
            identity_provider['id'], identity_provider
        )

        mapping = PROVIDERS.federation_api.create_mapping(
            uuid.uuid4().hex, unit.new_mapping_ref()
        )
        protocol = unit.new_protocol_ref(mapping_id=mapping['id'])
        protocol = PROVIDERS.federation_api.create_protocol(
            identity_provider['id'], protocol['id'], protocol
        )
        return (protocol, mapping, identity_provider)

    def test_user_cannot_create_protocols(self):
        identity_provider = unit.new_identity_provider_ref()
        identity_provider = PROVIDERS.federation_api.create_idp(
            identity_provider['id'], identity_provider
        )

        mapping = PROVIDERS.federation_api.create_mapping(
            uuid.uuid4().hex, unit.new_mapping_ref()
        )

        protocol_id = 'saml2'
        create = {'protocol': {'mapping_id': mapping['id']}}

        with self.test_client() as c:
            path = (
                '/v3/OS-FEDERATION/identity_providers/%s/protocols/%s' %
                (identity_provider['id'], protocol_id)
            )
            c.put(
                path, json=create, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_update_protocols(self):
        protocol, mapping, identity_provider = self._create_protocol_and_deps()

        new_mapping = PROVIDERS.federation_api.create_mapping(
            uuid.uuid4().hex, unit.new_mapping_ref()
        )

        update = {'protocol': {'mapping_id': new_mapping['id']}}
        with self.test_client() as c:
            path = (
                '/v3/OS-FEDERATION/identity_providers/%s/protocols/%s' %
                (identity_provider['id'], protocol['id'])
            )
            c.patch(
                path, json=update, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_can_list_protocols(self):
        protocol, mapping, identity_provider = self._create_protocol_and_deps()

        with self.test_client() as c:
            path = (
                '/v3/OS-FEDERATION/identity_providers/%s/protocols' %
                identity_provider['id']
            )
            r = c.get(path, headers=self.headers)
            self.assertEqual(1, len(r.json['protocols']))
            self.assertEqual(protocol['id'], r.json['protocols'][0]['id'])

    def test_user_can_get_a_protocol(self):
        protocol, mapping, identity_provider = self._create_protocol_and_deps()

        with self.test_client() as c:
            path = (
                '/v3/OS-FEDERATION/identity_providers/%s/protocols/%s' %
                (identity_provider['id'], protocol['id'])
            )
            c.get(path, headers=self.headers)

    def test_user_cannot_delete_protocol(self):
        protocol, mapping, identity_provider = self._create_protocol_and_deps()

        with self.test_client() as c:
            path = (
                '/v3/OS-FEDERATION/identity_providers/%s/protocols/%s' %
                (identity_provider['id'], protocol['id'])
            )
            c.delete(
                path, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )
