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

import uuid

from six.moves import http_client

from keystone.tests.unit import test_v3_federation


class FederatedSetupMixinV8(object):
    def useV8driver(self):
        # We use the SQL driver as an example V8 driver, so override
        # the current driver with that version.
        self.config_fixture.config(
            group='federation',
            driver='keystone.federation.V8_backends.sql.Federation')
        self.use_specific_sql_driver_version(
            'keystone.federation', 'backends', 'V8_')


class FederatedIdentityProviderTestsV8(
        test_v3_federation.FederatedIdentityProviderTests,
        FederatedSetupMixinV8):
    """Test that a V8 driver still passes the same tests."""

    def config_overrides(self):
        super(FederatedIdentityProviderTestsV8, self).config_overrides()
        self.useV8driver()

    def test_create_idp_remote_repeated(self):
        """Creates two IdentityProvider entities with some remote_ids

        A remote_id is the same for both so the second IdP is not
        created because of the uniqueness of the remote_ids

        Expect HTTP 409 Conflict code for the latter call.

        Note: V9 drivers and later augment the conflict message with
        additional information, which won't be present if we are running
        a V8 driver - so override the newer tests to just ensure a
        conflict message is raised.
        """
        body = self.default_body.copy()
        repeated_remote_id = uuid.uuid4().hex
        body['remote_ids'] = [uuid.uuid4().hex,
                              uuid.uuid4().hex,
                              uuid.uuid4().hex,
                              repeated_remote_id]
        self._create_default_idp(body=body)

        url = self.base_url(suffix=uuid.uuid4().hex)
        body['remote_ids'] = [uuid.uuid4().hex,
                              repeated_remote_id]
        self.put(url, body={'identity_provider': body},
                 expected_status=http_client.CONFLICT)

    def test_check_idp_uniqueness(self):
        """Add same IdP twice.

        Expect HTTP 409 Conflict code for the latter call.

        Note: V9 drivers and later augment the conflict message with
        additional information, which won't be present if we are running
        a V8 driver - so override the newer tests to just ensure a
        conflict message is raised.
        """
        url = self.base_url(suffix=uuid.uuid4().hex)
        body = self._http_idp_input()
        self.put(url, body={'identity_provider': body},
                 expected_status=http_client.CREATED)
        self.put(url, body={'identity_provider': body},
                 expected_status=http_client.CONFLICT)


class MappingCRUDTestsV8(
        test_v3_federation.MappingCRUDTests,
        FederatedSetupMixinV8):
    """Test that a V8 driver still passes the same tests."""

    def config_overrides(self):
        super(MappingCRUDTestsV8, self).config_overrides()
        self.useV8driver()


class ServiceProviderTestsV8(
        test_v3_federation.ServiceProviderTests,
        FederatedSetupMixinV8):
    """Test that a V8 driver still passes the same tests."""

    def config_overrides(self):
        super(ServiceProviderTestsV8, self).config_overrides()
        self.useV8driver()

    def test_filter_list_sp_by_id(self):
        self.skipTest('Operation not supported in v8 and earlier drivers')

    def test_filter_list_sp_by_enabled(self):
        self.skipTest('Operation not supported in v8 and earlier drivers')
