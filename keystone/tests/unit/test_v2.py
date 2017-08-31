# Copyright 2012 OpenStack Foundation
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

import uuid

import six
from six.moves import http_client

from keystone.common import extension as keystone_extension
import keystone.conf
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import rest
from keystone.tests.unit.schema import v2

CONF = keystone.conf.CONF


class CoreApiTests(object):
    def assertValidError(self, error):
        self.assertIsNotNone(error.get('code'))
        self.assertIsNotNone(error.get('title'))
        self.assertIsNotNone(error.get('message'))

    def assertValidVersion(self, version):
        self.assertIsNotNone(version)
        self.assertIsNotNone(version.get('id'))
        self.assertIsNotNone(version.get('status'))
        self.assertIsNotNone(version.get('updated'))

    def assertValidExtension(self, extension):
        self.assertIsNotNone(extension)
        self.assertIsNotNone(extension.get('name'))
        self.assertIsNotNone(extension.get('namespace'))
        self.assertIsNotNone(extension.get('alias'))
        self.assertIsNotNone(extension.get('updated'))

    def assertValidExtensionLink(self, link):
        self.assertIsNotNone(link.get('rel'))
        self.assertIsNotNone(link.get('type'))
        self.assertIsNotNone(link.get('href'))

    def assertValidTenant(self, tenant):
        self.assertIsNotNone(tenant.get('id'))
        self.assertIsNotNone(tenant.get('name'))
        self.assertNotIn('domain_id', tenant)
        self.assertNotIn('parent_id', tenant)

    def assertValidUser(self, user):
        self.assertIsNotNone(user.get('id'))
        self.assertIsNotNone(user.get('name'))

    def assertValidRole(self, role):
        self.assertIsNotNone(role.get('id'))
        self.assertIsNotNone(role.get('name'))

    def test_public_not_found(self):
        r = self.public_request(
            path='/%s' % uuid.uuid4().hex,
            expected_status=http_client.NOT_FOUND)
        self.assertValidErrorResponse(r)

    def test_admin_not_found(self):
        r = self.admin_request(
            path='/%s' % uuid.uuid4().hex,
            expected_status=http_client.NOT_FOUND)
        self.assertValidErrorResponse(r)

    def test_public_multiple_choice(self):
        r = self.public_request(path='/', expected_status=300)
        self.assertValidMultipleChoiceResponse(r)

    def test_admin_multiple_choice(self):
        r = self.admin_request(path='/', expected_status=300)
        self.assertValidMultipleChoiceResponse(r)

    def test_public_version(self):
        r = self.public_request(path='/v2.0/')
        self.assertValidVersionResponse(r)

    def test_admin_version(self):
        r = self.admin_request(path='/v2.0/')
        self.assertValidVersionResponse(r)

    def test_public_extensions(self):
        r = self.public_request(path='/v2.0/extensions')
        self.assertValidExtensionListResponse(
            r, keystone_extension.PUBLIC_EXTENSIONS)

    def test_admin_extensions(self):
        r = self.admin_request(path='/v2.0/extensions')
        self.assertValidExtensionListResponse(
            r, keystone_extension.ADMIN_EXTENSIONS)

    def test_admin_extensions_returns_not_found(self):
        self.admin_request(path='/v2.0/extensions/invalid-extension',
                           expected_status=http_client.NOT_FOUND)

    def test_public_osksadm_extension_returns_not_found(self):
        self.public_request(path='/v2.0/extensions/OS-KSADM',
                            expected_status=http_client.NOT_FOUND)

    def test_admin_osksadm_extension(self):
        r = self.admin_request(path='/v2.0/extensions/OS-KSADM')
        self.assertValidExtensionResponse(
            r, keystone_extension.ADMIN_EXTENSIONS)

    def test_authenticate(self):
        r = self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'passwordCredentials': {
                        'username': self.user_foo['name'],
                        'password': self.user_foo['password'],
                    },
                    'tenantId': self.tenant_bar['id'],
                },
            },
            expected_status=http_client.OK)
        self.assertValidAuthenticationResponse(r, require_service_catalog=True)

    def test_authenticate_unscoped(self):
        r = self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'passwordCredentials': {
                        'username': self.user_foo['name'],
                        'password': self.user_foo['password'],
                    },
                },
            },
            expected_status=http_client.OK)
        self.assertValidAuthenticationResponse(r)

    def test_validate_token(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/tokens/%(token_id)s' % {
                'token_id': token,
            },
            token=token)
        self.assertValidAuthenticationResponse(r)

    def test_invalid_token_returns_not_found(self):
        token = self.get_scoped_token()
        self.admin_request(
            path='/v2.0/tokens/%(token_id)s' % {
                'token_id': 'invalid',
            },
            token=token,
            expected_status=http_client.NOT_FOUND)

    def test_validate_token_service_role(self):
        self.md_foobar = self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_service['id'],
            self.role_service['id'])

        token = self.get_scoped_token(
            tenant_id=default_fixtures.SERVICE_TENANT_ID)
        r = self.admin_request(
            path='/v2.0/tokens/%s' % token,
            token=token)
        self.assertValidAuthenticationResponse(r)

    def test_remove_role_revokes_token(self):
        self.md_foobar = self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_service['id'],
            self.role_service['id'])

        token = self.get_scoped_token(
            tenant_id=default_fixtures.SERVICE_TENANT_ID)
        r = self.admin_request(
            path='/v2.0/tokens/%s' % token,
            token=token)
        self.assertValidAuthenticationResponse(r)

        self.assignment_api.remove_role_from_user_and_project(
            self.user_foo['id'],
            self.tenant_service['id'],
            self.role_service['id'])

        r = self.admin_request(
            path='/v2.0/tokens/%s' % token,
            token=token,
            expected_status=http_client.UNAUTHORIZED)

    def test_validate_token_belongs_to(self):
        token = self.get_scoped_token()
        path = ('/v2.0/tokens/%s?belongsTo=%s' % (token,
                                                  self.tenant_bar['id']))
        r = self.admin_request(path=path, token=token)
        self.assertValidAuthenticationResponse(r, require_service_catalog=True)

    def test_validate_token_no_belongs_to_still_returns_catalog(self):
        token = self.get_scoped_token()
        path = ('/v2.0/tokens/%s' % token)
        r = self.admin_request(path=path, token=token)
        self.assertValidAuthenticationResponse(r, require_service_catalog=True)

    def test_validate_token_head(self):
        """The same call as above, except using HEAD.

        There's no response to validate here, but this is included for the
        sake of completely covering the core API.

        """
        token = self.get_scoped_token()
        self.admin_request(
            method='HEAD',
            path='/v2.0/tokens/%(token_id)s' % {
                'token_id': token,
            },
            token=token,
            expected_status=http_client.OK)

    def test_endpoints(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/tokens/%(token_id)s/endpoints' % {
                'token_id': token,
            },
            token=token)
        self.assertValidEndpointListResponse(r)

    def test_error_response(self):
        """Trigger assertValidErrorResponse by convention."""
        self.public_request(path='/v2.0/tenants',
                            expected_status=http_client.UNAUTHORIZED)

    def _get_user_id(self, r):
        """Helper method to return user ID from a response.

        This needs to be overridden by child classes
        based on their content type.

        """
        raise NotImplementedError()

    def _get_role_id(self, r):
        """Helper method to return a role ID from a response.

        This needs to be overridden by child classes
        based on their content type.

        """
        raise NotImplementedError()

    def _get_role_name(self, r):
        """Helper method to return role NAME from a response.

        This needs to be overridden by child classes
        based on their content type.

        """
        raise NotImplementedError()

    def _get_project_id(self, r):
        """Helper method to return project ID from a response.

        This needs to be overridden by child classes
        based on their content type.

        """
        raise NotImplementedError()

    def assertNoRoles(self, r):
        """Helper method to assert No Roles.

        This needs to be overridden by child classes
        based on their content type.

        """
        raise NotImplementedError()

    def test_authenticating_a_user_with_no_password(self):
        token = self.get_scoped_token()

        username = uuid.uuid4().hex

        # create the user
        self.admin_request(
            method='POST',
            path='/v3/users',
            body={
                'user': {
                    'name': username,
                    'enabled': True,
                },
            },
            token=token)

        # fail to authenticate
        r = self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'passwordCredentials': {
                        'username': username,
                        'password': 'password',
                    },
                },
            },
            expected_status=http_client.UNAUTHORIZED)
        self.assertValidErrorResponse(r)

    def test_www_authenticate_header(self):
        r = self.public_request(
            path='/v2.0/tenants',
            expected_status=http_client.UNAUTHORIZED)
        self.assertEqual('Keystone uri="http://localhost"',
                         r.headers.get('WWW-Authenticate'))

    def test_www_authenticate_header_host(self):
        test_url = 'http://%s:4187' % uuid.uuid4().hex
        self.config_fixture.config(public_endpoint=test_url)
        r = self.public_request(
            path='/v2.0/tenants',
            expected_status=http_client.UNAUTHORIZED)
        self.assertEqual('Keystone uri="%s"' % test_url,
                         r.headers.get('WWW-Authenticate'))


class RestfulTestCase(rest.RestfulTestCase):

    def setUp(self):
        super(RestfulTestCase, self).setUp()

        # TODO(termie): add an admin user to the fixtures and use that user
        # override the fixtures, for now
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_admin['id'])


class V2TestCase(object):

    def config_overrides(self):
        super(V2TestCase, self).config_overrides()
        self.config_fixture.config(
            group='catalog',
            driver='templated',
            template_file=unit.dirs.tests('default_catalog.templates'))

    def _get_user_id(self, r):
        return r['user']['id']

    def _get_role_name(self, r):
        return r['roles'][0]['name']

    def _get_role_id(self, r):
        return r['roles'][0]['id']

    def _get_project_id(self, r):
        return r['tenant']['id']

    def _get_token_id(self, r):
        return r.result['access']['token']['id']

    def assertNoRoles(self, r):
        self.assertEqual([], r['roles'])

    def assertValidErrorResponse(self, r):
        self.assertIsNotNone(r.result.get('error'))
        self.assertValidError(r.result['error'])
        self.assertEqual(r.result['error']['code'], r.status_code)

    def assertValidExtension(self, extension, expected):
        super(V2TestCase, self).assertValidExtension(extension)
        descriptions = [ext['description'] for ext in expected.values()]
        description = extension.get('description')
        self.assertIsNotNone(description)
        self.assertIn(description, descriptions)
        self.assertIsNotNone(extension.get('links'))
        self.assertNotEmpty(extension.get('links'))
        for link in extension.get('links'):
            self.assertValidExtensionLink(link)

    def assertValidExtensionListResponse(self, r, expected):
        self.assertIsNotNone(r.result.get('extensions'))
        self.assertIsNotNone(r.result['extensions'].get('values'))
        self.assertNotEmpty(r.result['extensions'].get('values'))
        for extension in r.result['extensions']['values']:
            self.assertValidExtension(extension, expected)

    def assertValidExtensionResponse(self, r, expected):
        self.assertValidExtension(r.result.get('extension'), expected)

    def assertValidUser(self, user):
        super(V2TestCase, self).assertValidUser(user)
        self.assertNotIn('default_project_id', user)
        if 'tenantId' in user:
            # NOTE(morganfainberg): tenantId should never be "None", it gets
            # filtered out of the object if it is there. This is suspenders
            # and a belt check to avoid unintended regressions.
            self.assertIsNotNone(user.get('tenantId'))

    def assertValidAuthenticationResponse(self, r,
                                          require_service_catalog=False):
        self.assertIsNotNone(r.result.get('access'))
        self.assertIsNotNone(r.result['access'].get('token'))
        self.assertIsNotNone(r.result['access'].get('user'))

        # validate token
        self.assertIsNotNone(r.result['access']['token'].get('id'))
        self.assertIsNotNone(r.result['access']['token'].get('expires'))
        tenant = r.result['access']['token'].get('tenant')
        if tenant is not None:
            # validate tenant
            self.assertIsNotNone(tenant.get('id'))
            self.assertIsNotNone(tenant.get('name'))

        # validate user
        self.assertIsNotNone(r.result['access']['user'].get('id'))
        self.assertIsNotNone(r.result['access']['user'].get('name'))

        if require_service_catalog:
            # roles are only provided with a service catalog
            roles = r.result['access']['user'].get('roles')
            self.assertNotEmpty(roles)
            for role in roles:
                self.assertIsNotNone(role.get('name'))

        serviceCatalog = r.result['access'].get('serviceCatalog')
        # validate service catalog
        if require_service_catalog:
            self.assertIsNotNone(serviceCatalog)
        if serviceCatalog is not None:
            self.assertIsInstance(serviceCatalog, list)
            if require_service_catalog:
                self.assertNotEmpty(serviceCatalog)
            for service in r.result['access']['serviceCatalog']:
                # validate service
                self.assertIsNotNone(service.get('name'))
                self.assertIsNotNone(service.get('type'))

                # services contain at least one endpoint
                self.assertIsNotNone(service.get('endpoints'))
                self.assertNotEmpty(service['endpoints'])
                for endpoint in service['endpoints']:
                    # validate service endpoint
                    self.assertIsNotNone(endpoint.get('publicURL'))

    def assertValidTenantListResponse(self, r):
        self.assertIsNotNone(r.result.get('tenants'))
        self.assertNotEmpty(r.result['tenants'])
        for tenant in r.result['tenants']:
            self.assertValidTenant(tenant)
            self.assertIsNotNone(tenant.get('enabled'))
            self.assertIn(tenant.get('enabled'), [True, False])

    def assertValidUserResponse(self, r):
        self.assertIsNotNone(r.result.get('user'))
        self.assertValidUser(r.result['user'])

    def assertValidTenantResponse(self, r):
        self.assertIsNotNone(r.result.get('tenant'))
        self.assertValidTenant(r.result['tenant'])

    def assertValidRoleListResponse(self, r):
        self.assertIsNotNone(r.result.get('roles'))
        self.assertNotEmpty(r.result['roles'])
        for role in r.result['roles']:
            self.assertValidRole(role)

    def assertValidVersion(self, version):
        super(V2TestCase, self).assertValidVersion(version)

        self.assertIsNotNone(version.get('links'))
        self.assertNotEmpty(version.get('links'))
        for link in version.get('links'):
            self.assertIsNotNone(link.get('rel'))
            self.assertIsNotNone(link.get('href'))

        self.assertIsNotNone(version.get('media-types'))
        self.assertNotEmpty(version.get('media-types'))
        for media in version.get('media-types'):
            self.assertIsNotNone(media.get('base'))
            self.assertIsNotNone(media.get('type'))

    def assertValidMultipleChoiceResponse(self, r):
        self.assertIsNotNone(r.result.get('versions'))
        self.assertIsNotNone(r.result['versions'].get('values'))
        self.assertNotEmpty(r.result['versions']['values'])
        for version in r.result['versions']['values']:
            self.assertValidVersion(version)

    def assertValidVersionResponse(self, r):
        self.assertValidVersion(r.result.get('version'))

    def assertValidEndpointListResponse(self, r):
        self.assertIsNotNone(r.result.get('endpoints'))
        self.assertNotEmpty(r.result['endpoints'])
        for endpoint in r.result['endpoints']:
            self.assertIsNotNone(endpoint.get('id'))
            self.assertIsNotNone(endpoint.get('name'))
            self.assertIsNotNone(endpoint.get('type'))
            self.assertIsNotNone(endpoint.get('publicURL'))
            self.assertIsNotNone(endpoint.get('internalURL'))
            self.assertIsNotNone(endpoint.get('adminURL'))

    def get_user_from_response(self, r):
        return r.result.get('user')

    def get_user_attribute_from_response(self, r, attribute_name):
        return r.result['user'][attribute_name]

    def test_fetch_revocation_list_nonadmin_fails(self):
        self.admin_request(
            method='GET',
            path='/v2.0/tokens/revoked',
            expected_status=http_client.UNAUTHORIZED)

    def test_fetch_revocation_list_admin_200(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            method='GET',
            path='/v2.0/tokens/revoked',
            token=token,
            expected_status=http_client.OK)
        self.assertValidRevocationListResponse(r)

    def assertValidRevocationListResponse(self, response):
        self.assertIsNotNone(response.result['signed'])


class V2TestCaseUUID(V2TestCase, RestfulTestCase, CoreApiTests):

    def config_overrides(self):
        super(V2TestCaseUUID, self).config_overrides()
        self.config_fixture.config(group='token', provider='uuid')


class V2TestCaseFernet(V2TestCase, RestfulTestCase, CoreApiTests):

    def config_overrides(self):
        super(V2TestCaseFernet, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def test_fetch_revocation_list_md5(self):
        self.skipTest('Revocation lists do not support Fernet')

    def test_fetch_revocation_list_sha256(self):
        self.skipTest('Revocation lists do not support Fernet')


class TestFernetTokenProviderV2(RestfulTestCase):

    def setUp(self):
        super(TestFernetTokenProviderV2, self).setUp()
        # Add catalog data
        self.region = unit.new_region_ref()
        self.region_id = self.region['id']
        self.catalog_api.create_region(self.region)

        self.service = unit.new_service_ref()
        self.service_id = self.service['id']
        self.catalog_api.create_service(self.service_id, self.service)

        self.endpoint = unit.new_endpoint_ref(service_id=self.service_id,
                                              interface='public',
                                              region_id=self.region_id)
        self.endpoint_id = self.endpoint['id']
        self.catalog_api.create_endpoint(self.endpoint_id, self.endpoint)

    def assertValidUnscopedTokenResponse(self, r):
        v2.unscoped_validator.validate(r.json['access'])

    def assertValidScopedTokenResponse(self, r):
        v2.scoped_validator.validate(r.json['access'])

    # Used by RestfulTestCase
    def _get_token_id(self, r):
        return r.result['access']['token']['id']

    def new_project_ref(self):
        return {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'description': uuid.uuid4().hex,
                'domain_id': 'default',
                'enabled': True}

    def config_overrides(self):
        super(TestFernetTokenProviderV2, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def test_authenticate_unscoped_token(self):
        unscoped_token = self.get_unscoped_token()
        # Fernet token must be of length 255 per usability requirements
        self.assertLess(len(unscoped_token), 255)

    def test_validate_unscoped_token(self):
        # Grab an admin token to validate with
        project_ref = self.new_project_ref()
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.assignment_api.add_role_to_user_and_project(self.user_foo['id'],
                                                         project_ref['id'],
                                                         self.role_admin['id'])
        admin_token = self.get_scoped_token(tenant_id=project_ref['id'])
        unscoped_token = self.get_unscoped_token()
        path = ('/v2.0/tokens/%s' % unscoped_token)
        resp = self.admin_request(
            method='GET',
            path=path,
            token=admin_token,
            expected_status=http_client.OK)
        self.assertValidUnscopedTokenResponse(resp)

    def test_authenticate_scoped_token(self):
        project_ref = self.new_project_ref()
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], project_ref['id'], self.role_service['id'])
        token = self.get_scoped_token(tenant_id=project_ref['id'])
        # Fernet token must be of length 255 per usability requirements
        self.assertLess(len(token), 255)

    def test_validate_scoped_token(self):
        project_ref = self.new_project_ref()
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.assignment_api.add_role_to_user_and_project(self.user_foo['id'],
                                                         project_ref['id'],
                                                         self.role_admin['id'])
        project2_ref = self.new_project_ref()
        self.resource_api.create_project(project2_ref['id'], project2_ref)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], project2_ref['id'], self.role_member['id'])
        admin_token = self.get_scoped_token(tenant_id=project_ref['id'])
        member_token = self.get_scoped_token(tenant_id=project2_ref['id'])
        path = ('/v2.0/tokens/%s?belongsTo=%s' % (member_token,
                project2_ref['id']))
        # Validate token belongs to project
        resp = self.admin_request(
            method='GET',
            path=path,
            token=admin_token,
            expected_status=http_client.OK)
        self.assertValidScopedTokenResponse(resp)

    def test_token_authentication_and_validation(self):
        """Test token authentication for Fernet token provider.

        Verify that token authentication returns validate response code and
        valid token belongs to project.
        """
        project_ref = self.new_project_ref()
        self.resource_api.create_project(project_ref['id'], project_ref)
        unscoped_token = self.get_unscoped_token()
        self.assignment_api.add_role_to_user_and_project(self.user_foo['id'],
                                                         project_ref['id'],
                                                         self.role_admin['id'])
        token_id = unscoped_token
        if six.PY2:
            token_id = token_id.encode('ascii')
        r = self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'tenantName': project_ref['name'],
                    'token': {
                        'id': token_id,
                    }
                }
            },
            expected_status=http_client.OK)

        token_id = self._get_token_id(r)
        path = ('/v2.0/tokens/%s?belongsTo=%s' % (token_id, project_ref['id']))
        # Validate token belongs to project
        resp = self.admin_request(
            method='GET',
            path=path,
            token=self.get_admin_token(),
            expected_status=http_client.OK)
        self.assertValidScopedTokenResponse(resp)

    def test_rescoped_tokens_maintain_original_expiration(self):
        project_ref = self.new_project_ref()
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.assignment_api.add_role_to_user_and_project(self.user_foo['id'],
                                                         project_ref['id'],
                                                         self.role_admin['id'])
        resp = self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'tenantName': project_ref['name'],
                    'passwordCredentials': {
                        'username': self.user_foo['name'],
                        'password': self.user_foo['password']
                    }
                }
            },
            # NOTE(lbragstad): This test may need to be refactored if Keystone
            # decides to disallow rescoping using a scoped token.
            expected_status=http_client.OK)
        original_token = resp.result['access']['token']['id']
        original_expiration = resp.result['access']['token']['expires']

        resp = self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'tenantName': project_ref['name'],
                    'token': {
                        'id': original_token,
                    }
                }
            },
            expected_status=http_client.OK)
        rescoped_token = resp.result['access']['token']['id']
        rescoped_expiration = resp.result['access']['token']['expires']
        self.assertNotEqual(original_token, rescoped_token)
        self.assertEqual(original_expiration, rescoped_expiration)
        self.assertValidScopedTokenResponse(resp)
