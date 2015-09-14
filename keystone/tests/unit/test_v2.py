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

import json
import time
import uuid

from keystoneclient.common import cms
from oslo_config import cfg
import six
from six.moves import http_client
from testtools import matchers

from keystone.common import extension as keystone_extension
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import rest


CONF = cfg.CONF


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

    def assertValidRole(self, tenant):
        self.assertIsNotNone(tenant.get('id'))
        self.assertIsNotNone(tenant.get('name'))

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

    def test_admin_extensions_404(self):
        self.admin_request(path='/v2.0/extensions/invalid-extension',
                           expected_status=http_client.NOT_FOUND)

    def test_public_osksadm_extension_404(self):
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
            expected_status=200)
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
            expected_status=200)
        self.assertValidAuthenticationResponse(r)

    def test_get_tenants_for_token(self):
        r = self.public_request(path='/v2.0/tenants',
                                token=self.get_scoped_token())
        self.assertValidTenantListResponse(r)

    def test_validate_token(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/tokens/%(token_id)s' % {
                'token_id': token,
            },
            token=token)
        self.assertValidAuthenticationResponse(r)

    def test_invalid_token_404(self):
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

        token = self.get_scoped_token(tenant_id='service')
        r = self.admin_request(
            path='/v2.0/tokens/%s' % token,
            token=token)
        self.assertValidAuthenticationResponse(r)

    def test_remove_role_revokes_token(self):
        self.md_foobar = self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_service['id'],
            self.role_service['id'])

        token = self.get_scoped_token(tenant_id='service')
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
            expected_status=200)

    def test_endpoints(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/tokens/%(token_id)s/endpoints' % {
                'token_id': token,
            },
            token=token)
        self.assertValidEndpointListResponse(r)

    def test_get_tenant(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/tenants/%(tenant_id)s' % {
                'tenant_id': self.tenant_bar['id'],
            },
            token=token)
        self.assertValidTenantResponse(r)

    def test_get_tenant_by_name(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/tenants?name=%(tenant_name)s' % {
                'tenant_name': self.tenant_bar['name'],
            },
            token=token)
        self.assertValidTenantResponse(r)

    def test_get_user_roles_with_tenant(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/tenants/%(tenant_id)s/users/%(user_id)s/roles' % {
                'tenant_id': self.tenant_bar['id'],
                'user_id': self.user_foo['id'],
            },
            token=token)
        self.assertValidRoleListResponse(r)

    def test_get_user(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/users/%(user_id)s' % {
                'user_id': self.user_foo['id'],
            },
            token=token)
        self.assertValidUserResponse(r)

    def test_get_user_by_name(self):
        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/users?name=%(user_name)s' % {
                'user_name': self.user_foo['name'],
            },
            token=token)
        self.assertValidUserResponse(r)

    def test_create_update_user_invalid_enabled_type(self):
        # Enforce usage of boolean for 'enabled' field
        token = self.get_scoped_token()

        # Test CREATE request
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex,
                    'enabled': "False",
                },
            },
            token=token,
            expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(r)

        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex,
                    # In JSON, 0|1 are not booleans
                    'enabled': 0,
                },
            },
            token=token,
            expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(r)

        # Test UPDATE request
        path = '/v2.0/users/%(user_id)s' % {
               'user_id': self.user_foo['id'],
        }

        r = self.admin_request(
            method='PUT',
            path=path,
            body={
                'user': {
                    'enabled': "False",
                },
            },
            token=token,
            expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(r)

        r = self.admin_request(
            method='PUT',
            path=path,
            body={
                'user': {
                    # In JSON, 0|1 are not booleans
                    'enabled': 1,
                },
            },
            token=token,
            expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(r)

    def test_create_update_user_valid_enabled_type(self):
        # Enforce usage of boolean for 'enabled' field
        token = self.get_scoped_token()

        # Test CREATE request
        self.admin_request(method='POST',
                           path='/v2.0/users',
                           body={
                               'user': {
                                   'name': uuid.uuid4().hex,
                                   'password': uuid.uuid4().hex,
                                   'enabled': False,
                               },
                           },
                           token=token,
                           expected_status=200)

    def test_error_response(self):
        """This triggers assertValidErrorResponse by convention."""
        self.public_request(path='/v2.0/tenants',
                            expected_status=http_client.UNAUTHORIZED)

    def test_invalid_parameter_error_response(self):
        token = self.get_scoped_token()
        bad_body = {
            'OS-KSADM:service%s' % uuid.uuid4().hex: {
                'name': uuid.uuid4().hex,
                'type': uuid.uuid4().hex,
            },
        }
        res = self.admin_request(method='POST',
                                 path='/v2.0/OS-KSADM/services',
                                 body=bad_body,
                                 token=token,
                                 expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(res)
        res = self.admin_request(method='POST',
                                 path='/v2.0/users',
                                 body=bad_body,
                                 token=token,
                                 expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(res)

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
        """Helper method to assert No Roles

        This needs to be overridden by child classes
        based on their content type.

        """
        raise NotImplementedError()

    def test_update_user_tenant(self):
        token = self.get_scoped_token()

        # Create a new user
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex,
                    'tenantId': self.tenant_bar['id'],
                    'enabled': True,
                },
            },
            token=token,
            expected_status=200)

        user_id = self._get_user_id(r.result)

        # Check if member_role is in tenant_bar
        r = self.admin_request(
            path='/v2.0/tenants/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.tenant_bar['id'],
                'user_id': user_id
            },
            token=token,
            expected_status=200)
        self.assertEqual(CONF.member_role_name, self._get_role_name(r.result))

        # Create a new tenant
        r = self.admin_request(
            method='POST',
            path='/v2.0/tenants',
            body={
                'tenant': {
                    'name': 'test_update_user',
                    'description': 'A description ...',
                    'enabled': True,
                },
            },
            token=token,
            expected_status=200)

        project_id = self._get_project_id(r.result)

        # Update user's tenant
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%(user_id)s' % {
                'user_id': user_id,
            },
            body={
                'user': {
                    'tenantId': project_id,
                },
            },
            token=token,
            expected_status=200)

        # 'member_role' should be in new_tenant
        r = self.admin_request(
            path='/v2.0/tenants/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': project_id,
                'user_id': user_id
            },
            token=token,
            expected_status=200)
        self.assertEqual('_member_', self._get_role_name(r.result))

        # 'member_role' should not be in tenant_bar any more
        r = self.admin_request(
            path='/v2.0/tenants/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.tenant_bar['id'],
                'user_id': user_id
            },
            token=token,
            expected_status=200)
        self.assertNoRoles(r.result)

    def test_update_user_with_invalid_tenant(self):
        token = self.get_scoped_token()

        # Create a new user
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': 'test_invalid_tenant',
                    'password': uuid.uuid4().hex,
                    'tenantId': self.tenant_bar['id'],
                    'enabled': True,
                },
            },
            token=token,
            expected_status=200)
        user_id = self._get_user_id(r.result)

        # Update user with an invalid tenant
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%(user_id)s' % {
                'user_id': user_id,
            },
            body={
                'user': {
                    'tenantId': 'abcde12345heha',
                },
            },
            token=token,
            expected_status=http_client.NOT_FOUND)

    def test_update_user_with_invalid_tenant_no_prev_tenant(self):
        token = self.get_scoped_token()

        # Create a new user
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': 'test_invalid_tenant',
                    'password': uuid.uuid4().hex,
                    'enabled': True,
                },
            },
            token=token,
            expected_status=200)
        user_id = self._get_user_id(r.result)

        # Update user with an invalid tenant
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%(user_id)s' % {
                'user_id': user_id,
            },
            body={
                'user': {
                    'tenantId': 'abcde12345heha',
                },
            },
            token=token,
            expected_status=http_client.NOT_FOUND)

    def test_update_user_with_old_tenant(self):
        token = self.get_scoped_token()

        # Create a new user
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex,
                    'tenantId': self.tenant_bar['id'],
                    'enabled': True,
                },
            },
            token=token,
            expected_status=200)

        user_id = self._get_user_id(r.result)

        # Check if member_role is in tenant_bar
        r = self.admin_request(
            path='/v2.0/tenants/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.tenant_bar['id'],
                'user_id': user_id
            },
            token=token,
            expected_status=200)
        self.assertEqual(CONF.member_role_name, self._get_role_name(r.result))

        # Update user's tenant with old tenant id
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%(user_id)s' % {
                'user_id': user_id,
            },
            body={
                'user': {
                    'tenantId': self.tenant_bar['id'],
                },
            },
            token=token,
            expected_status=200)

        # 'member_role' should still be in tenant_bar
        r = self.admin_request(
            path='/v2.0/tenants/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.tenant_bar['id'],
                'user_id': user_id
            },
            token=token,
            expected_status=200)
        self.assertEqual('_member_', self._get_role_name(r.result))

    def test_authenticating_a_user_with_no_password(self):
        token = self.get_scoped_token()

        username = uuid.uuid4().hex

        # create the user
        self.admin_request(
            method='POST',
            path='/v2.0/users',
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


class LegacyV2UsernameTests(object):
    """Tests to show the broken username behavior in V2.

    The V2 API is documented to use `username` instead of `name`.  The
    API forced used to use name and left the username to fall into the
    `extra` field.

    These tests ensure this behavior works so fixes to `username`/`name`
    will be backward compatible.
    """

    def create_user(self, **user_attrs):
        """Creates a users and returns the response object.

        :param user_attrs: attributes added to the request body (optional)
        """
        token = self.get_scoped_token()
        body = {
            'user': {
                'name': uuid.uuid4().hex,
                'enabled': True,
            },
        }
        body['user'].update(user_attrs)

        return self.admin_request(
            method='POST',
            path='/v2.0/users',
            token=token,
            body=body,
            expected_status=200)

    def test_create_with_extra_username(self):
        """The response for creating a user will contain the extra fields."""
        fake_username = uuid.uuid4().hex
        r = self.create_user(username=fake_username)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(fake_username, user.get('username'))

    def test_get_returns_username_from_extra(self):
        """The response for getting a user will contain the extra fields."""
        token = self.get_scoped_token()

        fake_username = uuid.uuid4().hex
        r = self.create_user(username=fake_username)

        id_ = self.get_user_attribute_from_response(r, 'id')
        r = self.admin_request(path='/v2.0/users/%s' % id_, token=token)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(fake_username, user.get('username'))

    def test_update_returns_new_username_when_adding_username(self):
        """The response for updating a user will contain the extra fields.

        This is specifically testing for updating a username when a value
        was not previously set.
        """
        token = self.get_scoped_token()

        r = self.create_user()

        id_ = self.get_user_attribute_from_response(r, 'id')
        name = self.get_user_attribute_from_response(r, 'name')
        enabled = self.get_user_attribute_from_response(r, 'enabled')
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%s' % id_,
            token=token,
            body={
                'user': {
                    'name': name,
                    'username': 'new_username',
                    'enabled': enabled,
                },
            },
            expected_status=200)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual('new_username', user.get('username'))

    def test_update_returns_new_username_when_updating_username(self):
        """The response for updating a user will contain the extra fields.

        This tests updating a username that was previously set.
        """
        token = self.get_scoped_token()

        r = self.create_user(username='original_username')

        id_ = self.get_user_attribute_from_response(r, 'id')
        name = self.get_user_attribute_from_response(r, 'name')
        enabled = self.get_user_attribute_from_response(r, 'enabled')
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%s' % id_,
            token=token,
            body={
                'user': {
                    'name': name,
                    'username': 'new_username',
                    'enabled': enabled,
                },
            },
            expected_status=200)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual('new_username', user.get('username'))

    def test_username_is_always_returned_create(self):
        """Username is set as the value of name if no username is provided.

        This matches the v2.0 spec where we really should be using username
        and not name.
        """
        r = self.create_user()

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(user.get('name'), user.get('username'))

    def test_username_is_always_returned_get(self):
        """Username is set as the value of name if no username is provided.

        This matches the v2.0 spec where we really should be using username
        and not name.
        """
        token = self.get_scoped_token()

        r = self.create_user()

        id_ = self.get_user_attribute_from_response(r, 'id')
        r = self.admin_request(path='/v2.0/users/%s' % id_, token=token)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(user.get('name'), user.get('username'))

    def test_username_is_always_returned_get_by_name(self):
        """Username is set as the value of name if no username is provided.

        This matches the v2.0 spec where we really should be using username
        and not name.
        """
        token = self.get_scoped_token()

        r = self.create_user()

        name = self.get_user_attribute_from_response(r, 'name')
        r = self.admin_request(path='/v2.0/users?name=%s' % name, token=token)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(user.get('name'), user.get('username'))

    def test_username_is_always_returned_update_no_username_provided(self):
        """Username is set as the value of name if no username is provided.

        This matches the v2.0 spec where we really should be using username
        and not name.
        """
        token = self.get_scoped_token()

        r = self.create_user()

        id_ = self.get_user_attribute_from_response(r, 'id')
        name = self.get_user_attribute_from_response(r, 'name')
        enabled = self.get_user_attribute_from_response(r, 'enabled')
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%s' % id_,
            token=token,
            body={
                'user': {
                    'name': name,
                    'enabled': enabled,
                },
            },
            expected_status=200)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(user.get('name'), user.get('username'))

    def test_updated_username_is_returned(self):
        """Username is set as the value of name if no username is provided.

        This matches the v2.0 spec where we really should be using username
        and not name.
        """
        token = self.get_scoped_token()

        r = self.create_user()

        id_ = self.get_user_attribute_from_response(r, 'id')
        name = self.get_user_attribute_from_response(r, 'name')
        enabled = self.get_user_attribute_from_response(r, 'enabled')
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%s' % id_,
            token=token,
            body={
                'user': {
                    'name': name,
                    'enabled': enabled,
                },
            },
            expected_status=200)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(user.get('name'), user.get('username'))

    def test_username_can_be_used_instead_of_name_create(self):
        token = self.get_scoped_token()

        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            token=token,
            body={
                'user': {
                    'username': uuid.uuid4().hex,
                    'enabled': True,
                },
            },
            expected_status=200)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(user.get('name'), user.get('username'))

    def test_username_can_be_used_instead_of_name_update(self):
        token = self.get_scoped_token()

        r = self.create_user()

        id_ = self.get_user_attribute_from_response(r, 'id')
        new_username = uuid.uuid4().hex
        enabled = self.get_user_attribute_from_response(r, 'enabled')
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%s' % id_,
            token=token,
            body={
                'user': {
                    'username': new_username,
                    'enabled': enabled,
                },
            },
            expected_status=200)

        self.assertValidUserResponse(r)

        user = self.get_user_from_response(r)
        self.assertEqual(new_username, user.get('name'))
        self.assertEqual(user.get('name'), user.get('username'))


class RestfulTestCase(rest.RestfulTestCase):

    def setUp(self):
        super(RestfulTestCase, self).setUp()

        # TODO(termie): add an admin user to the fixtures and use that user
        # override the fixtures, for now
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_admin['id'])


class V2TestCase(RestfulTestCase, CoreApiTests, LegacyV2UsernameTests):
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
        descriptions = [ext['description'] for ext in six.itervalues(expected)]
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

    def test_service_crud_requires_auth(self):
        """Service CRUD should return unauthorized without an X-Auth-Token."""
        # values here don't matter because it will be unauthorized before
        # they're checked (bug 1006822).
        service_path = '/v2.0/OS-KSADM/services/%s' % uuid.uuid4().hex
        service_body = {
            'OS-KSADM:service': {
                'name': uuid.uuid4().hex,
                'type': uuid.uuid4().hex,
            },
        }

        r = self.admin_request(method='GET',
                               path='/v2.0/OS-KSADM/services',
                               expected_status=http_client.UNAUTHORIZED)
        self.assertValidErrorResponse(r)

        r = self.admin_request(method='POST',
                               path='/v2.0/OS-KSADM/services',
                               body=service_body,
                               expected_status=http_client.UNAUTHORIZED)
        self.assertValidErrorResponse(r)

        r = self.admin_request(method='GET',
                               path=service_path,
                               expected_status=http_client.UNAUTHORIZED)
        self.assertValidErrorResponse(r)

        r = self.admin_request(method='DELETE',
                               path=service_path,
                               expected_status=http_client.UNAUTHORIZED)
        self.assertValidErrorResponse(r)

    def test_user_role_list_requires_auth(self):
        """User role list return unauthorized without an X-Auth-Token."""
        # values here don't matter because it will be unauthorized before
        # they're checked (bug 1006815).
        path = '/v2.0/tenants/%(tenant_id)s/users/%(user_id)s/roles' % {
            'tenant_id': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
        }

        r = self.admin_request(path=path,
                               expected_status=http_client.UNAUTHORIZED)
        self.assertValidErrorResponse(r)

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
            expected_status=200)
        self.assertValidRevocationListResponse(r)

    def assertValidRevocationListResponse(self, response):
        self.assertIsNotNone(response.result['signed'])

    def _fetch_parse_revocation_list(self):

        token1 = self.get_scoped_token()

        # TODO(morganfainberg): Because this is making a restful call to the
        # app a change to UTCNOW via mock.patch will not affect the returned
        # token. The only surefire way to ensure there is not a transient bug
        # based upon when the second token is issued is with a sleep. This
        # issue all stems from the limited resolution (no microseconds) on the
        # expiry time of tokens and the way revocation events utilizes token
        # expiry to revoke individual tokens. This is a stop-gap until all
        # associated issues with resolution on expiration and revocation events
        # are resolved.
        time.sleep(1)

        token2 = self.get_scoped_token()

        self.admin_request(method='DELETE',
                           path='/v2.0/tokens/%s' % token2,
                           token=token1)

        r = self.admin_request(
            method='GET',
            path='/v2.0/tokens/revoked',
            token=token1,
            expected_status=200)
        signed_text = r.result['signed']

        data_json = cms.cms_verify(signed_text, CONF.signing.certfile,
                                   CONF.signing.ca_certs)

        data = json.loads(data_json)

        return (data, token2)

    def test_fetch_revocation_list_md5(self):
        """If the server is configured for md5, then the revocation list has
           tokens hashed with MD5.
        """

        # The default hash algorithm is md5.
        hash_algorithm = 'md5'

        (data, token) = self._fetch_parse_revocation_list()
        token_hash = cms.cms_hash_token(token, mode=hash_algorithm)
        self.assertThat(token_hash, matchers.Equals(data['revoked'][0]['id']))

    def test_fetch_revocation_list_sha256(self):
        """If the server is configured for sha256, then the revocation list has
           tokens hashed with SHA256
        """

        hash_algorithm = 'sha256'
        self.config_fixture.config(group='token',
                                   hash_algorithm=hash_algorithm)

        (data, token) = self._fetch_parse_revocation_list()
        token_hash = cms.cms_hash_token(token, mode=hash_algorithm)
        self.assertThat(token_hash, matchers.Equals(data['revoked'][0]['id']))

    def test_create_update_user_invalid_enabled_type(self):
        # Enforce usage of boolean for 'enabled' field
        token = self.get_scoped_token()

        # Test CREATE request
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex,
                    # In JSON, "true|false" are not boolean
                    'enabled': "true",
                },
            },
            token=token,
            expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(r)

        # Test UPDATE request
        r = self.admin_request(
            method='PUT',
            path='/v2.0/users/%(user_id)s' % {
                 'user_id': self.user_foo['id'],
            },
            body={
                'user': {
                    # In JSON, "true|false" are not boolean
                    'enabled': "true",
                },
            },
            token=token,
            expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(r)

    def test_authenticating_a_user_with_an_OSKSADM_password(self):
        token = self.get_scoped_token()

        username = uuid.uuid4().hex
        password = uuid.uuid4().hex

        # create the user
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': username,
                    'OS-KSADM:password': password,
                    'enabled': True,
                },
            },
            token=token)

        # successfully authenticate
        self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'passwordCredentials': {
                        'username': username,
                        'password': password,
                    },
                },
            },
            expected_status=200)

        # ensure password doesn't leak
        user_id = r.result['user']['id']
        r = self.admin_request(
            method='GET',
            path='/v2.0/users/%s' % user_id,
            token=token,
            expected_status=200)
        self.assertNotIn('OS-KSADM:password', r.result['user'])

    def test_updating_a_user_with_an_OSKSADM_password(self):
        token = self.get_scoped_token()

        user_id = self.user_foo['id']
        password = uuid.uuid4().hex

        # update the user
        self.admin_request(
            method='PUT',
            path='/v2.0/users/%s/OS-KSADM/password' % user_id,
            body={
                'user': {
                   'password': password,
                },
            },
            token=token,
            expected_status=200)

        # successfully authenticate
        self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'passwordCredentials': {
                        'username': self.user_foo['name'],
                        'password': password,
                    },
                },
            },
            expected_status=200)


class RevokeApiTestCase(V2TestCase):
    def config_overrides(self):
        super(RevokeApiTestCase, self).config_overrides()
        self.config_fixture.config(group='revoke', driver='kvs')
        self.config_fixture.config(
            group='token',
            provider='pki',
            revoke_by_id=False)

    def test_fetch_revocation_list_admin_200(self):
        self.skipTest('Revoke API disables revocation_list.')

    def test_fetch_revocation_list_md5(self):
        self.skipTest('Revoke API disables revocation_list.')

    def test_fetch_revocation_list_sha256(self):
        self.skipTest('Revoke API disables revocation_list.')


class TestFernetTokenProviderV2(RestfulTestCase):

    def setUp(self):
        super(TestFernetTokenProviderV2, self).setUp()
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))

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
        self.admin_request(
            method='GET',
            path=path,
            token=admin_token,
            expected_status=200)

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
        self.admin_request(
            method='GET',
            path=path,
            token=admin_token,
            expected_status=200)

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
        r = self.public_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'tenantName': project_ref['name'],
                    'token': {
                        'id': unscoped_token.encode('ascii')
                    }
                }
            },
            expected_status=200)

        token_id = self._get_token_id(r)
        path = ('/v2.0/tokens/%s?belongsTo=%s' % (token_id, project_ref['id']))
        # Validate token belongs to project
        self.admin_request(
            method='GET',
            path=path,
            token=CONF.admin_token,
            expected_status=200)

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
            expected_status=200)
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
            expected_status=200)
        rescoped_token = resp.result['access']['token']['id']
        rescoped_expiration = resp.result['access']['token']['expires']
        self.assertNotEqual(original_token, rescoped_token)
        self.assertEqual(original_expiration, rescoped_expiration)
