# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import io
import uuid

from lxml import etree
import nose.exc
import webtest

from keystone import test

from keystone.common import extension
from keystone.common import serializer
from keystone.openstack.common import jsonutils

import default_fixtures


class RestfulTestCase(test.TestCase):
    """Performs restful tests against the WSGI app over HTTP.

    This class launches public & admin WSGI servers for every test, which can
    be accessed by calling ``public_request()`` or ``admin_request()``,
    respectfully.

    ``restful_request()`` and ``request()`` methods are also exposed if you
    need to bypass restful conventions or access HTTP details in your test
    implementation.

    Three new asserts are provided:

    * ``assertResponseSuccessful``: called automatically for every request
        unless an ``expected_status`` is provided
    * ``assertResponseStatus``: called instead of ``assertResponseSuccessful``,
        if an ``expected_status`` is provided
    * ``assertValidResponseHeaders``: validates that the response headers
        appear as expected

    Requests are automatically serialized according to the defined
    ``content_type``. Responses are automatically deserialized as well, and
    available in the ``response.body`` attribute. The original body content is
    available in the ``response.raw`` attribute.

    """

    # default content type to test
    content_type = 'json'

    def setUp(self):
        super(RestfulTestCase, self).setUp()

        self.load_backends()
        self.load_fixtures(default_fixtures)

        self.public_app = webtest.TestApp(
            self.loadapp('keystone', name='main'))
        self.admin_app = webtest.TestApp(
            self.loadapp('keystone', name='admin'))

        # TODO(termie): add an admin user to the fixtures and use that user
        # override the fixtures, for now
        self.metadata_foobar = self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_admin['id'])

    def tearDown(self):
        """Kill running servers and release references to avoid leaks."""
        self.public_app = None
        self.admin_app = None
        super(RestfulTestCase, self).tearDown()

    def request(self, app, path, body=None, headers=None, token=None,
                expected_status=None, **kwargs):
        if headers:
            headers = dict([(str(k), str(v)) for k, v in headers.iteritems()])
        else:
            headers = {}

        if token:
            headers['X-Auth-Token'] = str(token)

        # setting body this way because of:
        # https://github.com/Pylons/webtest/issues/71
        if body:
            kwargs['body_file'] = io.BytesIO(body)

        # sets environ['REMOTE_ADDR']
        kwargs.setdefault('remote_addr', 'localhost')

        response = app.request(path, headers=headers,
                               status=expected_status, **kwargs)

        return response

    def assertResponseSuccessful(self, response):
        """Asserts that a status code lies inside the 2xx range.

        :param response: :py:class:`httplib.HTTPResponse` to be
          verified to have a status code between 200 and 299.

        example::

             self.assertResponseSuccessful(response, 203)
        """
        self.assertTrue(
            response.status_code >= 200 and response.status_code <= 299,
            'Status code %d is outside of the expected range (2xx)\n\n%s' %
            (response.status, response.body))

    def assertResponseStatus(self, response, expected_status):
        """Asserts a specific status code on the response.

        :param response: :py:class:`httplib.HTTPResponse`
        :param assert_status: The specific ``status`` result expected

        example::

            self.assertResponseStatus(response, 203)
        """
        self.assertEqual(
            response.status_code,
            expected_status,
            'Status code %s is not %s, as expected)\n\n%s' %
            (response.status_code, expected_status, response.body))

    def assertValidResponseHeaders(self, response):
        """Ensures that response headers appear as expected."""
        self.assertIn('X-Auth-Token', response.headers.get('Vary'))

    def _to_content_type(self, body, headers, content_type=None):
        """Attempt to encode JSON and XML automatically."""
        content_type = content_type or self.content_type

        if content_type == 'json':
            headers['Accept'] = 'application/json'
            if body:
                headers['Content-Type'] = 'application/json'
                return jsonutils.dumps(body)
        elif content_type == 'xml':
            headers['Accept'] = 'application/xml'
            if body:
                headers['Content-Type'] = 'application/xml'
                return serializer.to_xml(body)

    def _from_content_type(self, response, content_type=None):
        """Attempt to decode JSON and XML automatically, if detected."""
        content_type = content_type or self.content_type

        if response.body is not None and response.body.strip():
            # if a body is provided, a Content-Type is also expected
            header = response.headers.get('Content-Type', None)
            self.assertIn(content_type, header)

            if content_type == 'json':
                response.result = jsonutils.loads(response.body)
            elif content_type == 'xml':
                response.result = etree.fromstring(response.body)

    def restful_request(self, method='GET', headers=None, body=None,
                        content_type=None, **kwargs):
        """Serializes/deserializes json/xml as request/response body.

        .. WARNING::

            * Existing Accept header will be overwritten.
            * Existing Content-Type header will be overwritten.

        """
        # Initialize headers dictionary
        headers = {} if not headers else headers

        body = self._to_content_type(body, headers, content_type)

        # Perform the HTTP request/response
        response = self.request(method=method, headers=headers, body=body,
                                **kwargs)

        self._from_content_type(response, content_type)

        # we can save some code & improve coverage by always doing this
        if method != 'HEAD' and response.status_code >= 400:
            self.assertValidErrorResponse(response)

        # Contains the decoded response.body
        return response

    def _request(self, convert=True, **kwargs):
        if convert:
            response = self.restful_request(**kwargs)
        else:
            response = self.request(**kwargs)

        self.assertValidResponseHeaders(response)
        return response

    def public_request(self, **kwargs):
        return self._request(app=self.public_app, **kwargs)

    def admin_request(self, **kwargs):
        return self._request(app=self.admin_app, **kwargs)

    def _get_token(self, body):
        """Convenience method so that we can test authenticated requests."""
        r = self.public_request(method='POST', path='/v2.0/tokens', body=body)
        return self._get_token_id(r)

    def get_unscoped_token(self):
        """Convenience method so that we can test authenticated requests."""
        return self._get_token({
            'auth': {
                'passwordCredentials': {
                    'username': self.user_foo['name'],
                    'password': self.user_foo['password'],
                },
            },
        })

    def get_scoped_token(self, tenant_id=None):
        """Convenience method so that we can test authenticated requests."""
        if not tenant_id:
            tenant_id = self.tenant_bar['id']
        return self._get_token({
            'auth': {
                'passwordCredentials': {
                    'username': self.user_foo['name'],
                    'password': self.user_foo['password'],
                },
                'tenantId': tenant_id,
            },
        })

    def _get_token_id(self, r):
        """Helper method to return a token ID from a response.

        This needs to be overridden by child classes for on their content type.

        """
        raise NotImplementedError()


class CoreApiTests(object):
    def assertValidError(self, error):
        """Applicable to XML and JSON."""
        self.assertIsNotNone(error.get('code'))
        self.assertIsNotNone(error.get('title'))
        self.assertIsNotNone(error.get('message'))

    def assertValidVersion(self, version):
        """Applicable to XML and JSON.

        However, navigating links and media-types differs between content
        types so they need to be validated separately.

        """
        self.assertIsNotNone(version)
        self.assertIsNotNone(version.get('id'))
        self.assertIsNotNone(version.get('status'))
        self.assertIsNotNone(version.get('updated'))

    def assertValidExtension(self, extension):
        """Applicable to XML and JSON.

        However, navigating extension links differs between content types.
        They need to be validated separately with assertValidExtensionLink.

        """
        self.assertIsNotNone(extension)
        self.assertIsNotNone(extension.get('name'))
        self.assertIsNotNone(extension.get('namespace'))
        self.assertIsNotNone(extension.get('alias'))
        self.assertIsNotNone(extension.get('updated'))

    def assertValidExtensionLink(self, link):
        """Applicable to XML and JSON."""
        self.assertIsNotNone(link.get('rel'))
        self.assertIsNotNone(link.get('type'))
        self.assertIsNotNone(link.get('href'))

    def assertValidTenant(self, tenant):
        """Applicable to XML and JSON."""
        self.assertIsNotNone(tenant.get('id'))
        self.assertIsNotNone(tenant.get('name'))

    def assertValidUser(self, user):
        """Applicable to XML and JSON."""
        self.assertIsNotNone(user.get('id'))
        self.assertIsNotNone(user.get('name'))

    def assertValidRole(self, tenant):
        """Applicable to XML and JSON."""
        self.assertIsNotNone(tenant.get('id'))
        self.assertIsNotNone(tenant.get('name'))

    def test_public_not_found(self):
        r = self.public_request(
            path='/%s' % uuid.uuid4().hex,
            expected_status=404)
        self.assertValidErrorResponse(r)

    def test_admin_not_found(self):
        r = self.admin_request(
            path='/%s' % uuid.uuid4().hex,
            expected_status=404)
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
        self.assertValidExtensionListResponse(r,
                                              extension.PUBLIC_EXTENSIONS)

    def test_admin_extensions(self):
        r = self.admin_request(path='/v2.0/extensions')
        self.assertValidExtensionListResponse(r,
                                              extension.ADMIN_EXTENSIONS)

    def test_admin_extensions_404(self):
        self.admin_request(path='/v2.0/extensions/invalid-extension',
                           expected_status=404)

    def test_public_osksadm_extension_404(self):
        self.public_request(path='/v2.0/extensions/OS-KSADM',
                            expected_status=404)

    def test_admin_osksadm_extension(self):
        r = self.admin_request(path='/v2.0/extensions/OS-KSADM')
        self.assertValidExtensionResponse(r,
                                          extension.ADMIN_EXTENSIONS)

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

    def test_validate_token_service_role(self):
        self.metadata_foobar = self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_service['id'],
            self.role_service['id'])

        token = self.get_scoped_token(tenant_id='service')
        r = self.admin_request(
            path='/v2.0/tokens/%s' % token,
            token=token)
        self.assertValidAuthenticationResponse(r)

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
            expected_status=204)

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

    def test_get_user_roles(self):
        raise nose.exc.SkipTest('Blocked by bug 933565')

        token = self.get_scoped_token()
        r = self.admin_request(
            path='/v2.0/users/%(user_id)s/roles' % {
                'user_id': self.user_foo['id'],
            },
            token=token)
        self.assertValidRoleListResponse(r)

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
        # Enforce usage of boolean for 'enabled' field in JSON and XML
        token = self.get_scoped_token()

        # Test CREATE request
        r = self.admin_request(
            method='POST',
            path='/v2.0/users',
            body={
                'user': {
                    'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex,
                    # In XML, only "true|false" are converted to boolean.
                    'enabled': "False",
                },
            },
            token=token,
            expected_status=400)
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
            expected_status=400)
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
                    # In XML, only "true|false" are converted to boolean.
                    'enabled': "False",
                },
            },
            token=token,
            expected_status=400)
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
            expected_status=400)
        self.assertValidErrorResponse(r)

    def test_error_response(self):
        """This triggers assertValidErrorResponse by convention."""
        self.public_request(path='/v2.0/tenants', expected_status=401)

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
                                 expected_status=400)
        self.assertValidErrorResponse(res)
        res = self.admin_request(method='POST',
                                 path='/v2.0/users',
                                 body=bad_body,
                                 token=token,
                                 expected_status=400)
        self.assertValidErrorResponse(res)


class JsonTestCase(RestfulTestCase, CoreApiTests):
    content_type = 'json'

    def _get_token_id(self, r):
        """Applicable only to JSON."""
        return r.result['access']['token']['id']

    def assertValidErrorResponse(self, r):
        self.assertIsNotNone(r.result.get('error'))
        self.assertValidError(r.result['error'])
        self.assertEqual(r.result['error']['code'], r.status_code)

    def assertValidExtension(self, extension, expected):
        super(JsonTestCase, self).assertValidExtension(extension)
        descriptions = [ext['description'] for ext in expected.itervalues()]
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
            self.assertTrue(isinstance(serviceCatalog, list))
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
        super(JsonTestCase, self).assertValidVersion(version)

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

    def test_service_crud_requires_auth(self):
        """Service CRUD should 401 without an X-Auth-Token (bug 1006822)."""
        # values here don't matter because we should 401 before they're checked
        service_path = '/v2.0/OS-KSADM/services/%s' % uuid.uuid4().hex
        service_body = {
            'OS-KSADM:service': {
                'name': uuid.uuid4().hex,
                'type': uuid.uuid4().hex,
            },
        }

        r = self.admin_request(method='GET',
                               path='/v2.0/OS-KSADM/services',
                               expected_status=401)
        self.assertValidErrorResponse(r)

        r = self.admin_request(method='POST',
                               path='/v2.0/OS-KSADM/services',
                               body=service_body,
                               expected_status=401)
        self.assertValidErrorResponse(r)

        r = self.admin_request(method='GET',
                               path=service_path,
                               expected_status=401)
        self.assertValidErrorResponse(r)

        r = self.admin_request(method='DELETE',
                               path=service_path,
                               expected_status=401)
        self.assertValidErrorResponse(r)

    def test_user_role_list_requires_auth(self):
        """User role list should 401 without an X-Auth-Token (bug 1006815)."""
        # values here don't matter because we should 401 before they're checked
        path = '/v2.0/tenants/%(tenant_id)s/users/%(user_id)s/roles' % {
            'tenant_id': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
        }

        r = self.admin_request(path=path, expected_status=401)
        self.assertValidErrorResponse(r)

    def test_fetch_revocation_list_nonadmin_fails(self):
        self.admin_request(
            method='GET',
            path='/v2.0/tokens/revoked',
            expected_status=401)

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

    def test_create_update_user_json_invalid_enabled_type(self):
        # Enforce usage of boolean for 'enabled' field in JSON
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
            expected_status=400)
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
            expected_status=400)
        self.assertValidErrorResponse(r)


class XmlTestCase(RestfulTestCase, CoreApiTests):
    xmlns = 'http://docs.openstack.org/identity/api/v2.0'
    content_type = 'xml'

    def _get_token_id(self, r):
        return r.result.find(self._tag('token')).get('id')

    def _tag(self, tag_name, xmlns=None):
        """Helper method to build an namespaced element name."""
        return '{%(ns)s}%(tag)s' % {'ns': xmlns or self.xmlns, 'tag': tag_name}

    def assertValidErrorResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('error'))

        self.assertValidError(xml)
        self.assertEqual(xml.get('code'), str(r.status_code))

    def assertValidExtension(self, extension, expected):
        super(XmlTestCase, self).assertValidExtension(extension)

        self.assertIsNotNone(extension.find(self._tag('description')))
        self.assertTrue(extension.find(self._tag('description')).text)
        links = extension.find(self._tag('links'))
        self.assertNotEmpty(links.findall(self._tag('link')))
        descriptions = [ext['description'] for ext in expected.itervalues()]
        description = extension.find(self._tag('description')).text
        self.assertIn(description, descriptions)
        for link in links.findall(self._tag('link')):
            self.assertValidExtensionLink(link)

    def assertValidExtensionListResponse(self, r, expected):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('extensions'))
        self.assertNotEmpty(xml.findall(self._tag('extension')))
        for ext in xml.findall(self._tag('extension')):
            self.assertValidExtension(ext, expected)

    def assertValidExtensionResponse(self, r, expected):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('extension'))

        self.assertValidExtension(xml, expected)

    def assertValidVersion(self, version):
        super(XmlTestCase, self).assertValidVersion(version)

        links = version.find(self._tag('links'))
        self.assertIsNotNone(links)
        self.assertNotEmpty(links.findall(self._tag('link')))
        for link in links.findall(self._tag('link')):
            self.assertIsNotNone(link.get('rel'))
            self.assertIsNotNone(link.get('href'))

        media_types = version.find(self._tag('media-types'))
        self.assertIsNotNone(media_types)
        self.assertNotEmpty(media_types.findall(self._tag('media-type')))
        for media in media_types.findall(self._tag('media-type')):
            self.assertIsNotNone(media.get('base'))
            self.assertIsNotNone(media.get('type'))

    def assertValidMultipleChoiceResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('versions'))

        self.assertNotEmpty(xml.findall(self._tag('version')))
        for version in xml.findall(self._tag('version')):
            self.assertValidVersion(version)

    def assertValidVersionResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('version'))

        self.assertValidVersion(xml)

    def assertValidEndpointListResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('endpoints'))

        self.assertNotEmpty(xml.findall(self._tag('endpoint')))
        for endpoint in xml.findall(self._tag('endpoint')):
            self.assertIsNotNone(endpoint.get('id'))
            self.assertIsNotNone(endpoint.get('name'))
            self.assertIsNotNone(endpoint.get('type'))
            self.assertIsNotNone(endpoint.get('publicURL'))
            self.assertIsNotNone(endpoint.get('internalURL'))
            self.assertIsNotNone(endpoint.get('adminURL'))

    def assertValidTenantResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('tenant'))

        self.assertValidTenant(xml)

    def assertValidUserResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('user'))

        self.assertValidUser(xml)

    def assertValidRoleListResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('roles'))

        self.assertNotEmpty(r.result.findall(self._tag('role')))
        for role in r.result.findall(self._tag('role')):
            self.assertValidRole(role)

    def assertValidAuthenticationResponse(self, r,
                                          require_service_catalog=False):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('access'))

        # validate token
        token = xml.find(self._tag('token'))
        self.assertIsNotNone(token)
        self.assertIsNotNone(token.get('id'))
        self.assertIsNotNone(token.get('expires'))
        tenant = token.find(self._tag('tenant'))
        if tenant is not None:
            # validate tenant
            self.assertValidTenant(tenant)
            self.assertIn(tenant.get('enabled'), ['true', 'false'])

        user = xml.find(self._tag('user'))
        self.assertIsNotNone(user)
        self.assertIsNotNone(user.get('id'))
        self.assertIsNotNone(user.get('name'))

        if require_service_catalog:
            # roles are only provided with a service catalog
            roles = user.findall(self._tag('role'))
            self.assertNotEmpty(roles)
            for role in roles:
                self.assertIsNotNone(role.get('name'))

        serviceCatalog = xml.find(self._tag('serviceCatalog'))
        # validate the serviceCatalog
        if require_service_catalog:
            self.assertIsNotNone(serviceCatalog)
        if serviceCatalog is not None:
            services = serviceCatalog.findall(self._tag('service'))
            if require_service_catalog:
                self.assertNotEmpty(services)
            for service in services:
                # validate service
                self.assertIsNotNone(service.get('name'))
                self.assertIsNotNone(service.get('type'))

                # services contain at least one endpoint
                endpoints = service.findall(self._tag('endpoint'))
                self.assertNotEmpty(endpoints)
                for endpoint in endpoints:
                    # validate service endpoint
                    self.assertIsNotNone(endpoint.get('publicURL'))

    def assertValidTenantListResponse(self, r):
        xml = r.result
        self.assertEqual(xml.tag, self._tag('tenants'))

        self.assertNotEmpty(r.result)
        for tenant in r.result.findall(self._tag('tenant')):
            self.assertValidTenant(tenant)
            self.assertIn(tenant.get('enabled'), ['true', 'false'])

    def test_authenticate_with_invalid_xml_in_password(self):
        # public_request would auto escape the ampersand
        self.public_request(
            method='POST',
            path='/v2.0/tokens',
            headers={
                'Content-Type': 'application/xml'
            },
            body="""
                <?xml version="1.0" encoding="UTF-8"?>
                <auth xmlns="http://docs.openstack.org/identity/api/v2.0"
                        tenantId="bar">
                     <passwordCredentials username="FOO" password="&"/>
                </auth>
            """,
            expected_status=400,
            convert=False)

    def test_add_tenant_xml(self):
        """Create a tenant without providing description field."""
        token = self.get_scoped_token()
        r = self.admin_request(
            method='POST',
            path='/v2.0/tenants',
            headers={
                'Content-Type': 'application/xml',
                'X-Auth-Token': token
            },
            body="""
                <?xml version="1.0" encoding="UTF-8"?>
                <tenant xmlns="http://docs.openstack.org/identity/api/v2.0"
                enabled="true" name="ACME Corp">
                <description></description>
                </tenant>
            """,
            convert=False)
        self._from_content_type(r, 'json')
        self.assertIsNotNone(r.result.get('tenant'))
        self.assertValidTenant(r.result['tenant'])
        self.assertEqual(r.result['tenant'].get('description'), "")

    def test_add_tenant_json(self):
        """Create a tenant without providing description field."""
        token = self.get_scoped_token()
        r = self.admin_request(
            method='POST',
            path='/v2.0/tenants',
            headers={
                'Content-Type': 'application/json',
                'X-Auth-Token': token
            },
            body="""
                {"tenant":{
                    "name":"test1",
                    "description":"",
                    "enabled":true}
                }
            """,
            convert=False)
        self._from_content_type(r, 'json')
        self.assertIsNotNone(r.result.get('tenant'))
        self.assertValidTenant(r.result['tenant'])
        self.assertEqual(r.result['tenant'].get('description'), "")

    def test_create_project_invalid_enabled_type_string(self):
        # Forbidden usage of string for 'enabled' field in JSON and XML
        token = self.get_scoped_token()

        r = self.admin_request(
            method='POST',
            path='/v2.0/tenants',
            body={
                'tenant': {
                    'name': uuid.uuid4().hex,
                    # In XML, only "true|false" are converted to boolean.
                    'enabled': "False",
                },
            },
            token=token,
            expected_status=400)
        self.assertValidErrorResponse(r)

    def test_update_project_invalid_enabled_type_string(self):
        # Forbidden usage of string for 'enabled' field in JSON and XML
        token = self.get_scoped_token()

        path = '/v2.0/tenants/%(tenant_id)s' % {
               'tenant_id': self.tenant_bar['id'],
        }

        r = self.admin_request(
            method='PUT',
            path=path,
            body={
                'tenant': {
                    # In XML, only "true|false" are converted to boolean.
                    'enabled': "False",
                },
            },
            token=token,
            expected_status=400)
        self.assertValidErrorResponse(r)
