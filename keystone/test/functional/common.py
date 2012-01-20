import datetime
import httplib
import json
import logging
import os
import random
import unittest2 as unittest
import uuid
from webob import Request, Response
from xml.etree import ElementTree

from keystone import server
import keystone.backends.api as db_api
from keystone.test import client as client_tests
from keystone import utils

logger = logging.getLogger(__name__)


def isSsl():
    """ See if we are testing with SSL.  If cert is non-empty, we are! """
    if 'cert_file' in os.environ:
        return os.environ['cert_file']
    return None


class HttpTestCase(unittest.TestCase):
    """Performs generic HTTP request testing.

    Defines a ``request`` method for use in test cases that makes
    HTTP requests, and two new asserts:

    * assertResponseSuccessful
    * assertResponseStatus
    """

    def request(self, host='127.0.0.1', protocol='http', port=80, method='GET',
                path='/', headers=None, body=None, assert_status=None):
        """Perform request and fetch httplib.HTTPResponse from the server"""

        # Initialize headers dictionary
        headers = {} if not headers else headers

        logger.debug("Connecting to %s://%s:%s", protocol, host, port)
        if protocol == 'https':
            cert_file = isSsl()
            connection = httplib.HTTPSConnection(host, port,
                                            cert_file=cert_file,
                                            timeout=20)
        else:
            connection = httplib.HTTPConnection(host, port, timeout=20)

        # Perform the request
        connection.request(method, path, body, headers)

        # Retrieve the response so can go ahead and close the connection
        response = connection.getresponse()
        logger.debug("%s %s returned %s", method, path, response.status)

        response.body = response.read()
        if response.status != httplib.OK:
            logger.debug("Response Body:")
            for line in response.body.split("\n"):
                logger.debug(line)

        # Close the connection
        connection.close()

        # Automatically assert HTTP status code
        if assert_status:
            self.assertResponseStatus(response, assert_status)
        else:
            self.assertResponseSuccessful(response)

        # Contains the response headers, body, etc
        return response

    def assertResponseSuccessful(self, response):
        """Asserts that a status code lies inside the 2xx range

        :param response: :py:class:`httplib.HTTPResponse` to be
          verified to have a status code between 200 and 299.

        example::

            >>> self.assertResponseSuccessful(response, 203)
        """
        self.assertTrue(response.status >= 200 and response.status <= 299,
            'Status code %d is outside of the expected range (2xx)\n\n%s' %
            (response.status, response.body))

    def assertResponseStatus(self, response, assert_status):
        """Asserts a specific status code on the response

        :param response: :py:class:`httplib.HTTPResponse`
        :param assert_status: The specific ``status`` result expected

        example::

            >>> self.assertResponseStatus(response, 203)
        """
        self.assertEqual(response.status, assert_status,
            'Status code %s is not %s, as expected)\n\n%s' %
            (response.status, assert_status, response.body))


class RestfulTestCase(HttpTestCase):
    """Performs restful HTTP request testing"""

    def restful_request(self, headers=None, as_json=None, as_xml=None,
        **kwargs):
        """Encodes and decodes (JSON & XML) HTTP requests and responses.

        Dynamically encodes json or xml as request body if one is provided.

        .. WARNING::

            * Existing Content-Type header will be overwritten.
            * If both as_json and as_xml are provided, as_xml is ignored.
            * If either as_json or as_xml AND a body is provided, the body
              is ignored.

        Dynamically returns 'as_json' or 'as_xml' attribute based on the
        detected response type, and fails the current test case if
        unsuccessful.

        response.as_json: standard python dictionary

        response.as_xml: as_etree.ElementTree
        """

        # Initialize headers dictionary
        headers = {} if not headers else headers

        # Attempt to encode JSON and XML automatically, if requested
        if as_json:
            body = RestfulTestCase._encode_json(as_json)
            headers['Content-Type'] = 'application/json'
        elif as_xml:
            body = as_xml
            headers['Content-Type'] = 'application/xml'

            # Assume the client wants xml back if it didn't specify
            if 'Accept' not in headers:
                headers['Accept'] = 'application/xml'
        elif 'body' in kwargs:
            body = kwargs.pop('body')
        else:
            body = None

        # Perform the HTTP request/response
        response = self.request(headers=headers, body=body, **kwargs)

        # Attempt to parse JSON and XML automatically, if detected
        response = self._decode_response_body(response)

        # Contains the decoded response as_json/as_xml, etc
        return response

    @staticmethod
    def _encode_json(data):
        """Returns a JSON-encoded string of the given python dictionary

        :param data: python object to be encoded into JSON
        :returns: string of JSON encoded data
        """
        return json.dumps(data)

    def _decode_response_body(self, response):
        """Detects response body type, and attempts to decode it

        :param response: :py:class:`httplib.HTTPResponse`
        :returns: response object with additions:

        If context type is application/json, the response will have an
        additional attribute ``json`` that will have the decoded JSON
        result (typically a dict)

        If context type is application/xml, the response will have an
        additional attribute ``xml`` that will have the an ElementTree
        result.
        """
        if response.body is not None and response.body.strip():
            if 'application/json' in response.getheader('Content-Type', ''):
                response.json = self._decode_json(response.body)
            elif 'application/xml' in response.getheader('Content-Type', ''):
                response.xml = self._decode_xml(response.body)
        return response

    @staticmethod
    def _decode_json(json_str):
        """Returns a dict of the given JSON string"""
        return json.loads(json_str)

    @staticmethod
    def _decode_xml(xml_str):
        """Returns an ElementTree of the given XML string"""
        return ElementTree.XML(xml_str)


class ApiTestCase(RestfulTestCase):
    """Abstracts REST verbs & resources of the service & admin API."""
    use_server = False

    admin_role_name = 'Admin'
    service_admin_role_name = 'KeystoneServiceAdmin'
    member_role_name = 'Member'

    # Same as KeystoneTest settings
    admin_username = 'admin'
    admin_password = 'secrete'

    service_token = None
    admin_token = None

    service_api = None
    admin_api = None

    """
    Dict of configuration options to pass to the API controller
    """
    options = {
        'backends': "keystone.backends.sqlalchemy",
        'keystone.backends.sqlalchemy': {
            # in-memory db
            'sql_connection': 'sqlite://',
            'verbose': False,
            'debug': False,
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
    # Populate the CONF module with these values
    utils.set_configuration(options)

    def fixture_create_role(self, **kwargs):
        """
        Creates a role fixture.

        :params \*\*kwargs: Attributes of the role to create
        """
        values = kwargs.copy()
        role = db_api.ROLE.create(values)
        logger.debug("Created role fixture %s (id=%s)", role.name, role.id)
        return role

    def fixture_create_token(self, **kwargs):
        """
        Creates a token fixture.

        :params \*\*kwargs: Attributes of the token to create
        """
        values = kwargs.copy()
        token = db_api.TOKEN.create(values)
        logger.debug("Created token fixture %s", token.id)
        return token

    def fixture_create_tenant(self, **kwargs):
        """
        Creates a tenant fixture.

        :params \*\*kwargs: Attributes of the tenant to create
        """
        values = kwargs.copy()
        tenant = db_api.TENANT.create(values)
        logger.debug("Created tenant fixture %s (id=%s)", tenant.name,
                     tenant.id)
        return tenant

    def fixture_create_user(self, **kwargs):
        """
        Creates a user fixture. If the user's tenant ID is set, and the tenant
        does not exist in the database, the tenant is created.

        :params \*\*kwargs: Attributes of the user to create
        """
        values = kwargs.copy()
        tenant_name = values.get('tenant_name')
        if tenant_name:
            if not db_api.TENANT.get_by_name(tenant_name):
                tenant = db_api.TENANT.create({'name': tenant_name,
                                      'enabled': True,
                                      'desc': tenant_name})
                values['tenant_id'] = tenant.id
        user = db_api.USER.create(values)
        logger.debug("Created user fixture %s (id=%s)", user.name, user.id)
        return user

    def fixture_create_service(self, service_name=None, service_type=None,
            service_description=None, **kwargs):
        """
        Creates a service fixture.

        :params \*\*kwargs: Additional attributes of the service to create
        """
        values = kwargs.copy()
        service_name = optional_str(service_name)
        if service_type is None:
            service_type = ['compute', 'identity', 'image-service',
                            'object-store', 'ext:extension-service'
                            ][random.randrange(5)]
        service_description = optional_str(service_description)
        values["name"] = service_name
        values["type"] = service_type
        values["description"] = service_description

        service = db_api.SERVICE.create(values)
        logger.debug("Created service fixture %s (id=%s)", service.name,
                     service.id)
        return service

    def setUp(self):
        super(ApiTestCase, self).setUp()
        if self.use_server:
            return

        self.service_api = server.ServiceApi()
        self.admin_api = server.AdminApi()

        # ADMIN ROLE
        self.admin_role = self.fixture_create_role(
            name=self.admin_role_name)

        # ADMIN
        password = unique_str()
        self.admin_user = self.fixture_create_user(
            name="admin-user-%s" % uuid.uuid4().hex, enabled=True,
            password=password)
        self.admin_user['password'] = password
        self.admin_password = password
        self.admin_username = self.admin_user['name']

        obj = {}
        obj['role_id'] = self.admin_role['id']
        obj['user_id'] = self.admin_user['id']
        obj['tenant_id'] = None
        result = db_api.USER.user_role_add(obj)
        logger.debug("Created grant fixture %s", result.id)

        # SERVICE ADMIN ROLE
        self.service_admin_role = self.fixture_create_role(
            name=self.service_admin_role_name)

        # MEMBER ROLE
        self.member_role = self.fixture_create_role(
            name='Member')

    def tearDown(self):
        super(ApiTestCase, self).tearDown()
        # Explicitly release these to limit memory use.
        self.service_api = self.admin_api = self.admin_role = None
        self.admin_user = self.admin_password = self.admin_username = None
        self.service_admin_role = self.member_role = None

    def request(self, host='127.0.0.1', protocol='http', port=80, method='GET',
                path='/', headers=None, body=None, assert_status=None,
                server=None):
        """Overrides HttpTestCase and uses local calls"""
        if self.use_server:
            # Call a real server (bypass the override)
            return super(ApiTestCase, self).request(host=host, port=port,
                                    protocol=protocol, method=method,
                                    path=path, headers=headers, body=body,
                                    assert_status=assert_status)

        req = Request.blank(path)
        req.method = method
        req.headers = headers
        if isinstance(body, unicode):
            req.body = body.encode('utf-8')
        else:
            req.body = body

        res = req.get_response(server)
        logger.debug("%s %s returned %s", req.method, req.path_qs,
                     res.status)
        if res.status_int != httplib.OK:
            logger.debug("Response Body:")
            for line in res.body.split("\n"):
                logger.debug(line)

        # Automatically assert HTTP status code
        if assert_status:
            self.assertEqual(res.status_int, assert_status,
                'Status code %s is not %s, as expected)\n\n%s' %
                (res.status_int, assert_status, res.body))
        else:
            self.assertTrue(299 >= res.status_int >= 200,
                'Status code %d is outside of the expected range (2xx)\n\n%s' %
                (res.status_int, res.body))

        # Contains the response headers, body, etc
        return res

    def _decode_response_body(self, response):
        """Override to support webob.Response.
        """
        if self.use_server:
            # Call a real server (bypass the override)
            return super(ApiTestCase, self)._decode_response_body(response)

        if response.body is not None and response.body.strip():
            if 'application/json' in response.content_type:
                response.json = self._decode_json(response.body)
            elif 'application/xml' in response.content_type:
                response.xml = self._decode_xml(response.body)
        return response

    def assertResponseSuccessful(self, response):
        """Asserts that a status code lies inside the 2xx range

        :param response: :py:class:`webob.Response` to be
          verified to have a status code between 200 and 299.

        example::

            >>> self.assertResponseSuccessful(response, 203)
        """
        if self.use_server:
            # Call a real server (bypass the override)
            return super(ApiTestCase, self).assertResponseSuccessful(response)

        self.assertTrue(response.status_int >= 200 and
                        response.status_int <= 299,
            'Status code %d is outside of the expected range (2xx)\n\n%s' %
            (response.status_int, response.body))

    def assertResponseStatus(self, response, assert_status):
        """Asserts a specific status code on the response

        :param response: :py:class:`webob.Response`
        :param assert_status: The specific ``status`` result expected

        example::

            >>> self.assertResponseStatus(response, 203)
        """
        if self.use_server:
            # Call a real server (bypass the override)
            return super(ApiTestCase, self).assertResponseStatus(response,
                                                                 assert_status)

        self.assertEqual(response.status_int, assert_status,
            'Status code %s is not %s, as expected)\n\n%s' %
            (response.status_int, assert_status, response.body))

    def service_request(self, version='2.0', path='', port=None, headers=None,
            host=None, protocol=None, **kwargs):
        """Returns a request to the service API"""

        # Initialize headers dictionary
        headers = {} if not headers else headers

        if self.use_server:
            path = ApiTestCase._version_path(version, path)
            if port is None:
                port = client_tests.TEST_TARGET_SERVER_SERVICE_PORT or 5000
            if host is None:
                host = (client_tests.TEST_TARGET_SERVER_SERVICE_ADDRESS
                            or '127.0.0.1')
            if protocol is None:
                protocol = (client_tests.TEST_TARGET_SERVER_SERVICE_PROTOCOL
                            or 'http')

        if 'use_token' in kwargs:
            headers['X-Auth-Token'] = kwargs.pop('use_token')
        elif self.service_token:
            headers['X-Auth-Token'] = self.service_token
        elif self.admin_token:
            headers['X-Auth-Token'] = self.admin_token

        return self.restful_request(host=host, protocol=protocol, port=port,
                path=path, headers=headers, server=self.service_api, **kwargs)

    def admin_request(self, version='2.0', path='', port=None, headers=None,
            host=None, protocol=None, **kwargs):
        """Returns a request to the admin API"""

        # Initialize headers dictionary
        headers = {} if not headers else headers

        if self.use_server:
            path = ApiTestCase._version_path(version, path)
            if port is None:
                port = client_tests.TEST_TARGET_SERVER_ADMIN_PORT or 35357
            if host is None:
                host = (client_tests.TEST_TARGET_SERVER_ADMIN_ADDRESS
                                or '127.0.0.1')
            if protocol is None:
                protocol = (client_tests.TEST_TARGET_SERVER_ADMIN_PROTOCOL
                                or 'http')

        if 'use_token' in kwargs:
            headers['X-Auth-Token'] = kwargs.pop('use_token')
        elif self.admin_token:
            headers['X-Auth-Token'] = self.admin_token

        return self.restful_request(host=host, protocol=protocol, port=port,
            path=path, headers=headers, server=self.admin_api, **kwargs)

    @staticmethod
    def _version_path(version, path):
        """Prepend the given path with the API version.

        An empty version results in no version being prepended."""
        if version:
            return '/v' + str(version) + str(path)
        else:
            return str(path)

    def post_token(self, **kwargs):
        """POST /tokens"""
        #Setting service call as the default behavior."""
        if 'request_type' in kwargs and \
            kwargs.pop('request_type') == 'admin':
            return self.admin_request(method='POST',
                path='/tokens', **kwargs)
        else:
            return self.service_request(method='POST',
                path='/tokens', **kwargs)

    def get_token(self, token_id, **kwargs):
        """GET /tokens/{token_id}"""
        return self.admin_request(method='GET',
            path='/tokens/%s' % (token_id,), **kwargs)

    def get_token_belongsto(self, token_id, tenant_id, **kwargs):
        """GET /tokens/{token_id}?belongsTo={tenant_id}"""
        return self.admin_request(method='GET',
            path='/tokens/%s?belongsTo=%s' % (token_id, tenant_id), **kwargs)

    def check_token(self, token_id, **kwargs):
        """HEAD /tokens/{token_id}"""
        return self.admin_request(method='HEAD',
            path='/tokens/%s' % (token_id,), **kwargs)

    def check_token_belongs_to(self, token_id, tenant_id, **kwargs):
        """HEAD /tokens/{token_id}?belongsTo={tenant_id}"""
        return self.admin_request(method='HEAD',
            path='/tokens/%s?belongsTo=%s' % (token_id, tenant_id), **kwargs)

    def delete_token(self, token_id, **kwargs):
        """DELETE /tokens/{token_id}"""
        return self.admin_request(method='DELETE',
            path='/tokens/%s' % (token_id,), **kwargs)

    def post_tenant(self, **kwargs):
        """POST /tenants"""
        return self.admin_request(method='POST', path='/tenants', **kwargs)

    def get_tenants(self, **kwargs):
        """GET /tenants"""
        if 'request_type' in kwargs and \
            kwargs.pop('request_type') == 'service':
            return self.service_request(method='GET',
                path='/tenants', **kwargs)
        else:
            return self.admin_request(method='GET', path='/tenants', **kwargs)

    def get_tenant(self, tenant_id, **kwargs):
        """GET /tenants/{tenant_id}"""
        return self.admin_request(method='GET',
            path='/tenants/%s' % (tenant_id,), **kwargs)

    def get_tenant_by_name(self, tenant_name, **kwargs):
        """GET /tenants?name=tenant_name"""
        return self.admin_request(method='GET',
            path='/tenants?name=%s' % (tenant_name,), **kwargs)

    def post_tenant_for_update(self, tenant_id, **kwargs):
        """GET /tenants/{tenant_id}"""
        return self.admin_request(method='POST',
            path='/tenants/%s' % (tenant_id,), **kwargs)

    def get_tenant_users(self, tenant_id, **kwargs):
        """GET /tenants/{tenant_id}/users"""
        return self.admin_request(method='GET',
            path='/tenants/%s/users' % (tenant_id,), **kwargs)

    def get_tenant_users_by_role(self, tenant_id, role_id, **kwargs):
        """GET /tenants/{tenant_id}/users?roleId={roleId}"""
        return self.admin_request(method='GET',
            path='/tenants/%s/users?roleId=%s' % (\
                tenant_id, role_id), **kwargs)

    def delete_tenant(self, tenant_id, **kwargs):
        """DELETE /tenants/{tenant_id}"""
        return self.admin_request(method='DELETE',
            path='/tenants/%s' % (tenant_id,), **kwargs)

    def post_user(self, **kwargs):
        """POST /users"""
        return self.admin_request(method='POST', path='/users', **kwargs)

    def get_users(self, **kwargs):
        """GET /users"""
        return self.admin_request(method='GET', path='/users', **kwargs)

    def get_user(self, user_id, **kwargs):
        """GET /users/{user_id}"""
        return self.admin_request(method='GET',
            path='/users/%s' % (user_id,), **kwargs)

    def query_user(self, user_name, **kwargs):
        """GET /users?name={user_name}"""
        return self.admin_request(method='GET',
            path='/users?name=%s' % (user_name,), **kwargs)

    def post_user_for_update(self, user_id, **kwargs):
        """POST /users/{user_id}"""
        return self.admin_request(method='POST',
            path='/users/%s' % (user_id,), **kwargs)

    def put_user_password(self, user_id, **kwargs):
        """PUT /users/{user_id}/OS-KSADM/password"""
        return self.admin_request(method='PUT',
            path='/users/%s/OS-KSADM/password' % (user_id,), **kwargs)

    def put_user_tenant(self, user_id, **kwargs):
        """PUT /users/{user_id}/OS-KSADM/tenant"""
        return self.admin_request(method='PUT',
            path='/users/%s/OS-KSADM/tenant' % (user_id,), **kwargs)

    def put_user_enabled(self, user_id, **kwargs):
        """PUT /users/{user_id}/OS-KSADM/enabled"""
        return self.admin_request(method='PUT',
            path='/users/%s/OS-KSADM/enabled' % (user_id,), **kwargs)

    def delete_user(self, user_id, **kwargs):
        """DELETE /users/{user_id}"""
        return self.admin_request(method='DELETE',
            path='/users/%s' % (user_id,), **kwargs)

    def get_user_roles(self, user_id, **kwargs):
        """GET /users/{user_id}/roles"""
        return self.admin_request(method='GET',
            path='/users/%s/roles' % (user_id,), **kwargs)

    def put_user_role(self, user_id, role_id, tenant_id, **kwargs):
        if tenant_id is None:
            # PUT /users/{user_id}/roles/OS-KSADM/{role_id}
            return self.admin_request(method='PUT',
                path='/users/%s/roles/OS-KSADM/%s' %
                (user_id, role_id), **kwargs)
        else:
            # PUT /tenants/{tenant_id}/users/{user_id}/
            # roles/OS-KSADM/{role_id}
            return self.admin_request(method='PUT',
                path='/tenants/%s/users/%s/roles/OS-KSADM/%s' % (tenant_id,
                    user_id, role_id,), **kwargs)

    def delete_user_role(self, user_id, role_id, tenant_id, **kwargs):
        """DELETE /users/{user_id}/roles/{role_id}"""
        if tenant_id is None:
            return self.admin_request(method='DELETE',
                path='/users/%s/roles/OS-KSADM/%s'
                % (user_id, role_id), **kwargs)
        else:
            return self.admin_request(method='DELETE',
                path='/tenants/%s/users/%s/roles/OS-KSADM/%s' %
                    (tenant_id, user_id, role_id), **kwargs)

    def post_role(self, **kwargs):
        """POST /roles"""
        return self.admin_request(method='POST',
            path='/OS-KSADM/roles', **kwargs)

    def get_roles(self, **kwargs):
        """GET /OS-KSADM/roles"""
        return self.admin_request(method='GET',
            path='/OS-KSADM/roles', **kwargs)

    def get_roles_by_service(self, service_id, **kwargs):
        """GET /OS-KSADM/roles"""
        return self.admin_request(method='GET', path=(
            '/OS-KSADM/roles?serviceId=%s')
            % (service_id),
            **kwargs)

    def get_role(self, role_id, **kwargs):
        """GET /roles/{role_id}"""
        return self.admin_request(method='GET',
            path='/OS-KSADM/roles/%s' % (role_id,), **kwargs)

    def get_role_by_name(self, role_name, **kwargs):
        """GET /roles?name={role_name}"""
        return self.admin_request(method='GET',
            path='/OS-KSADM/roles?name=%s' % (role_name,), **kwargs)

    def delete_role(self, role_id, **kwargs):
        """DELETE /roles/{role_id}"""
        return self.admin_request(method='DELETE',
            path='/OS-KSADM/roles/%s' % (role_id,), **kwargs)

    def get_endpoint_templates(self, **kwargs):
        """GET /OS-KSCATALOG/endpointTemplates"""
        return self.admin_request(method='GET',
            path='/OS-KSCATALOG/endpointTemplates',
            **kwargs)

    def get_endpoint_templates_by_service(self, service_id, **kwargs):
        """GET /OS-KSCATALOG/endpointTemplates"""
        return self.admin_request(method='GET', path=(
            '/OS-KSCATALOG/endpointTemplates?serviceId=%s')
            % (service_id),
            **kwargs)

    def post_endpoint_template(self, **kwargs):
        """POST /OS-KSCATALOG/endpointTemplates"""
        return self.admin_request(method='POST',
            path='/OS-KSCATALOG/endpointTemplates',
            **kwargs)

    def put_endpoint_template(self, endpoint_template_id, **kwargs):
        """PUT /OS-KSCATALOG/endpointTemplates/{endpoint_template_id}"""
        return self.admin_request(method='PUT',
            path='/OS-KSCATALOG/endpointTemplates/%s'
            % (endpoint_template_id,),
            **kwargs)

    def get_endpoint_template(self, endpoint_template_id, **kwargs):
        """GET /OS-KSCATALOG/endpointTemplates/{endpoint_template_id}"""
        return self.admin_request(method='GET',
            path='/OS-KSCATALOG/endpointTemplates/%s'
            % (endpoint_template_id,),
            **kwargs)

    def delete_endpoint_template(self, endpoint_template_id, **kwargs):
        """DELETE /OS-KSCATALOG/endpointTemplates/{endpoint_template_id}"""
        return self.admin_request(method='DELETE',
            path='/OS-KSCATALOG/endpointTemplates/%s' %
            (endpoint_template_id,),
            **kwargs)

    def get_tenant_endpoints(self, tenant_id, **kwargs):
        """GET /tenants/{tenant_id}/OS-KSCATALOG/endpoints"""
        return self.admin_request(method='GET',
            path='/tenants/%s/OS-KSCATALOG/endpoints' %
            (tenant_id,),
            **kwargs)

    def post_tenant_endpoint(self, tenant_id, **kwargs):
        """POST /tenants/{tenant_id}/OS-KSCATALOG/endpoints"""
        return self.admin_request(method='POST',
            path='/tenants/%s/OS-KSCATALOG/endpoints' %
            (tenant_id,), **kwargs)

    def delete_tenant_endpoint(self, tenant_id, endpoint_id, **kwargs):
        """DELETE /tenants/{tenant_id}/OS-KSCATALOG/endpoints/{endpoint_id}"""
        return self.admin_request(method='DELETE',
            path='/tenants/%s/OS-KSCATALOG/endpoints/%s' %
            (tenant_id, endpoint_id,),
            **kwargs)

    def get_token_endpoints(self, token_id, **kwargs):
        """GET /tokens/{token_id}/endpoints"""
        return self.admin_request(method='GET',
            path='/tokens/%s/endpoints' %
            (token_id,),
            **kwargs)

    def post_service(self, **kwargs):
        """POST /services"""
        return self.admin_request(method='POST',
            path='/OS-KSADM/services', **kwargs)

    def get_services(self, **kwargs):
        """GET /services"""
        return self.admin_request(method='GET',
            path='/OS-KSADM/services', **kwargs)

    def get_service(self, service_id, **kwargs):
        """GET /services/{service_id}"""
        return self.admin_request(method='GET',
            path='/OS-KSADM/services/%s' % (service_id,), **kwargs)

    def get_service_by_name(self, service_name, **kwargs):
        """GET /services?name={service_name}"""
        return self.admin_request(method='GET',
            path='/OS-KSADM/services?name=%s' % (service_name,), **kwargs)

    def delete_service(self, service_id, **kwargs):
        """DELETE /services/{service_id}"""
        return self.admin_request(method='DELETE',
            path='/OS-KSADM/services/%s' % (service_id,), **kwargs)

    def get_root(self, **kwargs):
        """GET /"""
        return self.service_request(method='GET', path='/', **kwargs)

    def get_extensions(self, **kwargs):
        """GET /extensions"""
        return self.service_request(method='GET', path='/extensions', **kwargs)

    def get_admin_guide(self, **kwargs):
        """GET /identityadminguide.pdf"""
        return self.service_request(method='GET',
            path='/identityadminguide.pdf', **kwargs)

    def get_admin_wadl(self, **kwargs):
        """GET /identity-admin.wadl"""
        return self.service_request(method='GET', path='/identity-admin.wadl',
            **kwargs)

    def get_common_ent(self, **kwargs):
        """GET /common.ent"""
        return self.service_request(method='GET', path='/common.ent',
            **kwargs)

    def get_xsd(self, filename, **kwargs):
        """GET /xsd/{xsd}"""
        return self.service_request(method='GET', path='/xsd/%s' % (filename,),
            **kwargs)

    def get_xsd_atom(self, filename, **kwargs):
        """GET /xsd/atom/{xsd}"""
        return self.service_request(method='GET',
            path='/xsd/atom/%s' % (filename,), **kwargs)

    def get_xslt(self, filename, **kwargs):
        """GET /xslt/{file:.*}"""
        return self.service_request(method='GET',
            path='/xslt/%s' % (filename,), **kwargs)

    def get_javascript(self, filename, **kwargs):
        """GET /js/{file:.*}"""
        return self.service_request(method='GET', path='/js/%s' % (filename,),
            **kwargs)

    def get_style(self, filename, **kwargs):
        """GET /style/{file:.*}"""
        return self.service_request(method='GET',
            path='/style/%s' % (filename,), **kwargs)

    def get_sample(self, filename, **kwargs):
        """GET /samples/{file:.*}"""
        return self.service_request(method='GET',
            path='/samples/%s' % (filename,), **kwargs)

    def get_user_credentials(self, user_id, **kwargs):
        """GET /users/{user_id}/OS-KSADM/credentials"""
        return self.admin_request(method='GET',
            path='/users/%s/OS-KSADM/credentials' % (user_id,), **kwargs)

    def get_user_credentials_by_type(self,
        user_id, credentials_type, **kwargs):
        """GET /users/{user_id}/OS-KSADM/credentials/{credentials_type}"""
        return self.admin_request(method='GET',
            path='/users/%s/OS-KSADM/credentials/%s'\
            % (user_id, credentials_type,), **kwargs)

    def post_credentials(self, user_id, **kwargs):
        """POST /users/{user_id}/OS-KSADM/credentials"""
        return self.admin_request(method='POST',
            path='/users/%s/OS-KSADM/credentials' % (user_id,), **kwargs)

    def post_credentials_by_type(self, user_id, credentials_type, **kwargs):
        """POST /users/{user_id}/OS-KSADM/credentials/{credentials_type}"""
        return self.admin_request(method='POST',
            path='/users/%s/OS-KSADM/credentials/%s' %\
            (user_id, credentials_type), **kwargs)

    def delete_user_credentials_by_type(self, user_id,
        credentials_type, **kwargs):
        """DELETE /users/{user_id}/OS-KSADM/credentials/{credentials_type}"""
        return self.admin_request(method='DELETE',
            path='/users/%s/OS-KSADM/credentials/%s' %\
            (user_id, credentials_type,), **kwargs)


def unique_str():
    """Generates and return a unique string"""
    return str(uuid.uuid4())


def unique_email():
    """Generates and return a unique email"""
    return "%s@openstack.org" % unique_str()


def unique_url():
    """Generates and return a unique email"""
    return "http://%s" % unique_str()


def optional_str(val):
    """Automatically populates optional string fields"""
    return val if val is not None else unique_str()


def optional_email(val):
    """Automatically populates optional email fields"""
    return val if val is not None else unique_email()


def optional_url(val):
    """Automatically populates optional url fields"""
    return val if val is not None else unique_url()


class FunctionalTestCase(ApiTestCase):
    """Abstracts functional CRUD of the identity API"""
    admin_user_id = None

    admin_token = None
    service_token = None
    expired_admin_token = None
    disabled_admin_token = None
    service_admin_token = None

    user = None
    user_token = None
    service_user = None

    tenant = None
    tenant_user = None  # user with default tenant
    tenant_user_token = None

    disabled_tenant = None
    disabled_user = None

    xmlns = 'http://docs.openstack.org/identity/api/v2.0'
    xmlns_ksadm = 'http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0'
    xmlns_kscatalog = "http://docs.openstack.org/identity/api/ext"\
        + "/OS-KSCATALOG/v1.0"

    def setUp(self):
        """Prepare keystone for system tests"""
        super(FunctionalTestCase, self).setUp()

        # Authenticate as admin user to establish admin_token
        access = self.authenticate(self.admin_username, self.admin_password).\
            json['access']

        self.admin_token = access['token']['id']
        self.admin_user_id = access['user']['id']

    def fixture_create_service_admin(self):
        if self.service_user:
            return
        # SERVICE ADMIN
        password = unique_str()
        self.service_user = self.fixture_create_user(
            name="service-user-%s" % uuid.uuid4().hex, enabled=True,
            password=password)
        self.service_user['password'] = password

        self.service_admin_role = self.fetch_role_by_name(
                        self.service_admin_role_name,
                        assert_status=200).json['role']
        self.grant_global_role_to_user(self.service_user['id'],
                                self.service_admin_role['id'],
                                assert_status=201)

        self.service_user_token = self.authenticate(self.service_user['name'],
                                   self.service_user['password']).\
            json['access']['token']
        self.service_admin_token = self.service_user_token['id']

    def fixture_create_normal_tenant(self):
        if self.tenant:
            return
        # TENANT
        self.tenant = self.fixture_create_tenant(
            name="tenant-%s" % uuid.uuid4().hex, enabled=True)

    def fixture_create_disabled_tenant(self):
        if self.disabled_tenant:
            return
        # DISABLED TENANT
        self.disabled_tenant = self.fixture_create_tenant(
            name="disabled-tenant-%s" % uuid.uuid4().hex, enabled=False)

    def fixture_create_normal_user(self):
        if self.user:
            return
        # USER
        password = unique_str()
        self.user = self.fixture_create_user(
            name="user-%s" % uuid.uuid4().hex, enabled=True,
            password=password)
        self.user['password'] = password

        self.user_token = self.authenticate(self.user['name'],
                                   self.user['password']).\
            json['access']['token']

    def fixture_create_tenant_user(self):
        if self.tenant_user:
            return
        self.fixture_create_tenant()
        # USER with DEFAULT TENANT
        password = unique_str()
        self.tenant_user = self.fixture_create_user(
            name="user_in_tenant-%s" % uuid.uuid4().hex, enabled=True,
            tenant_id=self.tenant.id, password=password)
        self.tenant_user['password'] = password

        self.tenant_user_token = self.authenticate(self.tenant_user['name'],
                                   self.tenant_user['password'],
                                   self.tenant.id).\
            json['access']['token']

    def fixture_create_disabled_user_and_token(self):
        if self.disabled_user:
            return
        self.fixture_create_normal_tenant()
        # DISABLED USER
        self.disabled_user = self.fixture_create_user(
            name="disabled_user-%s" % uuid.uuid4().hex, enabled=False)

        # TOKEN for DISABLED user
        token = self.fixture_create_token(
                    id="disabled-user-tenant-token-%s" % uuid.uuid4().hex,
                    user_id=self.disabled_user.id,
                    tenant_id=self.tenant.id,
                    expires=datetime.datetime.now() + datetime.timedelta(1))
        self.disabled_admin_token = token.id

    def fixture_create_expired_token(self):
        if self.expired_admin_token:
            return
        self.fixture_create_normal_tenant()
        # EXPIRED token (for enabled user)
        token = self.fixture_create_token(
                    id="expired-admin-token-%s" % uuid.uuid4().hex,
                    user_id=self.admin_user_id,
                    tenant_id=self.tenant.id,
                    expires=datetime.datetime.now() - datetime.timedelta(1))
        self.expired_admin_token = token.id

    def authenticate(self, user_name=None, user_password=None, tenant_id=None,
            **kwargs):
        user_name = optional_str(user_name)
        user_password = optional_str(user_password)

        data = {
            "auth": {
                "passwordCredentials": {
                "username": user_name,
                "password": user_password}}}
        if tenant_id:
            data["auth"]["tenantId"] = tenant_id

        return self.post_token(as_json=data, **kwargs)

    def authenticate_D5(self, user_name=None, user_password=None,
                        tenant_id=None, **kwargs):
        user_name = optional_str(user_name)
        user_password = optional_str(user_password)

        data = {"passwordCredentials": {
                "username": user_name,
                "password": user_password}}
        if tenant_id:
            data["passwordCredentials"]["tenantId"] = tenant_id

        return self.post_token(as_json=data, **kwargs)

    def authenticate_using_token(self, token, tenant_id=None,
            **kwargs):

        data = {
            "auth": {
                "token": {
                    "id": token}}}

        if tenant_id:
            data["auth"]["tenantId"] = tenant_id

        return self.post_token(as_json=data, **kwargs)

    def validate_token(self, token_id=None, tenant_id=None, **kwargs):
        token_id = optional_str(token_id)

        if tenant_id:
            # validate scoped token
            return self.get_token_belongsto(token_id, tenant_id, **kwargs)
        else:
            # validate unscoped token
            return self.get_token(token_id, **kwargs)

    def remove_token(self, token_id=None, **kwargs):
        token_id = optional_str(token_id)
        return self.delete_token(token_id, **kwargs)

    def create_tenant(self, tenant_name=None, tenant_description=None,
            tenant_enabled=True, **kwargs):
        """Creates a tenant for testing

        The tenant name and description are generated from UUIDs.
        """
        tenant_name = optional_str(tenant_name)
        tenant_description = optional_str(tenant_description)

        data = {
            "tenant": {
                "name": tenant_name,
                "description": tenant_description,
                "enabled": tenant_enabled}}

        return self.post_tenant(as_json=data, **kwargs)

    def list_tenants(self, **kwargs):
        return self.get_tenants(**kwargs)

    def fetch_tenant(self, tenant_id=None, **kwargs):
        tenant_id = optional_str(tenant_id)
        return self.get_tenant(tenant_id, **kwargs)

    def fetch_tenant_by_name(self, tenant_name=None, **kwargs):
        tenant_name = optional_str(tenant_name)
        if tenant_name:
            return self.get_tenant_by_name(tenant_name, **kwargs)

    def update_tenant(self, tenant_id=None, tenant_name=None,
            tenant_description=None, tenant_enabled=True, **kwargs):
        tenant_id = optional_str(tenant_id)
        tenant_description = optional_str(tenant_description)

        data = {"tenant": {}}

        if tenant_name is not None:
            data['tenant']['name'] = tenant_name

        data['tenant']['description'] = tenant_description

        if tenant_enabled is not None:
            data['tenant']['enabled'] = tenant_enabled

        return self.post_tenant_for_update(tenant_id, as_json=data, **kwargs)

    def list_tenant_users(self, tenant_id, role_id=None, **kwargs):
        tenant_id = optional_str(tenant_id)
        if role_id:
            return self.get_tenant_users_by_role(tenant_id, role_id, **kwargs)
        else:
            return self.get_tenant_users(tenant_id, **kwargs)

    def remove_tenant(self, tenant_id=None, **kwargs):
        tenant_id = optional_str(tenant_id)
        return self.delete_tenant(tenant_id, **kwargs)

    def create_user(self, user_name=None, user_password=None, user_email=None,
            tenant_id=None, user_enabled=True, **kwargs):
        """Creates a user for testing

        The user name is generated from UUIDs.
        """
        user_name = optional_str(user_name)
        user_password = optional_str(user_password)
        user_email = optional_email(user_email)

        data = {
            "user": {
                "password": user_password,
                "name": user_name,
                "tenantId": tenant_id,
                "email": user_email,
                "enabled": user_enabled}}

        return self.post_user(as_json=data, **kwargs)

    def create_user_with_known_password(self, **kwargs):
        """Manually injects the new user's password into the response data"""

        password = unique_str()
        r = self.create_user(user_password=password, **kwargs)
        r.json['user']['password'] = password
        return r

    def list_users(self, **kwargs):
        return self.get_users(**kwargs)

    def fetch_user(self, user_id=None, **kwargs):
        user_id = optional_str(user_id)
        return self.get_user(user_id, **kwargs)

    def fetch_user_by_name(self, user_name=None, **kwargs):
        user_name = optional_str(user_name)
        return self.query_user(user_name, **kwargs)

    def update_user(self, user_id=None, user_email=None, user_enabled=None,
            user_name=None, **kwargs):
        user_id = optional_str(user_id)

        data = {"user": {}}

        if user_email is not None:
            data['user']['email'] = user_email

        if user_enabled is not None:
            data['user']['enabled'] = user_enabled
        if user_name is not None:
            data['user']['name'] = user_name
        return self.post_user_for_update(user_id, as_json=data, **kwargs)

    def update_user_password(self, user_id=None, user_password=None, **kwargs):
        user_id = optional_str(user_id)
        user_password = optional_str(user_password)

        data = {"user": {"password": user_password}}
        return self.put_user_password(user_id, as_json=data, **kwargs)

    def update_user_tenant(self, user_id=None, tenant_id=None, **kwargs):
        user_id = optional_str(user_id)
        tenant_id = optional_str(tenant_id)

        data = {"user": {"tenantId": tenant_id}}
        return self.put_user_tenant(user_id, as_json=data, **kwargs)

    def _enable_disable_user(self, user_id, user_enabled, **kwargs):
        """Private function to enable and disable a user.

        Use enable_user() and disable_user() instead."""
        data = {"user": {"enabled": user_enabled}}

        return self.put_user_enabled(user_id, as_json=data, **kwargs)

    def enable_user(self, user_id=None, **kwargs):
        user_id = optional_str(user_id)
        return self._enable_disable_user(user_id, True, **kwargs)

    def disable_user(self, user_id=None, **kwargs):
        user_id = optional_str(user_id)
        return self._enable_disable_user(user_id, False, **kwargs)

    def remove_user(self, user_id=None, **kwargs):
        user_id = optional_str(user_id)
        return self.delete_user(user_id, **kwargs)

    def grant_role_to_user(self, user_id=None, role_id=None, tenant_id=None,
            **kwargs):
        user_id = optional_str(user_id)
        role_id = optional_str(role_id)
        tenant_id = optional_str(tenant_id)
        return self.put_user_role(user_id, role_id, tenant_id, **kwargs)

    def grant_global_role_to_user(self, user_id=None, role_id=None,
            **kwargs):
        user_id = optional_str(user_id)
        role_id = optional_str(role_id)
        return self.put_user_role(user_id, role_id, None, **kwargs)

    def revoke_global_role_from_user(self,
        user_id=None, role_id=None, **kwargs):
        user_id = optional_str(user_id)
        role_id = optional_str(role_id)
        return self.delete_user_role(user_id, role_id, **kwargs)

    def revoke_role_from_user(self,
        user_id=None, role_id=None, tenant_id=None, **kwargs):
        user_id = optional_str(user_id)
        role_id = optional_str(role_id)
        tenant_id = optional_str(tenant_id)
        return self.delete_user_role(user_id, tenant_id, **kwargs)

    def create_role(self, role_name=None, role_description=None,
            service_id=None, service_name=None, **kwargs):
        """Creates a role for testing

        The role name and description are generated from UUIDs.
        """
        if service_name and not role_name:
            role_name = "%s:%s" % (service_name, optional_str(role_name))
        else:
            role_name = optional_str(role_name)
        role_description = optional_str(role_description)

        data = {
            "role": {
                "name": role_name,
                "description": role_description}}

        if service_id is not None:
            data['role']['serviceId'] = service_id

        return self.post_role(as_json=data, **kwargs)

    def list_roles(self, service_id=None, **kwargs):
        if service_id is None:
            return self.get_roles(**kwargs)
        else:
            return self.get_roles_by_service(service_id, **kwargs)

    def fetch_role(self, role_id=None, **kwargs):
        role_id = optional_str(role_id)
        return self.get_role(role_id, **kwargs)

    def fetch_role_by_name(self, role_name=None, **kwargs):
        role_name = optional_str(role_name)
        return self.get_role_by_name(role_name, **kwargs)

    def remove_role(self, role_id=None, **kwargs):
        role_id = optional_str(role_id)
        return self.delete_role(role_id, **kwargs)

    def create_service(self, service_name=None, service_type=None,
            service_description=None, **kwargs):
        service_name = optional_str(service_name)
        if service_type is None:
            service_type = ['compute', 'identity', 'image-service',
                            'object-store', 'ext:extension-service'
                            ][random.randrange(5)]
        service_description = optional_str(service_description)
        data = {
            "OS-KSADM:service": {
                "name": service_name,
                "type": service_type,
                "description": service_description}}
        return self.post_service(as_json=data, **kwargs)

    def list_services(self, **kwargs):
        return self.get_services(**kwargs)

    def fetch_service(self, service_id=None, **kwargs):
        service_id = optional_str(service_id)
        return self.get_service(service_id, **kwargs)

    def fetch_service_by_name(self, service_name=None, **kwargs):
        service_name = optional_str(service_name)
        return self.get_service_by_name(service_name, **kwargs)

    def remove_service(self, service_id=None, **kwargs):
        service_id = optional_str(service_id)
        self.delete_service(service_id, **kwargs)

    def create_endpoint_for_tenant(self, tenant_id=None,
            endpoint_template_id=None, **kwargs):
        tenant_id = optional_str(tenant_id)
        endpoint_template_id = optional_str(endpoint_template_id)

        data = {"OS-KSCATALOG:endpointTemplate": {"id": endpoint_template_id}}

        return self.post_tenant_endpoint(tenant_id, as_json=data, **kwargs)

    def list_tenant_endpoints(self, tenant_id=None, **kwargs):
        tenant_id = optional_str(tenant_id)
        return self.get_tenant_endpoints(tenant_id, **kwargs)

    def remove_endpoint_from_tenant(self, tenant_id=None, endpoint_id=None,
            **kwargs):
        tenant_id = optional_str(tenant_id)
        endpoint_id = optional_str(endpoint_id)

        """TODO: Should this be an 'endpoint_id' or 'endpoint_template_id'??"""
        return self.delete_tenant_endpoint(tenant_id, endpoint_id, **kwargs)

    def remove_tenant_endpoint(self, tenant_id=None, endpoint_id=None,
            **kwargs):
        tenant_id = optional_str(tenant_id)
        endpoint_id = optional_str(endpoint_id)

        """TODO: Should this be an 'endpoint_id' or 'endpoint_template_id'??"""
        return self.delete_tenant_endpoint(tenant_id, endpoint_id, **kwargs)

    def list_endpoint_templates(self, service_id=None, **kwargs):
        if service_id is None:
            return self.get_endpoint_templates(**kwargs)
        else:
            return self.get_endpoint_templates_by_service(service_id, **kwargs)

    def create_endpoint_template(self, region=None, name=None, type=None,
            public_url=None, admin_url=None, internal_url=None, enabled=True,
            is_global=True, version_id=None,
            version_list=None, version_info=None, **kwargs):

        region = optional_str(region)
        name = optional_str(name)
        type = optional_str(type)
        public_url = optional_url(public_url)
        admin_url = optional_url(admin_url)
        internal_url = optional_url(internal_url)
        version_id = optional_str(version_id)[:20]
        version_list = optional_str(version_list)
        version_info = optional_str(version_info)

        data = {
            "OS-KSCATALOG:endpointTemplate": {
                "region": region,
                "name": name,
                "type": type,
                "publicURL": public_url,
                "adminURL": admin_url,
                "internalURL": internal_url,
                "enabled": enabled,
                "global": is_global,
                "versionId": version_id,
                "versionInfo": version_info,
                "versionList": version_list}}
        return self.post_endpoint_template(as_json=data, **kwargs)

    def remove_endpoint_template(self, endpoint_template_id=None, **kwargs):
        endpoint_template_id = optional_str(endpoint_template_id)
        return self.delete_endpoint_template(endpoint_template_id, **kwargs)

    def fetch_endpoint_template(self, endpoint_template_id, **kwargs):
        endpoint_template_id = optional_str(endpoint_template_id)
        return self.get_endpoint_template(endpoint_template_id, **kwargs)

    def update_endpoint_template(self, endpoint_template_id=None, region=None,
            name=None, type=None, public_url=None, admin_url=None,
            internal_url=None, enabled=None, is_global=None,
            version_id=None, version_list=None, version_info=None, **kwargs):

        data = {"OS-KSCATALOG:endpointTemplate": {}}

        if region is not None:
            data['OS-KSCATALOG:endpointTemplate']['region'] = region

        if name is not None:
            data['OS-KSCATALOG:endpointTemplate']['name'] = name

        if type is not None:
            data['OS-KSCATALOG:endpointTemplate']['type'] = type

        if public_url is not None:
            data['OS-KSCATALOG:endpointTemplate']['publicURL'] = public_url

        if admin_url is not None:
            data['OS-KSCATALOG:endpointTemplate']['adminURL'] = admin_url

        if internal_url is not None:
            data['OS-KSCATALOG:endpointTemplate']['internalURL'] = internal_url

        if enabled is not None:
            data['OS-KSCATALOG:endpointTemplate']['enabled'] = enabled

        if is_global is not None:
            data['OS-KSCATALOG:endpointTemplate']['global'] = is_global

        if version_id is not None:
            data['OS-KSCATALOG:endpointTemplate']['versionId'] = version_id

        if version_list is not None:
            data['OS-KSCATALOG:endpointTemplate']['versionList'] = version_list

        if version_info is not None:
            data['OS-KSCATALOG:endpointTemplate']['versionInfo'] = version_info

        return self.put_endpoint_template(endpoint_template_id, as_json=data,
            **kwargs)

    def fetch_user_credentials(self, user_id=None, **kwargs):
        user_id = optional_str(user_id)
        return self.get_user_credentials(user_id, **kwargs)

    def fetch_password_credentials(self, user_id=None, **kwargs):
        user_id = optional_str(user_id)
        return self.get_user_credentials_by_type(
            user_id, 'passwordCredentials', **kwargs)

    def create_password_credentials(self, user_id, user_name,
                                    password=None, **kwargs):
        user_id = optional_str(user_id)
        password = optional_str(password)
        data = {
            "passwordCredentials": {
                "username": user_name,
                "password": password}}
        return self.post_credentials(user_id, as_json=data, **kwargs)

    def update_password_credentials(self, user_id, user_name,
                password=None, **kwargs):
        user_id = optional_str(user_id)
        password = optional_str(password)
        data = {
            "passwordCredentials": {
                "username": user_name,
                "password": password}}
        return self.post_credentials_by_type(
            user_id, 'passwordCredentials', as_json=data, **kwargs)

    def delete_password_credentials(self, user_id, **kwargs):
        user_id = optional_str(user_id)
        return self.delete_user_credentials_by_type(
                user_id, 'passwordCredentials', **kwargs)

    def check_urls_for_regular_user(self, service_catalog):
        self.assertIsNotNone(service_catalog)
        for x in range(0, len(service_catalog)):
            endpoints = service_catalog[x]['endpoints']
            for y in range(0, len(endpoints)):
                endpoint = endpoints[y]
                for key in endpoint:
                    #Checks whether adminURL is not present.
                    self.assertNotEquals(key, 'adminURL')

    def check_urls_for_regular_user_xml(self, service_catalog):
        self.assertIsNotNone(service_catalog)
        services = service_catalog.findall('{%s}service' % self.xmlns)
        self.assertIsNotNone(services)
        for service in services:
            endpoints = service.findall('{%s}endpoint' % self.xmlns)
            self.assertIsNotNone(endpoints)
            for endpoint in endpoints:
                #Checks whether adminURL is not present.
                self.assertIsNone(endpoint.get('adminURL'))
        self.assertIsNotNone(service_catalog)

    def check_urls_for_admin_user(self, service_catalog):
        self.assertIsNotNone(service_catalog)
        for x in range(0, len(service_catalog)):
            endpoints = service_catalog[x]['endpoints']
            is_admin__url_present = None
            for y in range(0, len(endpoints)):
                endpoint = endpoints[y]
                for key in endpoint:
                    if key == 'adminURL':
                        is_admin__url_present = True
            self.assertTrue(is_admin__url_present,
                            "Admin API does not return admin URL")

    def check_urls_for_admin_user_xml(self, service_catalog):
        self.assertIsNotNone(service_catalog)
        services = service_catalog.findall('{%s}service' % self.xmlns)
        self.assertIsNotNone(services)
        is_admin_url_present = None
        for service in services:
            endpoints = service.findall('{%s}endpoint' % self.xmlns)
            self.assertIsNotNone(endpoints)
            for endpoint in endpoints:
                if endpoint.get('adminURL'):
                    is_admin_url_present = True
        self.assertTrue(is_admin_url_present,
            "Admin API does not return admin URL")


class HeaderApp(object):
    """
    Dummy WSGI app the returns HTTP headers in the body

    This is useful for making sure the headers we want
    aer being passwed down to the downstream WSGI app.
    """
    def __init__(self):
        pass

    def __call__(self, env, start_response):
        self.request = Request.blank('', environ=env)
        body = ''
        for key in env:
            if key.startswith('HTTP_'):
                body += '%s: %s\n' % (key, env[key])
        return Response(status="200 OK",
                        body=body)(env, start_response)


class BlankApp(object):
    """
    Dummy WSGI app - does not do anything
    """
    def __init__(self):
        pass

    def __call__(self, env, start_response):
        self.request = Request.blank('', environ=env)
        return Response(status="200 OK",
                        body={})(env, start_response)


class MiddlewareTestCase(FunctionalTestCase):
    """
    Base class to run tests for Keystone WSGI middleware.
    """
    use_server = True

    def _setup_test_middleware(self):
        test_middleware = None
        if isinstance(self.middleware, tuple):
            test_middleware = HeaderApp()
            for filter in self.middleware:
                test_middleware = \
                    filter.filter_factory(self.settings)(test_middleware)
        else:
            test_middleware = \
                self.middleware.filter_factory(self.settings)(HeaderApp())
        return test_middleware

    def setUp(self, middleware, settings=None):
        super(MiddlewareTestCase, self).setUp()
        if settings is None:
            settings = {'delay_auth_decision': '0',
                'auth_host': client_tests.TEST_TARGET_SERVER_ADMIN_ADDRESS,
                'auth_port': client_tests.TEST_TARGET_SERVER_ADMIN_PORT,
                'auth_protocol':
                    client_tests.TEST_TARGET_SERVER_ADMIN_PROTOCOL,
                'auth_uri': ('%s://%s:%s/' % \
                             (client_tests.TEST_TARGET_SERVER_SERVICE_PROTOCOL,
                              client_tests.TEST_TARGET_SERVER_SERVICE_ADDRESS,
                              client_tests.TEST_TARGET_SERVER_SERVICE_PORT)),
                'admin_token': self.admin_token,
                'auth_admin_user': self.admin_username,
                'auth_admin_password': self.admin_password}
        cert_file = isSsl()
        if cert_file:
            settings['certfile'] = cert_file
        self.settings = settings
        self.middleware = middleware
        self.test_middleware = self._setup_test_middleware()

        name = unique_str()
        r = self.create_tenant(tenant_name=name, assert_status=201)
        self.tenant = r.json.get('tenant')

        user_name = unique_str()
        password = unique_str()
        r = self.create_user(user_name=user_name,
                                     user_password=password,
                                     tenant_id=self.tenant['id'])
        self.tenant_user = r.json.get('user')
        self.tenant_user['password'] = password

        access = self.authenticate(user_name, password).\
            json['access']
        self.tenant_user_token = access['token']

        self.services = {}
        self.endpoint_templates = {}
        for x in range(0, 5):
            self.services[x] = self.create_service().json['OS-KSADM:service']
            self.endpoint_templates[x] = self.create_endpoint_template(
                name=self.services[x]['name'], \
                type=self.services[x]['type']).\
                json['OS-KSCATALOG:endpointTemplate']
            self.create_endpoint_for_tenant(self.tenant['id'],
                self.endpoint_templates[x]['id'])

    @unittest.skipIf(isSsl() or 'HP-IDM_Disabled' in os.environ,
                     "Skipping SSL or HP-IDM tests")
    def test_with_service_id(self):
        if isSsl() or ('HP-IDM_Disabled' in os.environ):
            # TODO(zns): why is this not skipping with the decorator?!
            raise unittest.SkipTest("Skipping SSL or HP-IDM tests")
        # create a service role so the scope token validation will succeed
        role_resp = self.create_role(service_name=self.services[0]['name'])
        role = role_resp.json['role']
        self.grant_role_to_user(self.tenant_user['id'],
                                role['id'], self.tenant['id'])
        auth_resp = self.authenticate(self.tenant_user['name'],
            self.tenant_user['password'],
            self.tenant['id'], assert_status=200)
        user_token = auth_resp.json['access']['token']['id']
        self.settings['service_ids'] = "%s" % self.services[0]['id']
        test_middleware = self._setup_test_middleware()
        resp = Request.blank('/',
            headers={'X-Auth-Token': user_token}) \
            .get_response(test_middleware)
        self.assertEquals(resp.status_int, 200)

        # now give it a bogus service ID to make sure we get a 401
        self.settings['service_ids'] = "boguzz"
        test_middleware = self._setup_test_middleware()
        resp = Request.blank('/',
            headers={'X-Auth-Token': user_token}) \
            .get_response(test_middleware)
        self.assertEquals(resp.status_int, 401)

    @unittest.skipUnless(not isSsl() and 'HP-IDM_Disabled' in os.environ,
                     "Skipping since HP-IDM is enabled")
    def test_with_service_id_with_hpidm_disabled(self):
        # create a service role so the scope token validation will succeed
        role_resp = self.create_role(service_name=self.services[0]['name'])
        role = role_resp.json['role']
        self.grant_role_to_user(self.tenant_user['id'],
                                role['id'], self.tenant['id'])
        auth_resp = self.authenticate(self.tenant_user['name'],
            self.tenant_user['password'],
            self.tenant['id'], assert_status=200)
        user_token = auth_resp.json['access']['token']['id']
        self.settings['service_ids'] = "%s" % self.services[0]['id']
        test_middleware = self._setup_test_middleware()
        resp = Request.blank('/',
            headers={'X-Auth-Token': user_token}) \
            .get_response(test_middleware)
        self.assertEquals(resp.status_int, 200)

        # now give it a bogus service ID to make sure it got ignored
        self.settings['service_ids'] = "boguzz"
        test_middleware = self._setup_test_middleware()
        resp = Request.blank('/',
            headers={'X-Auth-Token': user_token}) \
            .get_response(test_middleware)
        self.assertEquals(resp.status_int, 200)

    def test_401_without_token(self):
        resp = Request.blank('/').get_response(self.test_middleware)
        self.assertEquals(resp.status_int, 401)
        headers = resp.headers
        self.assertTrue("WWW-Authenticate" in headers)
        self.assertEquals(headers['WWW-Authenticate'],
                            "Keystone uri='%s://%s:%s/'" % \
                         (client_tests.TEST_TARGET_SERVER_SERVICE_PROTOCOL,
                          client_tests.TEST_TARGET_SERVER_SERVICE_ADDRESS,
                          client_tests.TEST_TARGET_SERVER_SERVICE_PORT))

    def test_401_bad_token(self):
        resp = Request.blank('/',
            headers={'X-Auth-Token': 'MADE_THIS_UP'}) \
            .get_response(self.test_middleware)
        self.assertEquals(resp.status_int, 401)

    def test_200_good_token(self):
        resp = Request.blank('/',
            headers={'X-Auth-Token': self.tenant_user_token['id']}) \
            .get_response(self.test_middleware)

        self.assertEquals(resp.status_int, 200)

        headers = resp.body.split('\n')

        header = "HTTP_X_IDENTITY_STATUS: Confirmed"
        self.assertTrue(header in headers, "Missing %s" % header)

        header = "HTTP_X_USER_ID: %s" % self.tenant_user['id']
        self.assertTrue(header in headers, "Missing %s" % header)

        header = "HTTP_X_USER_NAME: %s" % self.tenant_user['name']
        self.assertTrue(header in headers, "Missing %s" % header)

        header = "HTTP_X_TENANT_ID: %s" % self.tenant['id']
        self.assertTrue(header in headers, "Missing %s" % header)

        header = "HTTP_X_TENANT_NAME: %s" % self.tenant['name']
        self.assertTrue(header in headers, "Missing %s" % header)

        # These are here for legacy support and should be removed by F
        header = "HTTP_X_TENANT: %s" % self.tenant['id']
        self.assertTrue(header in headers, "Missing %s" % header)

        header = "HTTP_X_USER: %s" % self.tenant_user['id']
        self.assertTrue(header in headers, "Missing %s" % header)
