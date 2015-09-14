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

import hashlib
import uuid

from oslo_config import cfg
from six.moves import http_client
import webob

from keystone.common import authorization
from keystone.common import tokenless_auth
from keystone.contrib.federation import constants as federation_constants
from keystone import exception
from keystone import middleware
from keystone.tests import unit
from keystone.tests.unit import mapping_fixtures
from keystone.tests.unit import test_backend_sql


CONF = cfg.CONF


def make_request(**kwargs):
    accept = kwargs.pop('accept', None)
    method = kwargs.pop('method', 'GET')
    body = kwargs.pop('body', None)
    req = webob.Request.blank('/', **kwargs)
    req.method = method
    if body is not None:
        req.body = body
    if accept is not None:
        req.accept = accept
    return req


def make_response(**kwargs):
    body = kwargs.pop('body', None)
    return webob.Response(body)


class TokenAuthMiddlewareTest(unit.TestCase):
    def test_request(self):
        req = make_request()
        req.headers[middleware.AUTH_TOKEN_HEADER] = 'MAGIC'
        middleware.TokenAuthMiddleware(None).process_request(req)
        context = req.environ[middleware.CONTEXT_ENV]
        self.assertEqual('MAGIC', context['token_id'])


class AdminTokenAuthMiddlewareTest(unit.TestCase):
    def test_request_admin(self):
        req = make_request()
        req.headers[middleware.AUTH_TOKEN_HEADER] = CONF.admin_token
        middleware.AdminTokenAuthMiddleware(None).process_request(req)
        context = req.environ[middleware.CONTEXT_ENV]
        self.assertTrue(context['is_admin'])

    def test_request_non_admin(self):
        req = make_request()
        req.headers[middleware.AUTH_TOKEN_HEADER] = 'NOT-ADMIN'
        middleware.AdminTokenAuthMiddleware(None).process_request(req)
        context = req.environ[middleware.CONTEXT_ENV]
        self.assertFalse(context['is_admin'])


class PostParamsMiddlewareTest(unit.TestCase):
    def test_request_with_params(self):
        req = make_request(body="arg1=one", method='POST')
        middleware.PostParamsMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual({"arg1": "one"}, params)


class JsonBodyMiddlewareTest(unit.TestCase):
    def test_request_with_params(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           content_type='application/json',
                           method='POST')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual({"arg1": "one", "arg2": ["a"]}, params)

    def test_malformed_json(self):
        req = make_request(body='{"arg1": "on',
                           content_type='application/json',
                           method='POST')
        resp = middleware.JsonBodyMiddleware(None).process_request(req)
        self.assertEqual(http_client.BAD_REQUEST, resp.status_int)

    def test_not_dict_body(self):
        req = make_request(body='42',
                           content_type='application/json',
                           method='POST')
        resp = middleware.JsonBodyMiddleware(None).process_request(req)
        self.assertEqual(http_client.BAD_REQUEST, resp.status_int)
        self.assertTrue('valid JSON object' in resp.json['error']['message'])

    def test_no_content_type(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           method='POST')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual({"arg1": "one", "arg2": ["a"]}, params)

    def test_unrecognized_content_type(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           content_type='text/plain',
                           method='POST')
        resp = middleware.JsonBodyMiddleware(None).process_request(req)
        self.assertEqual(http_client.BAD_REQUEST, resp.status_int)

    def test_unrecognized_content_type_without_body(self):
        req = make_request(content_type='text/plain',
                           method='GET')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ.get(middleware.PARAMS_ENV, {})
        self.assertEqual({}, params)


class AuthContextMiddlewareTest(test_backend_sql.SqlTests):

    def setUp(self):
        super(AuthContextMiddlewareTest, self).setUp()
        self.client_issuer = uuid.uuid4().hex
        self.untrusted_client_issuer = uuid.uuid4().hex
        self.trusted_issuer = self.client_issuer
        self.config_fixture.config(group='tokenless_auth',
                                   trusted_issuer=[self.trusted_issuer])

        # This idp_id is calculated based on
        # sha256(self.client_issuer)
        hashed_idp = hashlib.sha256(self.client_issuer)
        self.idp_id = hashed_idp.hexdigest()
        self._load_sample_data()

    def _load_sample_data(self):
        self.domain_id = uuid.uuid4().hex
        self.domain_name = uuid.uuid4().hex
        self.project_id = uuid.uuid4().hex
        self.project_name = uuid.uuid4().hex
        self.user_name = uuid.uuid4().hex
        self.user_password = uuid.uuid4().hex
        self.user_email = uuid.uuid4().hex
        self.protocol_id = 'x509'
        self.role_id = uuid.uuid4().hex
        self.role_name = uuid.uuid4().hex
        # for ephemeral user
        self.group_name = uuid.uuid4().hex

        # 1) Create a domain for the user.
        self.domain = {
            'description': uuid.uuid4().hex,
            'enabled': True,
            'id': self.domain_id,
            'name': self.domain_name,
        }

        self.resource_api.create_domain(self.domain_id, self.domain)

        # 2) Create a project for the user.
        self.project = {
            'description': uuid.uuid4().hex,
            'domain_id': self.domain_id,
            'enabled': True,
            'id': self.project_id,
            'name': self.project_name,
        }

        self.resource_api.create_project(self.project_id, self.project)

        # 3) Create a user in new domain.
        self.user = {
            'name': self.user_name,
            'domain_id': self.domain_id,
            'project_id': self.project_id,
            'password': self.user_password,
            'email': self.user_email,
        }

        self.user = self.identity_api.create_user(self.user)

        # Add IDP
        self.idp = self._idp_ref(id=self.idp_id)
        self.federation_api.create_idp(self.idp['id'],
                                       self.idp)

        # Add a role
        self.role = {
            'id': self.role_id,
            'name': self.role_name,
        }
        self.role_api.create_role(self.role_id, self.role)

        # Add a group
        self.group = {
            'name': self.group_name,
            'domain_id': self.domain_id,
        }
        self.group = self.identity_api.create_group(self.group)

        # Assign a role to the user on a project
        self.assignment_api.add_role_to_user_and_project(
            user_id=self.user['id'],
            tenant_id=self.project_id,
            role_id=self.role_id)

        # Assign a role to the group on a project
        self.assignment_api.create_grant(
            role_id=self.role_id,
            group_id=self.group['id'],
            project_id=self.project_id)

    def _load_mapping_rules(self, rules):
        # Add a mapping
        self.mapping = self._mapping_ref(rules=rules)
        self.federation_api.create_mapping(self.mapping['id'],
                                           self.mapping)
        # Add protocols
        self.proto_x509 = self._proto_ref(mapping_id=self.mapping['id'])
        self.proto_x509['id'] = self.protocol_id
        self.federation_api.create_protocol(self.idp['id'],
                                            self.proto_x509['id'],
                                            self.proto_x509)

    def _idp_ref(self, id=None):
        idp = {
            'id': id or uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        return idp

    def _proto_ref(self, mapping_id=None):
        proto = {
            'id': uuid.uuid4().hex,
            'mapping_id': mapping_id or uuid.uuid4().hex
        }
        return proto

    def _mapping_ref(self, rules=None):
        if rules is None:
            mapped_rules = {}
        else:
            mapped_rules = rules.get('rules', {})
        return {
            'id': uuid.uuid4().hex,
            'rules': mapped_rules
        }

    def _assert_tokenless_auth_context(self, context, ephemeral_user=False):
        self.assertIsNotNone(context)
        self.assertEqual(self.project_id, context['project_id'])
        self.assertIn(self.role_name, context['roles'])
        if ephemeral_user:
            self.assertEqual(self.group['id'], context['group_ids'][0])
            self.assertEqual('ephemeral',
                             context[federation_constants.PROTOCOL])
            self.assertEqual(self.idp_id,
                             context[federation_constants.IDENTITY_PROVIDER])
        else:
            self.assertEqual(self.user['id'], context['user_id'])

    def _create_context(self, request, mapping_ref=None,
                        exception_expected=False):
        """Builds the auth context from the given arguments.

        auth context will be returned from the AuthContextMiddleware based on
        what is being passed in the given request and what mapping is being
        setup in the backend DB.

        :param request: HTTP request
        :param mapping_ref: A mapping in JSON structure will be setup in the
            backend DB for mapping an user or a group.
        :param exception_expected: Sets to True when an exception is expected
            to raised based on the given arguments.
        :returns: context an auth context contains user and role information
        :rtype: dict
        """
        if mapping_ref:
            self._load_mapping_rules(mapping_ref)

        if not exception_expected:
            (middleware.AuthContextMiddleware('Tokenless_auth_test').
                process_request(request))
            context = request.environ.get(authorization.AUTH_CONTEXT_ENV)
        else:
            context = middleware.AuthContextMiddleware('Tokenless_auth_test')
        return context

    def test_context_already_exists(self):
        req = make_request()
        token_id = uuid.uuid4().hex
        req.environ[authorization.AUTH_CONTEXT_ENV] = {'token_id': token_id}
        context = self._create_context(request=req)
        self.assertEqual(token_id, context['token_id'])

    def test_not_applicable_to_token_request(self):
        env = {}
        env['PATH_INFO'] = '/auth/tokens'
        env['REQUEST_METHOD'] = 'POST'
        req = make_request(environ=env)
        context = self._create_context(request=req)
        self.assertIsNone(context)

    def test_no_tokenless_attributes_request(self):
        req = make_request()
        context = self._create_context(request=req)
        self.assertIsNone(context)

    def test_no_issuer_attribute_request(self):
        env = {}
        env['HTTP_X_PROJECT_ID'] = uuid.uuid4().hex
        req = make_request(environ=env)
        context = self._create_context(request=req)
        self.assertIsNone(context)

    def test_has_only_issuer_and_project_name_request(self):
        env = {}
        # SSL_CLIENT_I_DN is the attribute name that wsgi env
        # references to issuer of the client certificate.
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = uuid.uuid4().hex
        req = make_request(environ=env)
        context = self._create_context(request=req,
                                       exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_has_only_issuer_and_project_domain_name_request(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = uuid.uuid4().hex
        req = make_request(environ=env)
        context = self._create_context(request=req,
                                       exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_has_only_issuer_and_project_domain_id_request(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_DOMAIN_ID'] = uuid.uuid4().hex
        req = make_request(environ=env)
        context = self._create_context(request=req,
                                       exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_missing_both_domain_and_project_request(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        req = make_request(environ=env)
        context = self._create_context(request=req,
                                       exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_empty_trusted_issuer_list(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = uuid.uuid4().hex
        req = make_request(environ=env)
        self.config_fixture.config(group='tokenless_auth',
                                   trusted_issuer=[])
        context = self._create_context(request=req)
        self.assertIsNone(context)

    def test_client_issuer_not_trusted(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.untrusted_client_issuer
        env['HTTP_X_PROJECT_ID'] = uuid.uuid4().hex
        req = make_request(environ=env)
        context = self._create_context(request=req)
        self.assertIsNone(context)

    def test_proj_scope_with_proj_id_and_proj_dom_id_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = self.project_id
        env['HTTP_X_PROJECT_DOMAIN_ID'] = self.domain_id
        # SSL_CLIENT_USER_NAME and SSL_CLIENT_DOMAIN_NAME are the types
        # defined in the mapping that will map to the user name and
        # domain name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINNAME)
        self._assert_tokenless_auth_context(context)

    def test_proj_scope_with_proj_id_only_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = self.project_id
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINNAME)
        self._assert_tokenless_auth_context(context)

    def test_proj_scope_with_proj_name_and_proj_dom_id_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_ID'] = self.domain_id
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINNAME)
        self._assert_tokenless_auth_context(context)

    def test_proj_scope_with_proj_name_and_proj_dom_name_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINNAME)
        self._assert_tokenless_auth_context(context)

    def test_proj_scope_with_proj_name_only_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_id
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINNAME,
            exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_mapping_with_userid_and_domainid_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_ID'] = self.user['id']
        env['SSL_CLIENT_DOMAIN_ID'] = self.domain_id
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERID_AND_DOMAINID)
        self._assert_tokenless_auth_context(context)

    def test_mapping_with_userid_and_domainname_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_ID'] = self.user['id']
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERID_AND_DOMAINNAME)
        self._assert_tokenless_auth_context(context)

    def test_mapping_with_username_and_domainid_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_ID'] = self.domain_id
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINID)
        self._assert_tokenless_auth_context(context)

    def test_only_domain_name_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = self.project_id
        env['HTTP_X_PROJECT_DOMAIN_ID'] = self.domain_id
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_DOMAINNAME_ONLY,
            exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_only_domain_id_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = self.project_id
        env['HTTP_X_PROJECT_DOMAIN_ID'] = self.domain_id
        env['SSL_CLIENT_DOMAIN_ID'] = self.domain_id
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_DOMAINID_ONLY,
            exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_missing_domain_data_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = self.project_id
        env['HTTP_X_PROJECT_DOMAIN_ID'] = self.domain_id
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_ONLY,
            exception_expected=True)
        self.assertRaises(exception.ValidationError,
                          context.process_request,
                          req)

    def test_userid_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = self.project_id
        env['HTTP_X_PROJECT_DOMAIN_ID'] = self.domain_id
        env['SSL_CLIENT_USER_ID'] = self.user['id']
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERID_ONLY)
        self._assert_tokenless_auth_context(context)

    def test_domain_disable_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_ID'] = self.domain_id
        req = make_request(environ=env)
        self.domain['enabled'] = False
        self.domain = self.resource_api.update_domain(
            self.domain['id'], self.domain)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINID,
            exception_expected=True)
        self.assertRaises(exception.Unauthorized,
                          context.process_request,
                          req)

    def test_user_disable_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        env['SSL_CLIENT_DOMAIN_ID'] = self.domain_id
        req = make_request(environ=env)
        self.user['enabled'] = False
        self.user = self.identity_api.update_user(self.user['id'], self.user)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINID,
            exception_expected=True)
        self.assertRaises(AssertionError,
                          context.process_request,
                          req)

    def test_invalid_user_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_ID'] = self.project_id
        env['HTTP_X_PROJECT_DOMAIN_ID'] = self.domain_id
        env['SSL_CLIENT_USER_NAME'] = uuid.uuid4().hex
        env['SSL_CLIENT_DOMAIN_NAME'] = self.domain_name
        req = make_request(environ=env)
        context = self._create_context(
            request=req,
            mapping_ref=mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINNAME,
            exception_expected=True)
        self.assertRaises(exception.UserNotFound,
                          context.process_request,
                          req)

    def test_ephemeral_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        req = make_request(environ=env)
        self.config_fixture.config(group='tokenless_auth',
                                   protocol='ephemeral')
        self.protocol_id = 'ephemeral'
        mapping = mapping_fixtures.MAPPING_FOR_EPHEMERAL_USER.copy()
        mapping['rules'][0]['local'][0]['group']['id'] = self.group['id']
        context = self._create_context(
            request=req,
            mapping_ref=mapping)
        self._assert_tokenless_auth_context(context, ephemeral_user=True)

    def test_ephemeral_with_default_user_type_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        req = make_request(environ=env)
        self.config_fixture.config(group='tokenless_auth',
                                   protocol='ephemeral')
        self.protocol_id = 'ephemeral'
        # this mapping does not have the user type defined
        # and it should defaults to 'ephemeral' which is
        # the expected type for the test case.
        mapping = mapping_fixtures.MAPPING_FOR_DEFAULT_EPHEMERAL_USER.copy()
        mapping['rules'][0]['local'][0]['group']['id'] = self.group['id']
        context = self._create_context(
            request=req,
            mapping_ref=mapping)
        self._assert_tokenless_auth_context(context, ephemeral_user=True)

    def test_ephemeral_any_user_success(self):
        """Ephemeral user does not need a specified user
        Keystone is not looking to match the user, but a corresponding group.
        """
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = uuid.uuid4().hex
        req = make_request(environ=env)
        self.config_fixture.config(group='tokenless_auth',
                                   protocol='ephemeral')
        self.protocol_id = 'ephemeral'
        mapping = mapping_fixtures.MAPPING_FOR_EPHEMERAL_USER.copy()
        mapping['rules'][0]['local'][0]['group']['id'] = self.group['id']
        context = self._create_context(
            request=req,
            mapping_ref=mapping)
        self._assert_tokenless_auth_context(context, ephemeral_user=True)

    def test_ephemeral_invalid_scope_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = uuid.uuid4().hex
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = uuid.uuid4().hex
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        req = make_request(environ=env)
        self.config_fixture.config(group='tokenless_auth',
                                   protocol='ephemeral')
        self.protocol_id = 'ephemeral'
        mapping = mapping_fixtures.MAPPING_FOR_EPHEMERAL_USER.copy()
        mapping['rules'][0]['local'][0]['group']['id'] = self.group['id']
        context = self._create_context(
            request=req,
            mapping_ref=mapping,
            exception_expected=True)
        self.assertRaises(exception.Unauthorized,
                          context.process_request,
                          req)

    def test_ephemeral_no_group_found_fail(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        req = make_request(environ=env)
        self.config_fixture.config(group='tokenless_auth',
                                   protocol='ephemeral')
        self.protocol_id = 'ephemeral'
        mapping = mapping_fixtures.MAPPING_FOR_EPHEMERAL_USER.copy()
        mapping['rules'][0]['local'][0]['group']['id'] = uuid.uuid4().hex
        context = self._create_context(
            request=req,
            mapping_ref=mapping,
            exception_expected=True)
        self.assertRaises(exception.MappedGroupNotFound,
                          context.process_request,
                          req)

    def test_ephemeral_incorrect_mapping_fail(self):
        """Ephemeral user picks up the non-ephemeral user mapping.
        Looking up the mapping with protocol Id 'x509' will load up
        the non-ephemeral user mapping, results unauthenticated.
        """
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        env['HTTP_X_PROJECT_NAME'] = self.project_name
        env['HTTP_X_PROJECT_DOMAIN_NAME'] = self.domain_name
        env['SSL_CLIENT_USER_NAME'] = self.user_name
        req = make_request(environ=env)
        # This will pick up the incorrect mapping
        self.config_fixture.config(group='tokenless_auth',
                                   protocol='x509')
        self.protocol_id = 'x509'
        mapping = mapping_fixtures.MAPPING_FOR_EPHEMERAL_USER.copy()
        mapping['rules'][0]['local'][0]['group']['id'] = uuid.uuid4().hex
        context = self._create_context(
            request=req,
            mapping_ref=mapping,
            exception_expected=True)
        self.assertRaises(exception.MappedGroupNotFound,
                          context.process_request,
                          req)

    def test_create_idp_id_success(self):
        env = {}
        env['SSL_CLIENT_I_DN'] = self.client_issuer
        auth = tokenless_auth.TokenlessAuthHelper(env)
        idp_id = auth._build_idp_id()
        self.assertEqual(self.idp_id, idp_id)

    def test_create_idp_id_attri_not_found_fail(self):
        env = {}
        env[uuid.uuid4().hex] = self.client_issuer
        auth = tokenless_auth.TokenlessAuthHelper(env)
        expected_msg = ('Could not determine Identity Provider ID. The '
                        'configuration option %s was not found in the '
                        'request environment.' %
                        CONF.tokenless_auth.issuer_attribute)
        # Check the content of the exception message as well
        self.assertRaisesRegexp(exception.TokenlessAuthConfigError,
                                expected_msg,
                                auth._build_idp_id)
