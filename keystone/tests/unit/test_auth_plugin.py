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

import uuid

import mock

from keystone import auth
from keystone import exception
from keystone.tests import unit


# for testing purposes only
METHOD_NAME = 'simple_challenge_response'
EXPECTED_RESPONSE = uuid.uuid4().hex
DEMO_USER_ID = uuid.uuid4().hex


class SimpleChallengeResponse(auth.AuthMethodHandler):
    def authenticate(self, context, auth_payload, user_context):
        if 'response' in auth_payload:
            if auth_payload['response'] != EXPECTED_RESPONSE:
                raise exception.Unauthorized('Wrong answer')
            user_context['user_id'] = DEMO_USER_ID
        else:
            return {"challenge": "What's the name of your high school?"}


class TestAuthPlugin(unit.SQLDriverOverrides, unit.TestCase):
    def setUp(self):
        super(TestAuthPlugin, self).setUp()
        self.load_backends()

        self.api = auth.controllers.Auth()

    def config_overrides(self):
        super(TestAuthPlugin, self).config_overrides()
        method_opts = {
            METHOD_NAME:
                'keystone.tests.unit.test_auth_plugin.SimpleChallengeResponse',
        }

        self.auth_plugin_config_override(
            methods=['external', 'password', 'token', METHOD_NAME],
            **method_opts)

    def test_unsupported_auth_method(self):
        method_name = uuid.uuid4().hex
        auth_data = {'methods': [method_name]}
        auth_data[method_name] = {'test': 'test'}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.AuthMethodNotSupported,
                          auth.controllers.AuthInfo.create,
                          None,
                          auth_data)

    def test_addition_auth_steps(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'test': 'test'}
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo.create(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        try:
            self.api.authenticate({'environment': {}}, auth_info, auth_context)
        except exception.AdditionalAuthRequired as e:
            self.assertIn('methods', e.authentication)
            self.assertIn(METHOD_NAME, e.authentication['methods'])
            self.assertIn(METHOD_NAME, e.authentication)
            self.assertIn('challenge', e.authentication[METHOD_NAME])

        # test correct response
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'response': EXPECTED_RESPONSE}
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo.create(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.api.authenticate({'environment': {}}, auth_info, auth_context)
        self.assertEqual(DEMO_USER_ID, auth_context['user_id'])

        # test incorrect response
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'response': uuid.uuid4().hex}
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo.create(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.Unauthorized,
                          self.api.authenticate,
                          {'environment': {}},
                          auth_info,
                          auth_context)

    def test_duplicate_method(self):
        # Having the same method twice doesn't cause load_auth_methods to fail.
        self.auth_plugin_config_override(
            methods=['external', 'external'])
        self.clear_auth_plugin_registry()
        auth.controllers.load_auth_methods()
        self.assertIn('external', auth.controllers.AUTH_METHODS)


class TestAuthPluginDynamicOptions(TestAuthPlugin):
    def config_overrides(self):
        super(TestAuthPluginDynamicOptions, self).config_overrides()
        # Clear the override for the [auth] ``methods`` option so it is
        # possible to load the options from the config file.
        self.config_fixture.conf.clear_override('methods', group='auth')

    def config_files(self):
        config_files = super(TestAuthPluginDynamicOptions, self).config_files()
        config_files.append(unit.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files


class TestMapped(unit.TestCase):
    def setUp(self):
        super(TestMapped, self).setUp()
        self.load_backends()

        self.api = auth.controllers.Auth()

    def config_files(self):
        config_files = super(TestMapped, self).config_files()
        config_files.append(unit.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files

    def auth_plugin_config_override(self, methods=None, **method_classes):
        # Do not apply the auth plugin overrides so that the config file is
        # tested
        pass

    def _test_mapped_invocation_with_method_name(self, method_name):
        with mock.patch.object(auth.plugins.mapped.Mapped,
                               'authenticate',
                               return_value=None) as authenticate:
            context = {'environment': {}}
            auth_data = {
                'identity': {
                    'methods': [method_name],
                    method_name: {'protocol': method_name},
                }
            }
            auth_info = auth.controllers.AuthInfo.create(context, auth_data)
            auth_context = {'extras': {},
                            'method_names': [],
                            'user_id': uuid.uuid4().hex}
            self.api.authenticate(context, auth_info, auth_context)
            # make sure Mapped plugin got invoked with the correct payload
            ((context, auth_payload, auth_context),
             kwargs) = authenticate.call_args
            self.assertEqual(method_name, auth_payload['protocol'])

    def test_mapped_with_remote_user(self):
        with mock.patch.object(auth.plugins.mapped.Mapped,
                               'authenticate',
                               return_value=None) as authenticate:
            # external plugin should fail and pass to mapped plugin
            method_name = 'saml2'
            auth_data = {'methods': [method_name]}
            # put the method name in the payload so its easier to correlate
            # method name with payload
            auth_data[method_name] = {'protocol': method_name}
            auth_data = {'identity': auth_data}
            auth_info = auth.controllers.AuthInfo.create(None, auth_data)
            auth_context = {'extras': {},
                            'method_names': [],
                            'user_id': uuid.uuid4().hex}
            environment = {'environment': {'REMOTE_USER': 'foo@idp.com'}}
            self.api.authenticate(environment, auth_info, auth_context)
            # make sure Mapped plugin got invoked with the correct payload
            ((context, auth_payload, auth_context),
             kwargs) = authenticate.call_args
            self.assertEqual(auth_payload['protocol'], method_name)

    def test_supporting_multiple_methods(self):
        for method_name in ['saml2', 'openid', 'x509']:
            self._test_mapped_invocation_with_method_name(method_name)
