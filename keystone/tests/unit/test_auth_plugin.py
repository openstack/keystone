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

from unittest import mock
import uuid

import stevedore

from keystone.api._shared import authentication
from keystone import auth
from keystone.auth.plugins import base
from keystone.auth.plugins import mapped
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import auth_plugins


# for testing purposes only
METHOD_NAME = 'simple_challenge_response'
EXPECTED_RESPONSE = uuid.uuid4().hex
DEMO_USER_ID = uuid.uuid4().hex


class SimpleChallengeResponse(base.AuthMethodHandler):
    def authenticate(self, auth_payload):
        response_data = {}
        if 'response' in auth_payload:
            if auth_payload['response'] != EXPECTED_RESPONSE:
                raise exception.Unauthorized('Wrong answer')

            response_data['user_id'] = DEMO_USER_ID
            return base.AuthHandlerResponse(status=True, response_body=None,
                                            response_data=response_data)
        else:
            return base.AuthHandlerResponse(
                status=False,
                response_body={
                    "challenge": "What's the name of your high school?"},
                response_data=None)


class TestAuthPlugin(unit.SQLDriverOverrides, unit.TestCase):

    def test_unsupported_auth_method(self):
        method_name = uuid.uuid4().hex
        auth_data = {'methods': [method_name]}
        auth_data[method_name] = {'test': 'test'}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.AuthMethodNotSupported,
                          auth.core.AuthInfo.create,
                          auth_data)

    @mock.patch.object(auth.core, '_get_auth_driver_manager')
    def test_addition_auth_steps(self, stevedore_mock):
        simple_challenge_plugin = SimpleChallengeResponse()
        extension = stevedore.extension.Extension(
            name='simple_challenge', entry_point=None, plugin=None,
            obj=simple_challenge_plugin
        )
        test_manager = stevedore.DriverManager.make_test_instance(extension)
        stevedore_mock.return_value = test_manager

        self.useFixture(
            auth_plugins.ConfigAuthPlugins(self.config_fixture,
                                           methods=[METHOD_NAME]))
        self.useFixture(auth_plugins.LoadAuthPlugins(METHOD_NAME))

        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'test': 'test'}
        auth_data = {'identity': auth_data}
        auth_info = auth.core.AuthInfo.create(auth_data)
        auth_context = auth.core.AuthContext(method_names=[])
        try:
            with self.make_request():
                authentication.authenticate(auth_info, auth_context)
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
        auth_info = auth.core.AuthInfo.create(auth_data)
        auth_context = auth.core.AuthContext(method_names=[])
        with self.make_request():
            authentication.authenticate(auth_info, auth_context)
        self.assertEqual(DEMO_USER_ID, auth_context['user_id'])

        # test incorrect response
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'response': uuid.uuid4().hex}
        auth_data = {'identity': auth_data}
        auth_info = auth.core.AuthInfo.create(auth_data)
        auth_context = auth.core.AuthContext(method_names=[])
        with self.make_request():
            self.assertRaises(exception.Unauthorized,
                              authentication.authenticate,
                              auth_info,
                              auth_context)

    def test_duplicate_method(self):
        # Having the same method twice doesn't cause load_auth_methods to fail.
        self.useFixture(
            auth_plugins.ConfigAuthPlugins(self.config_fixture,
                                           ['external', 'external']))
        auth.core.load_auth_methods()
        self.assertIn('external', auth.core.AUTH_METHODS)


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

    def config_files(self):
        config_files = super(TestMapped, self).config_files()
        config_files.append(unit.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files

    def _test_mapped_invocation_with_method_name(self, method_name):
        with mock.patch.object(auth.plugins.mapped.Mapped,
                               'authenticate',
                               return_value=None) as authenticate:
            auth_data = {
                'identity': {
                    'methods': [method_name],
                    method_name: {'protocol': method_name},
                }
            }
            auth_info = auth.core.AuthInfo.create(auth_data)
            auth_context = auth.core.AuthContext(
                method_names=[],
                user_id=uuid.uuid4().hex)
            with self.make_request():
                authentication.authenticate(auth_info, auth_context)
            # make sure Mapped plugin got invoked with the correct payload
            ((auth_payload,), kwargs) = authenticate.call_args
            self.assertEqual(method_name, auth_payload['protocol'])

    def test_mapped_with_remote_user(self):
        method_name = 'saml2'
        auth_data = {'methods': [method_name]}
        # put the method name in the payload so its easier to correlate
        # method name with payload
        auth_data[method_name] = {'protocol': method_name}
        auth_data = {'identity': auth_data}

        auth_context = auth.core.AuthContext(
            method_names=[],
            user_id=uuid.uuid4().hex)

        self.useFixture(auth_plugins.LoadAuthPlugins(method_name))

        with mock.patch.object(auth.plugins.mapped.Mapped,
                               'authenticate',
                               return_value=None) as authenticate:
            auth_info = auth.core.AuthInfo.create(auth_data)
            with self.make_request(environ={'REMOTE_USER': 'foo@idp.com'}):
                authentication.authenticate(auth_info, auth_context)
            # make sure Mapped plugin got invoked with the correct payload
            ((auth_payload,), kwargs) = authenticate.call_args
            self.assertEqual(method_name, auth_payload['protocol'])

    @mock.patch('keystone.auth.plugins.mapped.PROVIDERS')
    def test_mapped_without_identity_provider_or_protocol(self,
                                                          mock_providers):
        mock_providers.resource_api = mock.Mock()
        mock_providers.federation_api = mock.Mock()
        mock_providers.identity_api = mock.Mock()
        mock_providers.assignment_api = mock.Mock()
        mock_providers.role_api = mock.Mock()

        test_mapped = mapped.Mapped()

        auth_payload = {'identity_provider': 'test_provider'}
        with self.make_request():
            self.assertRaises(
                exception.ValidationError, test_mapped.authenticate,
                auth_payload)

        auth_payload = {'protocol': 'saml2'}
        with self.make_request():
            self.assertRaises(
                exception.ValidationError, test_mapped.authenticate,
                auth_payload)

    def test_supporting_multiple_methods(self):
        method_names = ('saml2', 'openid', 'x509', 'mapped')
        self.useFixture(auth_plugins.LoadAuthPlugins(*method_names))
        for method_name in method_names:
            self._test_mapped_invocation_with_method_name(method_name)
