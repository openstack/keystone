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

from keystone import auth
from keystone.common import config
from keystone import exception
from keystone import tests


# for testing purposes only
METHOD_NAME = 'simple_challenge_response'
EXPECTED_RESPONSE = uuid.uuid4().hex
DEMO_USER_ID = uuid.uuid4().hex


class SimpleChallengeResponse(auth.AuthMethodHandler):

    method = METHOD_NAME

    def authenticate(self, context, auth_payload, user_context):
        if 'response' in auth_payload:
            if auth_payload['response'] != EXPECTED_RESPONSE:
                raise exception.Unauthorized('Wrong answer')
            user_context['user_id'] = DEMO_USER_ID
        else:
            return {"challenge": "What's the name of your high school?"}


class DuplicateAuthPlugin(SimpleChallengeResponse):
    """Duplicate simple challenge response auth plugin."""


class MismatchedAuthPlugin(SimpleChallengeResponse):
    method = uuid.uuid4().hex


class NoMethodAuthPlugin(auth.AuthMethodHandler):
    """An auth plugin that does not supply a method attribute."""
    def authenticate(self, context, auth_payload, auth_context):
        pass


class TestAuthPlugin(tests.SQLDriverOverrides, tests.TestCase):
    def setUp(self):
        super(TestAuthPlugin, self).setUp()
        self.load_backends()

        self.api = auth.controllers.Auth()

    def config_files(self):
        config_files = super(TestAuthPlugin, self).config_files()
        config_files.append(tests.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files

    def config_overrides(self):
        super(TestAuthPlugin, self).config_overrides()
        self.config_fixture.config(
            group='auth',
            methods=[
                'keystone.auth.plugins.external.DefaultDomain',
                'keystone.auth.plugins.password.Password',
                'keystone.auth.plugins.token.Token',
                'keystone.tests.test_auth_plugin.SimpleChallengeResponse'])

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
            self.assertTrue('methods' in e.authentication)
            self.assertTrue(METHOD_NAME in e.authentication['methods'])
            self.assertTrue(METHOD_NAME in e.authentication)
            self.assertTrue('challenge' in e.authentication[METHOD_NAME])

        # test correct response
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'response': EXPECTED_RESPONSE}
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo.create(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.api.authenticate({'environment': {}}, auth_info, auth_context)
        self.assertEqual(auth_context['user_id'], DEMO_USER_ID)

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


class TestAuthPluginDynamicOptions(TestAuthPlugin):
    def config_overrides(self):
        super(TestAuthPluginDynamicOptions, self).config_overrides()
        # Clear the override for the [auth] ``methods`` option so it is
        # possible to load the options from the config file.
        self.config_fixture.conf.clear_override('methods', group='auth')

    def config_files(self):
        config_files = super(TestAuthPluginDynamicOptions, self).config_files()
        config_files.append(tests.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files


class TestInvalidAuthMethodRegistration(tests.TestCase):
    def test_duplicate_auth_method_registration(self):
        self.config_fixture.config(
            group='auth',
            methods=[
                'keystone.tests.test_auth_plugin.SimpleChallengeResponse',
                'keystone.tests.test_auth_plugin.DuplicateAuthPlugin'])
        self.clear_auth_plugin_registry()
        self.assertRaises(ValueError, auth.controllers.load_auth_methods)

    def test_no_method_attribute_auth_method_by_class_name_registration(self):
        self.config_fixture.config(
            group='auth',
            methods=['keystone.tests.test_auth_plugin.NoMethodAuthPlugin'])
        self.clear_auth_plugin_registry()
        self.assertRaises(ValueError, auth.controllers.load_auth_methods)

    def test_mismatched_auth_method_and_plugin_attribute(self):
        test_opt = config.cfg.StrOpt('test')

        def clear_and_unregister_opt():
            # NOTE(morganfainberg): Reset is required before unregistering
            # arguments or ArgsAlreadyParsedError is raised.
            config.CONF.reset()
            config.CONF.unregister_opt(test_opt, 'auth')

        self.addCleanup(clear_and_unregister_opt)

        # Guarantee we register the option we expect to unregister in cleanup
        config.CONF.register_opt(test_opt, 'auth')

        self.config_fixture.config(group='auth', methods=['test'])
        self.config_fixture.config(
            group='auth',
            test='keystone.tests.test_auth_plugin.MismatchedAuthPlugin')

        self.clear_auth_plugin_registry()
        self.assertRaises(ValueError, auth.controllers.load_auth_methods)
