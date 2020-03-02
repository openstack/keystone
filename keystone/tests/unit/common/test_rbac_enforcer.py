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

import fixtures
import flask
from flask import blueprints
import flask_restful
from oslo_policy import policy

from keystone.common import authorization
from keystone.common import context
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import rest


PROVIDER_APIS = provider_api.ProviderAPIs


class TestRBACEnforcer(unit.TestCase):

    def test_enforcer_shared_state(self):
        enforcer = rbac_enforcer.enforcer.RBACEnforcer()
        enforcer2 = rbac_enforcer.enforcer.RBACEnforcer()

        self.assertIsNotNone(enforcer._enforcer)
        self.assertEqual(enforcer._enforcer, enforcer2._enforcer)
        setattr(enforcer, '_test_attr', uuid.uuid4().hex)
        self.assertEqual(enforcer._test_attr, enforcer2._test_attr)

    def test_enforcer_auto_instantiated(self):
        enforcer = rbac_enforcer.enforcer.RBACEnforcer()
        # Check that the enforcer instantiates the oslo_policy enforcer object
        # on demand.
        self.assertIsNotNone(enforcer._enforcer)
        enforcer._reset()
        self.assertIsNotNone(enforcer._enforcer)


class _TestRBACEnforcerBase(rest.RestfulTestCase):

    def setUp(self):
        super(_TestRBACEnforcerBase, self).setUp()
        self._setup_enforcer_object()
        self._setup_dynamic_flask_blueprint_api()
        self._setup_flask_restful_api()

    def _setup_enforcer_object(self):
        self.enforcer = rbac_enforcer.enforcer.RBACEnforcer()
        self.cleanup_instance('enforcer')

        def register_new_rules(enforcer):
            rules = self._testing_policy_rules()
            enforcer.register_defaults(rules)

        self.useFixture(fixtures.MockPatchObject(
            self.enforcer, 'register_rules', register_new_rules))

        # Set the possible actions to our limited list
        original_actions = rbac_enforcer.enforcer._POSSIBLE_TARGET_ACTIONS
        rbac_enforcer.enforcer._POSSIBLE_TARGET_ACTIONS = frozenset([
            rule.name for rule in self._testing_policy_rules()])

        # RESET the FrozenSet of possible target actions to the original
        # value
        self.addCleanup(setattr,
                        rbac_enforcer.enforcer,
                        '_POSSIBLE_TARGET_ACTIONS',
                        original_actions)

        # Force a reset on the enforcer to load up new policy rules.
        self.enforcer._reset()

    def _setup_dynamic_flask_blueprint_api(self):
        # Create a dynamic flask blueprint with a known prefix
        api = uuid.uuid4().hex
        url_prefix = '/_%s_TEST' % api
        blueprint = blueprints.Blueprint(api, __name__, url_prefix=url_prefix)
        self.url_prefix = url_prefix
        self.flask_blueprint = blueprint
        self.cleanup_instance('flask_blueprint', 'url_prefix')

    def _driver_simulation_get_method(self, argument_id):
        user = self.user_req_admin
        return {'id': argument_id,
                'value': 'TEST',
                'owner_id': user['id']}

    def _setup_flask_restful_api(self):
        self.restful_api_url_prefix = '/_%s_TEST' % uuid.uuid4().hex
        self.restful_api = flask_restful.Api(self.public_app.app,
                                             self.restful_api_url_prefix)

        driver_simulation_method = self._driver_simulation_get_method

        # Very Basic Restful Resource
        class RestfulResource(flask_restful.Resource):

            def get(self, argument_id=None):
                if argument_id is not None:
                    return self._get_argument(argument_id)
                return self._list_arguments()

            def _get_argument(self, argument_id):
                return {'argument': driver_simulation_method(argument_id)}

            def _list_arguments(self):
                return {'arguments': []}

        self.restful_api_resource = RestfulResource
        self.restful_api.add_resource(
            RestfulResource, '/argument/<string:argument_id>', '/argument')
        self.cleanup_instance('restful_api', 'restful_resource',
                              'restful_api_url_prefix')

    def _register_blueprint_to_app(self):
        # TODO(morgan): remove the need for webtest, but for now just unwrap
        # by one layer. Once everything is converted to flask, we can fix
        # the tests to eliminate "webtest".
        self.public_app.app.register_blueprint(
            self.flask_blueprint, url_prefix=self.url_prefix)

    def _auth_json(self):
        return {
            'auth': {
                'identity': {
                    'methods': ['password'],
                    'password': {
                        'user': {
                            'name': self.user_req_admin['name'],
                            'password': self.user_req_admin['password'],
                            'domain': {
                                'id': self.user_req_admin['domain_id']
                            }
                        }
                    }
                },
                'scope': {
                    'project': {
                        'id': self.project_service['id']
                    }
                }
            }
        }

    def _testing_policy_rules(self):
        test_policy_rules = [
            policy.RuleDefault(
                name='example:subject_token',
                check_str='user_id:%(target.token.user_id)s',
                scope_types=['project'],
            ),
            policy.RuleDefault(
                name='example:target',
                check_str='user_id:%(target.myuser.id)s',
                scope_types=['project'],
            ),
            policy.RuleDefault(
                name='example:inferred_member_data',
                check_str='user_id:%(target.argument.owner_id)s',
                scope_types=['project'],
            ),
            policy.RuleDefault(
                name='example:with_filter',
                check_str='user_id:%(user)s',
                scope_types=['project'],
            ),
            policy.RuleDefault(
                name='example:allowed',
                check_str='',
                scope_types=['project'],
            ),
            policy.RuleDefault(
                name='example:denied',
                check_str='false:false',
                scope_types=['project'],
            ),
        ]
        return test_policy_rules


class TestRBACEnforcerRestAdminAuthToken(_TestRBACEnforcerBase):

    def config_overrides(self):
        super(TestRBACEnforcerRestAdminAuthToken, self).config_overrides()
        self.config_fixture.config(admin_token='ADMIN')

    def test_enforcer_is_admin_check_with_token(self):
        # Admin-shared token passed and valid, "is_admin" should be true.
        with self.test_client() as c:
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={authorization.AUTH_TOKEN_HEADER: 'ADMIN'})
            self.assertTrue(self.enforcer._shared_admin_auth_token_set())

    def test_enforcer_is_admin_check_without_token(self):
        with self.test_client() as c:
            # Admin-shared token passed and invalid, "is_admin" should be false
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={authorization.AUTH_TOKEN_HEADER: 'BOGUS'})
            self.assertFalse(self.enforcer._shared_admin_auth_token_set())

            # Admin-shared token not passed, "is_admin" should be false
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex))
            self.assertFalse(self.enforcer._shared_admin_auth_token_set())

    def test_enforce_call_is_admin(self):
        with self.test_client() as c:
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={authorization.AUTH_TOKEN_HEADER: 'ADMIN'})
            with mock.patch.object(self.enforcer, '_enforce') as mock_method:
                self.enforcer.enforce_call(action='example:allowed')
                mock_method.assert_not_called()


class TestRBACEnforcerRest(_TestRBACEnforcerBase):

    def test_extract_subject_token_target_data(self):
        path = '/v3/auth/tokens'
        body = self._auth_json()

        with self.test_client() as c:
            r = c.post(
                path,
                json=body,
                follow_redirects=True,
                expected_status_code=201)

            token_id = r.headers['X-Subject-Token']

            c.get('/v3', headers={'X-Auth-Token': token_id,
                                  'X-Subject-Token': token_id})
            token = PROVIDER_APIS.token_provider_api.validate_token(token_id)
            subj_token_data = (
                self.enforcer._extract_subject_token_target_data())
            subj_token_data = subj_token_data['token']
            self.assertEqual(token.user_id, subj_token_data['user_id'])
            self.assertIn('user', subj_token_data)
            self.assertIn('domain', subj_token_data['user'])
            self.assertEqual(token.user_domain['id'],
                             subj_token_data['user']['domain']['id'])

    def test_extract_filter_data(self):
        # Test that we are extracting useful filter data from the
        # request context. The tested function validates tha
        # extract_filter_attr only adds the passed filter values to the
        # policy dict, all other query-params are ignored.

        path = uuid.uuid4().hex

        @self.flask_blueprint.route('/%s' % path)
        def return_nothing_interesting():
            return 'OK', 200

        self._register_blueprint_to_app()

        with self.test_client() as c:
            expected_param = uuid.uuid4().hex
            unexpected_param = uuid.uuid4().hex
            get_path = '/'.join([self.url_prefix, path])
            # Populate the query-string with two params, one that should
            # exist and one that should not in the resulting policy
            # dict.
            qs = '%(expected)s=EXPECTED&%(unexpected)s=UNEXPECTED' % {
                'expected': expected_param,
                'unexpected': unexpected_param
            }
            # Perform the get with the query-string
            c.get('%(path)s?%(qs)s' % {'path': get_path, 'qs': qs})
            # Extract the filter values.
            extracted_filter = self.enforcer._extract_filter_values(
                [expected_param])
            # Unexpected param is not in the extracted values
            # Expected param is in the extracted values
            # Expected param has the expected value
            self.assertNotIn(extracted_filter, unexpected_param)
            self.assertIn(expected_param, expected_param)
            self.assertEqual(extracted_filter[expected_param], 'EXPECTED')

    def test_retrive_oslo_req_context(self):
        # Test to ensure 'get_oslo_req_context' is pulling the request context
        # from the environ as expected. The only way to really test is an
        # instance check.
        with self.test_client() as c:
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex))
            oslo_req_context = self.enforcer._get_oslo_req_context()
            self.assertIsInstance(oslo_req_context, context.RequestContext)

    def test_is_authenticated_check(self):
        # Check that the auth_context is in-fact decoded as expected.
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={'X-Auth-Token': token_id})
            self.enforcer._assert_is_authenticated()
            c.get('/', expected_status_code=300)
            self.assertRaises(exception.Unauthorized,
                              self.enforcer._assert_is_authenticated)
            oslo_ctx = self.enforcer._get_oslo_req_context()
            # Set authenticated to a false value that is not None
            oslo_ctx.authenticated = False
            self.assertRaises(exception.Unauthorized,
                              self.enforcer._assert_is_authenticated)

    def test_extract_policy_check_credentials(self):
        # Make sure extracting the creds is the same as what is in the request
        # environment.
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={'X-Auth-Token': token_id})
            extracted_creds = self.enforcer._extract_policy_check_credentials()
            self.assertEqual(
                flask.request.environ.get(authorization.AUTH_CONTEXT_ENV),
                extracted_creds)

    def test_extract_member_target_data_inferred(self):
        # NOTE(morgan): Setup the "resource" object with a 'member_name' attr
        # and the 'get_member_from_driver' binding to the 'get' method. The
        # enforcer here will look for 'get_member_from_driver' (callable) and
        # the 'member_name' (e.g. 'user') so it can automatically populate
        # the target dict with the member information. This is mostly compat
        # with current @protected (ease of use). For most cases the target
        # should be explicitly passed to .enforce_call, but for ease of
        # converting / use, the automatic population of data has been added.
        self.restful_api_resource.member_key = 'argument'
        member_from_driver = self._driver_simulation_get_method
        self.restful_api_resource.get_member_from_driver = member_from_driver

        argument_id = uuid.uuid4().hex

        with self.test_client() as c:
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      argument_id))
            extracted = self.enforcer._extract_member_target_data(
                member_target_type=None, member_target=None)
            self.assertDictEqual(extracted['target'],
                                 self.restful_api_resource().get(argument_id))

    def test_view_args_populated_in_policy_dict(self):
        # Setup the "resource" object and make a call that has view arguments
        # (substituted values in the URL). Make sure to use an policy enforcer
        # that properly checks (substitutes in) a value that is not in "target"
        # path but in the main policy dict path.

        def _enforce_mock_func(credentials, action, target,
                               do_raise=True):
            if 'argument_id' not in target:
                raise exception.ForbiddenAction(action=action)

        self.useFixture(fixtures.MockPatchObject(
            self.enforcer, '_enforce', _enforce_mock_func))

        argument_id = uuid.uuid4().hex

        # Check with a call that will populate view_args.

        with self.test_client() as c:
            path = '/v3/auth/tokens'
            body = self._auth_json()

            r = c.post(
                path,
                json=body,
                follow_redirects=True,
                expected_status_code=201)

            token_id = r.headers['X-Subject-Token']

            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      argument_id),
                  headers={'X-Auth-Token': token_id})

            # Use any valid policy as _enforce is mockpatched out
            self.enforcer.enforce_call(action='example:allowed')
            c.get('%s/argument' % self.restful_api_url_prefix,
                  headers={'X-Auth-Token': token_id})
            self.assertRaises(exception.ForbiddenAction,
                              self.enforcer.enforce_call,
                              action='example:allowed')

    def test_extract_member_target_data_supplied_target(self):
        # Test extract member target data with member_target and
        # member_target_type supplied.
        member_type = uuid.uuid4().hex
        member_target = {uuid.uuid4().hex: {uuid.uuid4().hex}}
        extracted = self.enforcer._extract_member_target_data(
            member_target_type=member_type, member_target=member_target)
        self.assertDictEqual({'target': {member_type: member_target}},
                             extracted)

    def test_extract_member_target_data_bad_input(self):
        # Test Extract Member Target Data with only "member_target" and only
        # "member_target_type" and ensure empty dict is returned.
        self.assertEqual({}, self.enforcer._extract_member_target_data(
            member_target=None, member_target_type=uuid.uuid4().hex))
        self.assertEqual({}, self.enforcer._extract_member_target_data(
            member_target={}, member_target_type=None))

    def test_call_build_enforcement_target(self):
        assertIn = self.assertIn
        assertEq = self.assertEqual
        ref_uuid = uuid.uuid4().hex

        def _enforce_mock_func(credentials, action, target,
                               do_raise=True):
            assertIn('target.domain.id', target)
            assertEq(target['target.domain.id'], ref_uuid)

        def _build_enforcement_target():
            return {'domain': {'id': ref_uuid}}

        self.useFixture(fixtures.MockPatchObject(
            self.enforcer, '_enforce', _enforce_mock_func))

        argument_id = uuid.uuid4().hex

        with self.test_client() as c:
            path = '/v3/auth/tokens'
            body = self._auth_json()

            r = c.post(
                path,
                json=body,
                follow_redirects=True,
                expected_status_code=201)

            token_id = r.headers['X-Subject-Token']

            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      argument_id),
                  headers={'X-Auth-Token': token_id})
            self.enforcer.enforce_call(
                action='example:allowed',
                build_target=_build_enforcement_target)

    def test_policy_enforcer_action_decorator(self):
        # Create a method that has an action pre-registered
        action = 'example:allowed'

        @self.flask_blueprint.route('')
        @self.enforcer.policy_enforcer_action(action)
        def nothing_interesting():
            return 'OK', 200

        self._register_blueprint_to_app()

        with self.test_client() as c:
            c.get('%s' % self.url_prefix)
            self.assertEqual(
                action, getattr(flask.g, self.enforcer.ACTION_STORE_ATTR))

    def test_policy_enforcer_action_invalid_action_decorator(self):
        # If the "action" is not a registered policy enforcement point, check
        # that a ValueError is raised.
        def _decorator_fails():
            # Create a method that has an action pre-registered, but the
            # action is bogus
            action = uuid.uuid4().hex

            @self.flask_blueprint.route('')
            @self.enforcer.policy_enforcer_action(action)
            def nothing_interesting():
                return 'OK', 200

        self.assertRaises(ValueError, _decorator_fails)

    def test_enforce_call_invalid_action(self):
        self.assertRaises(exception.Forbidden,
                          self.enforcer.enforce_call,
                          action=uuid.uuid4().hex)

    def test_enforce_call_not_is_authenticated(self):
        with self.test_client() as c:
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex))
            # Patch the enforcer to return an empty oslo context.
            with mock.patch.object(self.enforcer, '_get_oslo_req_context',
                                   return_value=None):
                self.assertRaises(
                    exception.Unauthorized,
                    self.enforcer.enforce_call, action='example:allowed')

            # Explicitly set "authenticated" on the context to false.
            ctx = self.enforcer._get_oslo_req_context()
            ctx.authenticated = False
            self.assertRaises(
                exception.Unauthorized,
                self.enforcer.enforce_call, action='example:allowed')

    def test_enforce_call_explicit_target_attr(self):
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            # check the enforcer properly handles explicitly passed in targets
            # no subject-token processing is done in this case.
            #
            # TODO(morgan): confirm if subject-token-processing can/should
            # occur in this form without causing issues.
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={'X-Auth-Token': token_id,
                           'X-Subject-Token': token_id})
            target = {'myuser': {'id': self.user_req_admin['id']}}
            self.enforcer.enforce_call(action='example:target',
                                       target_attr=target)
            # Ensure extracting the subject-token data is not happening.
            self.assertRaises(
                exception.ForbiddenAction,
                self.enforcer.enforce_call,
                action='example:subject_token',
                target_attr=target)

    def test_enforce_call_with_subject_token_data(self):
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            # Check that the enforcer passes if user_id and subject token
            # user_id are the same. example:deprecated should also pass
            # since it is open enforcement.
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={'X-Auth-Token': token_id,
                           'X-Subject-Token': token_id})
            self.enforcer.enforce_call(action='example:subject_token')

    def test_enforce_call_with_member_target_type_and_member_target(self):
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            # check the enforcer properly handles passed in member_target_type
            # and member_target. This form still extracts data from the subject
            # token.
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={'X-Auth-Token': token_id,
                           'X-Subject-Token': token_id})
            target_type = 'myuser'
            target = {'id': self.user_req_admin['id']}
            self.enforcer.enforce_call(action='example:target',
                                       member_target_type=target_type,
                                       member_target=target)
            # Ensure we're still extracting the subject-token data
            self.enforcer.enforce_call(action='example:subject_token')

    def test_enforce_call_inferred_member_target_data(self):
        # Check that inferred "get" works as expected for the member target

        # setup the restful resource for an inferred "get"
        self.restful_api_resource.member_key = 'argument'
        member_from_driver = self._driver_simulation_get_method
        self.restful_api_resource.get_member_from_driver = member_from_driver

        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            # check the enforcer properly handles inferred member data get
            # This form still extracts data from the subject token.
            c.get('%s/argument/%s' % (self.restful_api_url_prefix,
                                      uuid.uuid4().hex),
                  headers={'X-Auth-Token': token_id,
                           'X-Subject-Token': token_id})
            self.enforcer.enforce_call(action='example:inferred_member_data')
            # Ensure we're still extracting the subject-token data
            self.enforcer.enforce_call(action='example:subject_token')

    def test_enforce_call_with_filter_values(self):
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            # Check that the enforcer passes if a filter is supplied *and*
            # the filter name is passed to enforce_call
            c.get('%s/argument/%s?user=%s' % (
                self.restful_api_url_prefix, uuid.uuid4().hex,
                self.user_req_admin['id']),
                headers={'X-Auth-Token': token_id})
            self.enforcer.enforce_call(action='example:with_filter',
                                       filters=['user'])

            # With No Filters passed into enforce_call
            self.assertRaises(
                exception.ForbiddenAction,
                self.enforcer.enforce_call,
                action='example:with_filter')

            # With No Filters in the PATH
            c.get('%s/argument/%s' % (
                self.restful_api_url_prefix, uuid.uuid4().hex),
                headers={'X-Auth-Token': token_id})
            self.assertRaises(
                exception.ForbiddenAction,
                self.enforcer.enforce_call,
                action='example:with_filter',
                filters=['user'])

            # With no filters in the path and no filters passed to enforce_call
            c.get('%s/argument/%s' % (
                self.restful_api_url_prefix, uuid.uuid4().hex),
                headers={'X-Auth-Token': token_id})
            self.assertRaises(
                exception.ForbiddenAction,
                self.enforcer.enforce_call,
                action='example:with_filter')

    def test_enforce_call_with_pre_instantiated_enforcer(self):
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        enforcer = rbac_enforcer.enforcer.RBACEnforcer()
        with self.test_client() as c:
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            # Check the enforcer behaves as expected with a pre-instantiated
            # enforcer passed into .enforce_call()
            c.get('%s/argument/%s' % (
                self.restful_api_url_prefix, uuid.uuid4().hex),
                headers={'X-Auth-Token': token_id})
            self.enforcer.enforce_call(action='example:allowed',
                                       enforcer=enforcer)
            self.assertRaises(exception.ForbiddenAction,
                              self.enforcer.enforce_call,
                              action='example:denied',
                              enforcer=enforcer)

    def test_enforce_call_sets_enforcement_attr(self):
        # Ensure calls to enforce_call set the value on flask.g that indicates
        # enforce_call has actually been called
        token_path = '/v3/auth/tokens'
        auth_json = self._auth_json()
        with self.test_client() as c:
            # setup/initial call. Note that the request must hit the flask
            # app to have access to g (without an explicit app-context push)
            r = c.post(token_path, json=auth_json, expected_status_code=201)
            token_id = r.headers.get('X-Subject-Token')
            c.get('%s/argument/%s' % (
                self.restful_api_url_prefix, uuid.uuid4().hex),
                headers={'X-Auth-Token': token_id})

            # Ensure the attribute is not set
            self.assertFalse(
                hasattr(
                    flask.g, rbac_enforcer.enforcer._ENFORCEMENT_CHECK_ATTR)
            )
            # Set the value to false, like the resource have done automatically
            setattr(
                flask.g, rbac_enforcer.enforcer._ENFORCEMENT_CHECK_ATTR, False)
            # Enforce
            self.enforcer.enforce_call(action='example:allowed')
            # Verify the attribute has been set to true.
            self.assertEqual(
                getattr(flask.g,
                        rbac_enforcer.enforcer._ENFORCEMENT_CHECK_ATTR),
                True)
            # Reset Attribute and check that attribute is still set even if
            # enforcement results in forbidden.
            setattr(
                flask.g, rbac_enforcer.enforcer._ENFORCEMENT_CHECK_ATTR, False)
            self.assertRaises(exception.ForbiddenAction,
                              self.enforcer.enforce_call,
                              action='example:denied')
            self.assertEqual(
                getattr(flask.g,
                        rbac_enforcer.enforcer._ENFORCEMENT_CHECK_ATTR),
                True)
