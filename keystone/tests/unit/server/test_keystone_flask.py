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

import fixtures
import flask
import flask_restful
import functools
from oslo_policy import policy
from oslo_serialization import jsonutils
from testtools import matchers

from keystone.common import context
from keystone.common import json_home
from keystone.common import rbac_enforcer
import keystone.conf
from keystone import exception
from keystone.server.flask import common as flask_common
from keystone.server.flask.request_processing import json_body
from keystone.tests.unit import rest


CONF = keystone.conf.CONF


class _TestResourceWithCollectionInfo(flask_common.ResourceBase):
    collection_key = 'arguments'
    member_key = 'argument'
    __shared_state__ = {}
    _storage_dict = {}

    def __init__(self):
        super(_TestResourceWithCollectionInfo, self).__init__()
        # Share State, this is for "dummy" backend storage.
        self.__dict__ = self.__shared_state__

    @classmethod
    def _reset(cls):
        # Used after a test to ensure clean-state
        cls._storage_dict.clear()
        cls.__shared_state__.clear()

    def _list_arguments(self):
        return self.wrap_collection(list(self._storage_dict.values()))

    def get(self, argument_id=None):
        # List with no argument, get resource with id, used for HEAD as well.
        rbac_enforcer.enforcer.RBACEnforcer.enforce_call(
            action='example:allowed')
        if argument_id is None:
            # List
            return self._list_arguments()
        else:
            # get resource with id
            try:
                return self.wrap_member(self._storage_dict[argument_id])
            except KeyError:
                raise exception.NotFound(target=argument_id)

    def post(self):
        rbac_enforcer.enforcer.RBACEnforcer.enforce_call(
            action='example:allowed')
        ref = flask.request.get_json(force=True)
        ref = self._assign_unique_id(ref)
        self._storage_dict[ref['id']] = ref
        return self.wrap_member(self._storage_dict[ref['id']]), 201

    def put(self, argument_id):
        rbac_enforcer.enforcer.RBACEnforcer.enforce_call(
            action='example:allowed')
        try:
            self._storage_dict[argument_id]
        except KeyError:
            raise exception.NotFound(target=argument_id)
        ref = flask.request.get_json(force=True)
        self._require_matching_id(ref)
        # Maintain the ref id
        ref['id'] = argument_id
        self._storage_dict[argument_id] = ref
        return '', 204

    def patch(self, argument_id):
        rbac_enforcer.enforcer.RBACEnforcer.enforce_call(
            action='example:allowed')
        try:
            self._storage_dict[argument_id]
        except KeyError:
            raise exception.NotFound(target=argument_id)
        ref = flask.request.get_json(force=True)
        self._require_matching_id(ref)
        self._storage_dict[argument_id].update(ref)
        return self.wrap_member(self._storage_dict[argument_id])

    def delete(self, argument_id):
        rbac_enforcer.enforcer.RBACEnforcer.enforce_call(
            action='example:allowed')
        try:
            del self._storage_dict[argument_id]
        except KeyError:
            raise exception.NotFound(target=argument_id)
        return '', 204


class _TestRestfulAPI(flask_common.APIBase):
    _name = 'test_api_base'
    _import_name = __name__
    resources = []
    resource_mapping = []

    def __init__(self, *args, **kwargs):
        self.resource_mapping = kwargs.pop('resource_mapping', [])
        self.resources = kwargs.pop('resources',
                                    [_TestResourceWithCollectionInfo])
        super(_TestRestfulAPI, self).__init__(*args, **kwargs)


class TestKeystoneFlaskCommon(rest.RestfulTestCase):

    _policy_rules = [
        policy.RuleDefault(
            name='example:allowed',
            check_str=''
        ),
        policy.RuleDefault(
            name='example:deny',
            check_str='false:false'
        )
    ]

    def setUp(self):
        super(TestKeystoneFlaskCommon, self).setUp()
        enf = rbac_enforcer.enforcer.RBACEnforcer()

        def register_rules(enf_obj):
            enf_obj.register_defaults(self._policy_rules)

        self.useFixture(fixtures.MockPatchObject(
            enf, 'register_rules', register_rules))
        self.useFixture(fixtures.MockPatchObject(
            rbac_enforcer.enforcer, '_POSSIBLE_TARGET_ACTIONS',
            {r.name for r in self._policy_rules}))

        enf._reset()
        self.addCleanup(enf._reset)
        self.addCleanup(
            _TestResourceWithCollectionInfo._reset)

    def _get_token(self):
        auth_json = {
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
        return self.test_client().post(
            '/v3/auth/tokens',
            json=auth_json,
            expected_status_code=201).headers['X-Subject-Token']

    def _setup_flask_restful_api(self, **options):

        self.restful_api_opts = options.copy()
        orig_value = _TestResourceWithCollectionInfo.api_prefix
        setattr(_TestResourceWithCollectionInfo,
                'api_prefix', options.get('api_url_prefix', ''))
        self.addCleanup(setattr, _TestResourceWithCollectionInfo, 'api_prefix',
                        orig_value)
        self.restful_api = _TestRestfulAPI(**options)
        self.public_app.app.register_blueprint(self.restful_api.blueprint)
        self.cleanup_instance('restful_api')
        self.cleanup_instance('restful_api_opts')

    def _make_requests(self):
        path_base = '/arguments'
        api_prefix = self.restful_api_opts.get('api_url_prefix', '')
        blueprint_prefix = self.restful_api._blueprint_url_prefix.rstrip('/')
        url = ''.join(
            [x for x in [blueprint_prefix, api_prefix, path_base] if x])
        headers = {'X-Auth-Token': self._get_token()}
        with self.test_client() as c:
            # GET LIST
            resp = c.get(url, headers=headers)
            self.assertEqual(
                _TestResourceWithCollectionInfo.wrap_collection(
                    []), resp.json)
            unknown_id = uuid.uuid4().hex

            # GET non-existent ref
            c.get('%s/%s' % (url, unknown_id), headers=headers,
                  expected_status_code=404)

            # HEAD non-existent ref
            c.head('%s/%s' % (url, unknown_id), headers=headers,
                   expected_status_code=404)

            # PUT non-existent ref
            c.put('%s/%s' % (url, unknown_id), json={}, headers=headers,
                  expected_status_code=404)

            # PATCH non-existent ref
            c.patch('%s/%s' % (url, unknown_id), json={}, headers=headers,
                    expected_status_code=404)

            # DELETE non-existent ref
            c.delete('%s/%s' % (url, unknown_id), headers=headers,
                     expected_status_code=404)

            # POST new ref
            new_argument_resource = {'testing': uuid.uuid4().hex}
            new_argument_resp = c.post(
                url,
                json=new_argument_resource,
                headers=headers).json['argument']

            # POST second new ref
            new_argument2_resource = {'testing': uuid.uuid4().hex}
            new_argument2_resp = c.post(
                url,
                json=new_argument2_resource,
                headers=headers).json['argument']

            # GET list
            get_list_resp = c.get(url, headers=headers).json
            self.assertIn(new_argument_resp,
                          get_list_resp['arguments'])
            self.assertIn(new_argument2_resp,
                          get_list_resp['arguments'])

            # GET first ref
            get_resp = c.get('%s/%s' % (url, new_argument_resp['id']),
                             headers=headers).json['argument']
            self.assertEqual(new_argument_resp, get_resp)

            # HEAD first ref
            head_resp = c.head(
                '%s/%s' % (url, new_argument_resp['id']),
                headers=headers).data
            # NOTE(morgan): For python3 compat, explicitly binary type
            self.assertEqual(head_resp, b'')

            # PUT update first ref
            replacement_argument = {'new_arg': True, 'id': uuid.uuid4().hex}
            c.put('%s/%s' % (url, new_argument_resp['id']), headers=headers,
                  json=replacement_argument, expected_status_code=400)
            replacement_argument.pop('id')
            c.put('%s/%s' % (url, new_argument_resp['id']),
                  headers=headers,
                  json=replacement_argument)
            put_resp = c.get('%s/%s' % (url, new_argument_resp['id']),
                             headers=headers).json['argument']
            self.assertNotIn(new_argument_resp['testing'],
                             put_resp)
            self.assertTrue(put_resp['new_arg'])

            # GET first ref (check for replacement)
            get_replacement_resp = c.get(
                '%s/%s' % (url, new_argument_resp['id']),
                headers=headers).json['argument']
            self.assertEqual(put_resp,
                             get_replacement_resp)

            # PATCH update first ref
            patch_ref = {'uuid': uuid.uuid4().hex}
            patch_resp = c.patch('%s/%s' % (url, new_argument_resp['id']),
                                 headers=headers,
                                 json=patch_ref).json['argument']
            self.assertTrue(patch_resp['new_arg'])
            self.assertEqual(patch_ref['uuid'], patch_resp['uuid'])

            # GET first ref (check for update)
            get_patched_ref_resp = c.get(
                '%s/%s' % (url, new_argument_resp['id']),
                headers=headers).json['argument']
            self.assertEqual(patch_resp,
                             get_patched_ref_resp)

            # DELETE first ref
            c.delete(
                '%s/%s' % (url, new_argument_resp['id']),
                headers=headers)
            # Check that it was in-fact deleted
            c.get(
                '%s/%s' % (url, new_argument_resp['id']),
                headers=headers, expected_status_code=404)

    def test_api_url_prefix(self):
        url_prefix = '/%s' % uuid.uuid4().hex
        self._setup_flask_restful_api(
            api_url_prefix=url_prefix)
        self._make_requests()

    def test_blueprint_url_prefix(self):
        url_prefix = '/%s' % uuid.uuid4().hex
        self._setup_flask_restful_api(
            blueprint_url_prefix=url_prefix)
        self._make_requests()

    def test_build_restful_api_no_prefix(self):
        self._setup_flask_restful_api()
        self._make_requests()

    def test_cannot_add_before_request_functions_twice(self):

        class TestAPIDuplicateBefore(_TestRestfulAPI):
            def __init__(self):
                super(TestAPIDuplicateBefore, self).__init__()
                self._register_before_request_functions()

        self.assertRaises(AssertionError, TestAPIDuplicateBefore)

    def test_cannot_add_after_request_functions_twice(self):

        class TestAPIDuplicateAfter(_TestRestfulAPI):
            def __init__(self):
                super(TestAPIDuplicateAfter, self).__init__()
                self._register_after_request_functions()

        self.assertRaises(AssertionError, TestAPIDuplicateAfter)

    def test_after_request_functions_must_be_added(self):

        class TestAPINoAfter(_TestRestfulAPI):
            def _register_after_request_functions(self, functions=None):
                pass

        self.assertRaises(AssertionError, TestAPINoAfter)

    def test_before_request_functions_must_be_added(self):

        class TestAPINoBefore(_TestRestfulAPI):
            def _register_before_request_functions(self, functions=None):
                pass

        self.assertRaises(AssertionError, TestAPINoBefore)

    def test_before_request_functions(self):
        # Test additional "before" request functions fire.
        attr = uuid.uuid4().hex

        def do_something():
            setattr(flask.g, attr, True)

        class TestAPI(_TestRestfulAPI):
            def _register_before_request_functions(self, functions=None):
                functions = functions or []
                functions.append(do_something)
                super(TestAPI, self)._register_before_request_functions(
                    functions)

        api = TestAPI(resources=[_TestResourceWithCollectionInfo])
        self.public_app.app.register_blueprint(api.blueprint)
        token = self._get_token()
        with self.test_client() as c:
            c.get('/v3/arguments', headers={'X-Auth-Token': token})
            self.assertTrue(getattr(flask.g, attr, False))

    def test_after_request_functions(self):
        # Test additional "after" request functions fire. In this case, we
        # alter the response code to 420
        attr = uuid.uuid4().hex

        def do_something(resp):
            setattr(flask.g, attr, True)
            resp.status_code = 420
            return resp

        class TestAPI(_TestRestfulAPI):
            def _register_after_request_functions(self, functions=None):
                functions = functions or []
                functions.append(do_something)
                super(TestAPI, self)._register_after_request_functions(
                    functions)

        api = TestAPI(resources=[_TestResourceWithCollectionInfo])
        self.public_app.app.register_blueprint(api.blueprint)
        token = self._get_token()
        with self.test_client() as c:
            c.get('/v3/arguments', headers={'X-Auth-Token': token},
                  expected_status_code=420)

    def test_construct_resource_map(self):
        resource_name = 'arguments'
        param_relation = json_home.build_v3_parameter_relation(
            'argument_id')
        alt_rel_func = functools.partial(
            json_home.build_v3_extension_resource_relation,
            extension_name='extension', extension_version='1.0')
        url = '/v3/arguments/<string:argument_id>'
        old_url = [dict(
            url='/v3/old_arguments/<string:argument_id>',
            json_home=flask_common.construct_json_home_data(
                rel='arguments',
                resource_relation_func=alt_rel_func)
        )]

        mapping = flask_common.construct_resource_map(
            resource=_TestResourceWithCollectionInfo,
            url=url,
            resource_kwargs={},
            alternate_urls=old_url,
            rel=resource_name,
            status=json_home.Status.EXPERIMENTAL,
            path_vars={'argument_id': param_relation},
            resource_relation_func=json_home.build_v3_resource_relation)
        self.assertEqual(_TestResourceWithCollectionInfo,
                         mapping.resource)
        self.assertEqual(url, mapping.url)
        self.assertEqual(json_home.build_v3_resource_relation(resource_name),
                         mapping.json_home_data.rel)
        self.assertEqual(json_home.Status.EXPERIMENTAL,
                         mapping.json_home_data.status)
        self.assertEqual({'argument_id': param_relation},
                         mapping.json_home_data.path_vars)
        # Check the alternate URL data is populated sanely
        self.assertEqual(1, len(mapping.alternate_urls))
        alt_url_data = mapping.alternate_urls[0]
        self.assertEqual(old_url[0]['url'], alt_url_data['url'])
        self.assertEqual(old_url[0]['json_home'], alt_url_data['json_home'])

    def test_instantiate_and_register_to_app(self):
        # Test that automatic instantiation and registration to app works.
        self.restful_api_opts = {}
        self.restful_api = _TestRestfulAPI.instantiate_and_register_to_app(
            self.public_app.app)
        self.cleanup_instance('restful_api_opts')
        self.cleanup_instance('restful_api')
        self._make_requests()

    def test_unenforced_api_decorator(self):
        # Test unenforced decorator works as expected

        class MappedResource(flask_restful.Resource):
            @flask_common.unenforced_api
            def post(self):
                post_body = flask.request.get_json()
                return {'post_body': post_body}, 201

        resource_map = flask_common.construct_resource_map(
            resource=MappedResource,
            url='test_api',
            alternate_urls=[],
            resource_kwargs={},
            rel='test',
            status=json_home.Status.STABLE,
            path_vars=None,
            resource_relation_func=json_home.build_v3_resource_relation)

        restful_api = _TestRestfulAPI(resource_mapping=[resource_map],
                                      resources=[])
        self.public_app.app.register_blueprint(restful_api.blueprint)
        token = self._get_token()
        with self.test_client() as c:
            body = {'test_value': uuid.uuid4().hex}
            # Works with token
            resp = c.post('/v3/test_api', json=body,
                          headers={'X-Auth-Token': token})
            self.assertEqual(body, resp.json['post_body'])
            # Works without token
            resp = c.post('/v3/test_api', json=body)
            self.assertEqual(body, resp.json['post_body'])

    def test_HTTP_OPTIONS_is_unenforced(self):
        # Standup a test mapped resource and call OPTIONS on it. This will
        # return a header "Allow" with the valid methods, in this case
        # OPTIONS and POST. Ensure that the response otherwise conforms
        # as expected.

        class MappedResource(flask_restful.Resource):
            def post(self):
                # we don't actually use this or call it.
                pass

        resource_map = flask_common.construct_resource_map(
            resource=MappedResource,
            url='test_api',
            alternate_urls=[],
            resource_kwargs={},
            rel='test',
            status=json_home.Status.STABLE,
            path_vars=None,
            resource_relation_func=json_home.build_v3_resource_relation)

        restful_api = _TestRestfulAPI(resource_mapping=[resource_map],
                                      resources=[])
        self.public_app.app.register_blueprint(restful_api.blueprint)
        with self.test_client() as c:
            r = c.options('/v3/test_api')
            # make sure we split the data and left/right strip off whitespace
            # The use of a SET here is to ensure the exact values are in place
            # even if hash-seeds change order. `r.data` will be an empty
            # byte-string. `Content-Length` will be 0.
            self.assertEqual(
                set(['OPTIONS', 'POST']),
                set([v.lstrip().rstrip()
                     for v in r.headers['Allow'].split(',')]))
            self.assertEqual(r.headers['Content-Length'], '0')
            self.assertEqual(r.data, b'')

    def test_mapped_resource_routes(self):
        # Test non-standard URL routes ("mapped") function as expected

        class MappedResource(flask_restful.Resource):
            def post(self):
                rbac_enforcer.enforcer.RBACEnforcer().enforce_call(
                    action='example:allowed')
                post_body = flask.request.get_json()
                return {'post_body': post_body}, 201

        resource_map = flask_common.construct_resource_map(
            resource=MappedResource,
            url='test_api',
            alternate_urls=[],
            resource_kwargs={},
            rel='test',
            status=json_home.Status.STABLE,
            path_vars=None,
            resource_relation_func=json_home.build_v3_resource_relation)

        restful_api = _TestRestfulAPI(resource_mapping=[resource_map],
                                      resources=[])
        self.public_app.app.register_blueprint(restful_api.blueprint)
        token = self._get_token()
        with self.test_client() as c:
            body = {'test_value': uuid.uuid4().hex}
            resp = c.post('/v3/test_api', json=body,
                          headers={'X-Auth-Token': token})
            self.assertEqual(body, resp.json['post_body'])

    def test_correct_json_home_document(self):
        class MappedResource(flask_restful.Resource):
            def post(self):
                rbac_enforcer.enforcer.RBACEnforcer().enforce_call(
                    action='example:allowed')
                post_body = flask.request.get_json()
                return {'post_body': post_body}

        # NOTE(morgan): totally fabricated json_home data based upon our TEST
        # restful_apis.
        json_home_data = {
            'https://docs.openstack.org/api/openstack-identity/3/'
            'rel/argument': {
                'href-template': '/v3/arguments/{argument_id}',
                'href-vars': {
                    'argument_id': 'https://docs.openstack.org/api/'
                                   'openstack-identity/3/param/argument_id'
                }
            },
            'https://docs.openstack.org/api/openstack-identity/3/'
            'rel/arguments': {
                'href': '/v3/arguments'
            },
            'https://docs.openstack.org/api/openstack-identity/3/'
            'rel/test': {
                'href': '/v3/test_api'
            },
        }

        resource_map = flask_common.construct_resource_map(
            resource=MappedResource,
            url='test_api',
            alternate_urls=[],
            resource_kwargs={},
            rel='test',
            status=json_home.Status.STABLE,
            path_vars=None,
            resource_relation_func=json_home.build_v3_resource_relation)

        restful_api = _TestRestfulAPI(resource_mapping=[resource_map])
        self.public_app.app.register_blueprint(restful_api.blueprint)

        with self.test_client() as c:
            headers = {'Accept': 'application/json-home'}
            resp = c.get('/', headers=headers)
            resp_data = jsonutils.loads(resp.data)
            for rel in json_home_data:
                self.assertThat(resp_data['resources'][rel],
                                matchers.Equals(json_home_data[rel]))

    def test_normalize_domain_id_extracts_domain_id_if_needed(self):
        self._setup_flask_restful_api()
        blueprint_prefix = self.restful_api._blueprint_url_prefix.rstrip('/')
        url = ''.join([blueprint_prefix, '/arguments'])
        headers = {'X-Auth-Token': self._get_token()}
        ref_with_domain_id = {'domain_id': uuid.uuid4().hex}
        ref_without_domain_id = {}
        with self.test_client() as c:
            # Make a dummy request.. ANY request is fine to push the whole
            # context stack.
            c.get('%s/%s' % (url, uuid.uuid4().hex), headers=headers,
                  expected_status_code=404)

            oslo_context = flask.request.environ[
                context.REQUEST_CONTEXT_ENV]

            # Normal Project Scope Form
            # ---------------------------
            # test that _normalize_domain_id does something sane
            domain_id = ref_with_domain_id['domain_id']
            # Ensure we don't change the domain if it is specified
            flask_common.ResourceBase._normalize_domain_id(ref_with_domain_id)
            self.assertEqual(domain_id, ref_with_domain_id['domain_id'])
            # Ensure (deprecated) we add default domain if needed
            flask_common.ResourceBase._normalize_domain_id(
                ref_without_domain_id)
            self.assertEqual(
                CONF.identity.default_domain_id,
                ref_without_domain_id['domain_id'])
            ref_without_domain_id.clear()

            # Domain Scoped Form
            # --------------------
            # Just set oslo_context domain_id to a value. This is how we
            # communicate domain scope. No need to explicitly
            # do a domain-scoped request, this is a synthetic text anyway
            oslo_context.domain_id = uuid.uuid4().hex
            # Ensure we don't change the domain if it is specified
            flask_common.ResourceBase._normalize_domain_id(ref_with_domain_id)
            self.assertEqual(domain_id, ref_with_domain_id['domain_id'])
            flask_common.ResourceBase._normalize_domain_id(
                ref_without_domain_id)
            self.assertEqual(oslo_context.domain_id,
                             ref_without_domain_id['domain_id'])
            ref_without_domain_id.clear()

            # "Admin" Token form
            # -------------------
            # Explicitly set "is_admin" to true, no new request is needed
            # as we simply check "is_admin" value everywhere
            oslo_context.is_admin = True
            oslo_context.domain_id = None
            # Ensure we don't change the domain if it is specified
            flask_common.ResourceBase._normalize_domain_id(ref_with_domain_id)
            self.assertEqual(domain_id, ref_with_domain_id['domain_id'])
            # Ensure we raise an appropriate exception with the inferred
            # domain_id
            self.assertRaises(exception.ValidationError,
                              flask_common.ResourceBase._normalize_domain_id,
                              ref=ref_without_domain_id)

    def test_api_prefix_self_referential_link_substitution(self):

        view_arg = uuid.uuid4().hex

        class TestResource(flask_common.ResourceBase):
            api_prefix = '/<string:test_value>/nothing'

        # use a dummy request context, no enforcement is happening
        # therefore we don't need the heavy lifting of a full request
        # run.
        with self.test_request_context(
                path='/%s/nothing/values' % view_arg,
                base_url='https://localhost/'):
            # explicitly set the view_args, this is a special case
            # for a synthetic test case, usually one would rely on
            # a full request stack to set these.
            flask.request.view_args = {'test_value': view_arg}

            # create dummy ref
            ref = {'id': uuid.uuid4().hex}

            # add the self referential link
            TestResource._add_self_referential_link(
                ref, collection_name='values')

            # Check that the link in fact starts with what we expect
            # including the explicit view arg.
            self.assertTrue(ref['links']['self'].startswith(
                'https://localhost/v3/%s' % view_arg)
            )

    def test_json_body_before_req_func_valid_json(self):
        with self.test_request_context(
                headers={'Content-Type': 'application/json'},
                data='{"key": "value"}'):
            # No exception should be raised, everything is happy.
            json_body.json_body_before_request()

    def test_json_body_before_req_func_invalid_json(self):
        with self.test_request_context(
                headers={'Content-Type': 'application/json'},
                data='invalid JSON'):
            # keystone.exception.ValidationError should be raised
            self.assertRaises(exception.ValidationError,
                              json_body.json_body_before_request)

    def test_json_body_before_req_func_no_content_type(self):
        # Unset
        with self.test_request_context(data='{"key": "value"}'):
            # No exception should be raised, everything is happy.
            json_body.json_body_before_request()

        # Explicitly set to ''
        with self.test_request_context(
                headers={'Content-Type': ''}, data='{"key": "value"}'):
            # No exception should be raised, everything is happy.
            json_body.json_body_before_request()

    def test_json_body_before_req_func_unrecognized_content_type(self):
        with self.test_request_context(
                headers={'Content-Type': 'unrecognized/content-type'},
                data='{"key": "value"'):
            # keystone.exception.ValidationError should be raised
            self.assertRaises(exception.ValidationError,
                              json_body.json_body_before_request)

    def test_json_body_before_req_func_unrecognized_conten_type_no_body(self):
        with self.test_request_context(
                headers={'Content-Type': 'unrecognized/content-type'}):
            # No exception should be raised, everything is happy.
            json_body.json_body_before_request()

    def test_resource_collection_key_raises_exception_if_unset(self):
        class TestResource(flask_common.ResourceBase):
            """A Test Resource."""

        class TestResourceWithKey(flask_common.ResourceBase):
            collection_key = uuid.uuid4().hex

        r = TestResource()
        self.assertRaises(ValueError, getattr, r, 'collection_key')

        r = TestResourceWithKey()
        self.assertEqual(
            TestResourceWithKey.collection_key, r.collection_key)

    def test_resource_member_key_raises_exception_if_unset(self):
        class TestResource(flask_common.ResourceBase):
            """A Test Resource."""

        class TestResourceWithKey(flask_common.ResourceBase):
            member_key = uuid.uuid4().hex

        r = TestResource()
        self.assertRaises(ValueError, getattr, r, 'member_key')

        r = TestResourceWithKey()
        self.assertEqual(
            TestResourceWithKey.member_key, r.member_key)


class TestKeystoneFlaskUnrouted404(rest.RestfulTestCase):
    def setUp(self):
        super(TestKeystoneFlaskUnrouted404, self).setUp()
        # unregister the 404 handler we explicitly set in loadapp. This
        # makes the 404 error fallback to a standard werkzeug handling.
        self.public_app.app.error_handler_spec[None].pop(404)

    def test_unrouted_path_is_not_jsonified_404(self):
        with self.test_client() as c:
            path = '/{unrouted_path}'.format(unrouted_path=uuid.uuid4())
            resp = c.get(path, expected_status_code=404)
            # Make sure we're emitting a html error
            self.assertIn('text/html', resp.headers['Content-Type'])
            # Ensure the more generic flask/werkzeug 404 response is emitted
            self.assertTrue(b'404 Not Found' in resp.data)
