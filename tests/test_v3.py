import datetime
import uuid

from lxml import etree
import webtest

from keystone import test
from keystone import token

from keystone import auth
from keystone.common import serializer
from keystone import config
from keystone.openstack.common import timeutils
from keystone.policy.backends import rules

import test_content_types


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id

TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class RestfulTestCase(test_content_types.RestfulTestCase):
    _config_file_list = [test.etcdir('keystone.conf.sample'),
                         test.testsdir('test_overrides.conf'),
                         test.testsdir('backend_sql.conf'),
                         test.testsdir('backend_sql_disk.conf')]

    #override this to sepcify the complete list of configuration files
    def config_files(self):
        return self._config_file_list

    def setUp(self, load_sample_data=True):
        """Setup for v3 Restful Test Cases.

        If a child class wants to create their own sample data
        and provide their own auth data to obtain tokens, then
        load_sample_data should be set to false.

        """
        self.config(self.config_files())

        test.setup_test_database()
        self.load_backends()

        self.token_provider_api = token.provider.Manager()

        self.public_app = webtest.TestApp(
            self.loadapp('keystone', name='main'))
        self.admin_app = webtest.TestApp(
            self.loadapp('keystone', name='admin'))

        if load_sample_data:
            self.domain_id = uuid.uuid4().hex
            self.domain = self.new_domain_ref()
            self.domain['id'] = self.domain_id
            self.identity_api.create_domain(self.domain_id, self.domain)

            self.project_id = uuid.uuid4().hex
            self.project = self.new_project_ref(
                domain_id=self.domain_id)
            self.project['id'] = self.project_id
            self.identity_api.create_project(self.project_id, self.project)

            self.user_id = uuid.uuid4().hex
            self.user = self.new_user_ref(
                domain_id=self.domain_id,
                project_id=self.project_id)
            self.user['id'] = self.user_id
            self.identity_api.create_user(self.user_id, self.user)

            self.default_domain_project_id = uuid.uuid4().hex
            self.default_domain_project = self.new_project_ref(
                domain_id=DEFAULT_DOMAIN_ID)
            self.default_domain_project['id'] = self.default_domain_project_id
            self.identity_api.create_project(self.default_domain_project_id,
                                             self.default_domain_project)

            self.default_domain_user_id = uuid.uuid4().hex
            self.default_domain_user = self.new_user_ref(
                domain_id=DEFAULT_DOMAIN_ID,
                project_id=self.default_domain_project_id)
            self.default_domain_user['id'] = self.default_domain_user_id
            self.identity_api.create_user(self.default_domain_user_id,
                                          self.default_domain_user)

            # create & grant policy.json's default role for admin_required
            self.role_id = uuid.uuid4().hex
            self.role = self.new_role_ref()
            self.role['id'] = self.role_id
            self.role['name'] = 'admin'
            self.identity_api.create_role(self.role_id, self.role)
            self.identity_api.add_role_to_user_and_project(
                self.user_id, self.project_id, self.role_id)
            self.identity_api.add_role_to_user_and_project(
                self.default_domain_user_id, self.default_domain_project_id,
                self.role_id)
            self.identity_api.add_role_to_user_and_project(
                self.default_domain_user_id, self.project_id,
                self.role_id)

        self.public_server = self.serveapp('keystone', name='main')
        self.admin_server = self.serveapp('keystone', name='admin')

    def tearDown(self):
        self.public_server.kill()
        self.admin_server.kill()
        self.public_server = None
        self.admin_server = None
        test.teardown_test_database()
        # need to reset the plug-ins
        auth.controllers.AUTH_METHODS = {}
        #drop the policy rules
        CONF.reset()
        rules.reset()

    def new_ref(self):
        """Populates a ref with attributes common to all API entities."""
        return {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'enabled': True}

    def new_service_ref(self):
        ref = self.new_ref()
        ref['type'] = uuid.uuid4().hex
        return ref

    def new_endpoint_ref(self, service_id):
        ref = self.new_ref()
        ref['interface'] = uuid.uuid4().hex[:8]
        ref['service_id'] = service_id
        ref['url'] = uuid.uuid4().hex
        ref['region'] = uuid.uuid4().hex
        return ref

    def new_domain_ref(self):
        ref = self.new_ref()
        return ref

    def new_project_ref(self, domain_id):
        ref = self.new_ref()
        ref['domain_id'] = domain_id
        return ref

    def new_user_ref(self, domain_id, project_id=None):
        ref = self.new_ref()
        ref['domain_id'] = domain_id
        ref['email'] = uuid.uuid4().hex
        ref['password'] = uuid.uuid4().hex
        if project_id:
            ref['project_id'] = project_id
        return ref

    def new_group_ref(self, domain_id):
        ref = self.new_ref()
        ref['domain_id'] = domain_id
        return ref

    def new_credential_ref(self, user_id, project_id=None):
        ref = self.new_ref()
        ref['user_id'] = user_id
        ref['blob'] = uuid.uuid4().hex
        ref['type'] = uuid.uuid4().hex
        if project_id:
            ref['project_id'] = project_id
        return ref

    def new_role_ref(self):
        ref = self.new_ref()
        return ref

    def new_policy_ref(self):
        ref = self.new_ref()
        ref['blob'] = uuid.uuid4().hex
        ref['type'] = uuid.uuid4().hex
        return ref

    def new_trust_ref(self, trustor_user_id, trustee_user_id, project_id=None,
                      impersonation=None, expires=None, role_ids=None,
                      role_names=None):
        ref = self.new_ref()

        ref['trustor_user_id'] = trustor_user_id
        ref['trustee_user_id'] = trustee_user_id
        ref['impersonation'] = impersonation or False
        ref['project_id'] = project_id

        if isinstance(expires, basestring):
            ref['expires_at'] = expires
        elif isinstance(expires, dict):
            ref['expires_at'] = timeutils.strtime(
                timeutils.utcnow() + datetime.timedelta(**expires),
                fmt=TIME_FORMAT)
        elif expires is None:
            pass
        else:
            raise NotImplementedError('Unexpected value for "expires"')

        role_ids = role_ids or []
        role_names = role_names or []
        if role_ids or role_names:
            ref['roles'] = []
            for role_id in role_ids:
                ref['roles'].append({'id': role_id})
            for role_name in role_names:
                ref['roles'].append({'name': role_name})

        return ref

    def admin_request(self, *args, **kwargs):
        """Translates XML responses to dicts.

        This implies that we only have to write assertions for JSON.

        """
        r = super(RestfulTestCase, self).admin_request(*args, **kwargs)
        if r.headers.get('Content-Type') == 'application/xml':
            r.result = serializer.from_xml(etree.tostring(r.result))
        return r

    def get_scoped_token(self):
        """Convenience method so that we can test authenticated requests."""
        r = self.admin_request(
            method='POST',
            path='/v3/auth/tokens',
            body={
                'auth': {
                    'identity': {
                        'methods': ['password'],
                        'password': {
                            'user': {
                                'name': self.user['name'],
                                'password': self.user['password'],
                                'domain': {
                                    'id': self.user['domain_id']
                                }
                            }
                        }
                    },
                    'scope': {
                        'project': {
                            'id': self.project['id'],
                        }
                    }
                }
            })
        return r.headers.get('X-Subject-Token')

    def get_requested_token(self, auth):
        """Request the specific token we want."""

        r = self.admin_request(
            method='POST',
            path='/v3/auth/tokens',
            body=auth)
        return r.headers.get('X-Subject-Token')

    def v3_request(self, path, **kwargs):
        # Check if the caller has passed in auth details for
        # use in requesting the token
        auth = kwargs.pop('auth', None)
        if auth:
            token = self.get_requested_token(auth)
        else:
            token = kwargs.pop('token', None)
            if not token:
                token = self.get_scoped_token()
        path = '/v3' + path

        return self.admin_request(path=path, token=token, **kwargs)

    def get(self, path, **kwargs):
        r = self.v3_request(method='GET', path=path, **kwargs)
        if 'expected_status' not in kwargs:
            self.assertResponseStatus(r, 200)
        return r

    def head(self, path, **kwargs):
        r = self.v3_request(method='HEAD', path=path, **kwargs)
        if 'expected_status' not in kwargs:
            self.assertResponseStatus(r, 204)
        return r

    def post(self, path, **kwargs):
        r = self.v3_request(method='POST', path=path, **kwargs)
        if 'expected_status' not in kwargs:
            self.assertResponseStatus(r, 201)
        return r

    def put(self, path, **kwargs):
        r = self.v3_request(method='PUT', path=path, **kwargs)
        if 'expected_status' not in kwargs:
            self.assertResponseStatus(r, 204)
        return r

    def patch(self, path, **kwargs):
        r = self.v3_request(method='PATCH', path=path, **kwargs)
        if 'expected_status' not in kwargs:
            self.assertResponseStatus(r, 200)
        return r

    def delete(self, path, **kwargs):
        r = self.v3_request(method='DELETE', path=path, **kwargs)
        if 'expected_status' not in kwargs:
            self.assertResponseStatus(r, 204)
        return r

    def assertValidErrorResponse(self, r):
        if r.headers.get('Content-Type') == 'application/xml':
            resp = serializer.from_xml(etree.tostring(r.result))
        else:
            resp = r.result
        self.assertIsNotNone(resp.get('error'))
        self.assertIsNotNone(resp['error'].get('code'))
        self.assertIsNotNone(resp['error'].get('title'))
        self.assertIsNotNone(resp['error'].get('message'))
        self.assertEqual(int(resp['error']['code']), r.status_code)

    def assertValidListLinks(self, links):
        self.assertIsNotNone(links)
        self.assertIsNotNone(links.get('self'))
        self.assertIn(CONF.public_endpoint % CONF, links['self'])

        self.assertIn('next', links)
        if links['next'] is not None:
            self.assertIn(
                CONF.public_endpoint % CONF,
                links['next'])

        self.assertIn('previous', links)
        if links['previous'] is not None:
            self.assertIn(
                CONF.public_endpoint % CONF,
                links['previous'])

    def assertValidListResponse(self, resp, key, entity_validator, ref=None,
                                expected_length=None, keys_to_check=None):
        """Make assertions common to all API list responses.

        If a reference is provided, it's ID will be searched for in the
        response, and asserted to be equal.

        """
        entities = resp.result.get(key)
        self.assertIsNotNone(entities)

        if expected_length is not None:
            self.assertEqual(len(entities), expected_length)
        elif ref is not None:
            # we're at least expecting the ref
            self.assertNotEmpty(entities)

        # collections should have relational links
        self.assertValidListLinks(resp.result.get('links'))

        for entity in entities:
            self.assertIsNotNone(entity)
            self.assertValidEntity(entity, keys_to_check=keys_to_check)
            entity_validator(entity)
        if ref:
            entity = [x for x in entities if x['id'] == ref['id']][0]
            self.assertValidEntity(entity, ref=ref,
                                   keys_to_check=keys_to_check)
            entity_validator(entity, ref)
        return entities

    def assertValidResponse(self, resp, key, entity_validator, *args,
                            **kwargs):
        """Make assertions common to all API responses."""
        entity = resp.result.get(key)
        self.assertIsNotNone(entity)
        keys = kwargs.pop('keys_to_check', None)
        self.assertValidEntity(entity, keys_to_check=keys, *args, **kwargs)
        entity_validator(entity, *args, **kwargs)
        return entity

    def assertValidEntity(self, entity, ref=None, keys_to_check=None):
        """Make assertions common to all API entities.

        If a reference is provided, the entity will also be compared against
        the reference.
        """
        if keys_to_check:
            keys = keys_to_check
        else:
            keys = ['name', 'description', 'enabled']

        for k in ['id'] + keys:
            msg = '%s unexpectedly None in %s' % (k, entity)
            self.assertIsNotNone(entity.get(k), msg)

        self.assertIsNotNone(entity.get('links'))
        self.assertIsNotNone(entity['links'].get('self'))
        self.assertIn(CONF.public_endpoint % CONF, entity['links']['self'])
        self.assertIn(entity['id'], entity['links']['self'])

        if ref:
            for k in keys:
                msg = '%s not equal: %s != %s' % (k, ref[k], entity[k])
                self.assertEquals(ref[k], entity[k])

        return entity

    # auth validation

    def assertValidISO8601ExtendedFormatDatetime(self, dt):
        try:
            return timeutils.parse_strtime(dt, fmt=TIME_FORMAT)
        except Exception:
            msg = '%s is not a valid ISO 8601 extended format date time.' % dt
            raise AssertionError(msg)
        self.assertTrue(isinstance(dt, datetime.datetime))

    def assertValidTokenResponse(self, r, user=None):
        self.assertTrue(r.headers.get('X-Subject-Token'))
        token = r.result['token']

        self.assertIsNotNone(token.get('expires_at'))
        expires_at = self.assertValidISO8601ExtendedFormatDatetime(
            token['expires_at'])
        self.assertIsNotNone(token.get('issued_at'))
        issued_at = self.assertValidISO8601ExtendedFormatDatetime(
            token['issued_at'])
        self.assertTrue(issued_at < expires_at)

        self.assertIn('user', token)
        self.assertIn('id', token['user'])
        self.assertIn('name', token['user'])
        self.assertIn('domain', token['user'])
        self.assertIn('id', token['user']['domain'])

        if user is not None:
            self.assertEqual(user['id'], token['user']['id'])
            self.assertEqual(user['name'], token['user']['name'])
            self.assertEqual(user['domain_id'], token['user']['domain']['id'])

        return token

    def assertValidUnscopedTokenResponse(self, r, *args, **kwargs):
        token = self.assertValidTokenResponse(r, *args, **kwargs)

        self.assertNotIn('roles', token)
        self.assertNotIn('catalog', token)
        self.assertNotIn('project', token)
        self.assertNotIn('domain', token)

        return token

    def assertValidScopedTokenResponse(self, r, *args, **kwargs):
        require_catalog = kwargs.pop('require_catalog', True)
        token = self.assertValidTokenResponse(r, *args, **kwargs)

        if require_catalog:
            self.assertIn('catalog', token)
        else:
            self.assertNotIn('catalog', token)

        self.assertIn('roles', token)
        self.assertTrue(token['roles'])
        for role in token['roles']:
            self.assertIn('id', role)
            self.assertIn('name', role)

        return token

    def assertValidProjectScopedTokenResponse(self, r, *args, **kwargs):
        token = self.assertValidScopedTokenResponse(r, *args, **kwargs)

        self.assertIn('project', token)
        self.assertIn('id', token['project'])
        self.assertIn('name', token['project'])
        self.assertIn('domain', token['project'])
        self.assertIn('id', token['project']['domain'])
        self.assertIn('name', token['project']['domain'])

        self.assertEqual(self.role_id, token['roles'][0]['id'])

        return token

    def assertValidProjectTrustScopedTokenResponse(self, r, *args, **kwargs):
        token = self.assertValidProjectScopedTokenResponse(r, *args, **kwargs)

        trust = token.get('OS-TRUST:trust')
        self.assertIsNotNone(trust)
        self.assertIsNotNone(trust.get('id'))
        self.assertTrue(isinstance(trust.get('impersonation'), bool))
        self.assertIsNotNone(trust.get('trustor_user'))
        self.assertIsNotNone(trust.get('trustee_user'))
        self.assertIsNotNone(trust['trustor_user'].get('id'))
        self.assertIsNotNone(trust['trustee_user'].get('id'))

    def assertValidDomainScopedTokenResponse(self, r, *args, **kwargs):
        token = self.assertValidScopedTokenResponse(r, *args, **kwargs)

        self.assertIn('domain', token)
        self.assertIn('id', token['domain'])
        self.assertIn('name', token['domain'])

        return token

    def assertEqualTokens(self, a, b):
        """Assert that two tokens are equal.

        Compare two tokens except for their ids. This also truncates
        the time in the comparison.
        """
        def normalize(token):
            del token['token']['expires_at']
            del token['token']['issued_at']
            return token

        a_expires_at = self.assertValidISO8601ExtendedFormatDatetime(
            a['token']['expires_at'])
        b_expires_at = self.assertValidISO8601ExtendedFormatDatetime(
            b['token']['expires_at'])
        self.assertCloseEnoughForGovernmentWork(a_expires_at, b_expires_at)

        a_issued_at = self.assertValidISO8601ExtendedFormatDatetime(
            a['token']['issued_at'])
        b_issued_at = self.assertValidISO8601ExtendedFormatDatetime(
            b['token']['issued_at'])
        self.assertCloseEnoughForGovernmentWork(a_issued_at, b_issued_at)

        return self.assertDictEqual(normalize(a), normalize(b))

    # service validation

    def assertValidServiceListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'services',
            self.assertValidService,
            *args,
            **kwargs)

    def assertValidServiceResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'service',
            self.assertValidService,
            *args,
            **kwargs)

    def assertValidService(self, entity, ref=None):
        self.assertIsNotNone(entity.get('type'))
        if ref:
            self.assertEqual(ref['type'], entity['type'])
        return entity

    # endpoint validation

    def assertValidEndpointListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'endpoints',
            self.assertValidEndpoint,
            *args,
            **kwargs)

    def assertValidEndpointResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'endpoint',
            self.assertValidEndpoint,
            *args,
            **kwargs)

    def assertValidEndpoint(self, entity, ref=None):
        self.assertIsNotNone(entity.get('interface'))
        self.assertIsNotNone(entity.get('service_id'))

        # this is intended to be an unexposed implementation detail
        self.assertNotIn('legacy_endpoint_id', entity)

        if ref:
            self.assertEqual(ref['interface'], entity['interface'])
            self.assertEqual(ref['service_id'], entity['service_id'])
        return entity

    # domain validation

    def assertValidDomainListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'domains',
            self.assertValidDomain,
            *args,
            **kwargs)

    def assertValidDomainResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'domain',
            self.assertValidDomain,
            *args,
            **kwargs)

    def assertValidDomain(self, entity, ref=None):
        if ref:
            pass
        return entity

    # project validation

    def assertValidProjectListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'projects',
            self.assertValidProject,
            *args,
            **kwargs)

    def assertValidProjectResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'project',
            self.assertValidProject,
            *args,
            **kwargs)

    def assertValidProject(self, entity, ref=None):
        self.assertIsNotNone(entity.get('domain_id'))
        if ref:
            self.assertEqual(ref['domain_id'], entity['domain_id'])
        return entity

    # user validation

    def assertValidUserListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'users',
            self.assertValidUser,
            *args,
            **kwargs)

    def assertValidUserResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'user',
            self.assertValidUser,
            *args,
            **kwargs)

    def assertValidUser(self, entity, ref=None):
        self.assertIsNotNone(entity.get('domain_id'))
        self.assertIsNotNone(entity.get('email'))
        self.assertIsNone(entity.get('password'))
        if ref:
            self.assertEqual(ref['domain_id'], entity['domain_id'])
            self.assertEqual(ref['email'], entity['email'])
        return entity

    # group validation

    def assertValidGroupListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'groups',
            self.assertValidGroup,
            *args,
            **kwargs)

    def assertValidGroupResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'group',
            self.assertValidGroup,
            *args,
            **kwargs)

    def assertValidGroup(self, entity, ref=None):
        self.assertIsNotNone(entity.get('name'))
        if ref:
            self.assertEqual(ref['name'], entity['name'])
        return entity

    # credential validation

    def assertValidCredentialListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'credentials',
            self.assertValidCredential,
            *args,
            **kwargs)

    def assertValidCredentialResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'credential',
            self.assertValidCredential,
            *args,
            **kwargs)

    def assertValidCredential(self, entity, ref=None):
        self.assertIsNotNone(entity.get('user_id'))
        self.assertIsNotNone(entity.get('blob'))
        self.assertIsNotNone(entity.get('type'))
        if ref:
            self.assertEqual(ref['user_id'], entity['user_id'])
            self.assertEqual(ref['blob'], entity['blob'])
            self.assertEqual(ref['type'], entity['type'])
            self.assertEqual(ref.get('project_id'), entity.get('project_id'))
        return entity

    # role validation

    def assertValidRoleListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'roles',
            self.assertValidRole,
            keys_to_check=['name'],
            *args,
            **kwargs)

    def assertValidRoleResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'role',
            self.assertValidRole,
            keys_to_check=['name'],
            *args,
            **kwargs)

    def assertValidRole(self, entity, ref=None):
        self.assertIsNotNone(entity.get('name'))
        if ref:
            self.assertEqual(ref['name'], entity['name'])
        return entity

    def assertValidRoleAssignmentListResponse(self, resp, ref=None,
                                              expected_length=None):

        entities = resp.result.get('role_assignments')

        if expected_length is not None:
            self.assertEqual(len(entities), expected_length)
        elif ref is not None:
            # we're at least expecting the ref
            self.assertNotEmpty(entities)

        # collections should have relational links
        self.assertValidListLinks(resp.result.get('links'))

        for entity in entities:
            self.assertIsNotNone(entity)
            self.assertValidRoleAssignment(entity)
        if ref:
            self.assertValidRoleAssignment(entity, ref)
        return entities

    def assertValidRoleAssignment(self, entity, ref=None, url=None):
        self.assertIsNotNone(entity.get('role'))
        self.assertIsNotNone(entity.get('scope'))

        # Only one of user or group should be present
        self.assertIsNotNone(entity.get('user') or
                             entity.get('group'))
        self.assertIsNone(entity.get('user') and
                          entity.get('group'))

        # Only one of domain or project should be present
        self.assertIsNotNone(entity['scope'].get('project') or
                             entity['scope'].get('domain'))
        self.assertIsNone(entity['scope'].get('project') and
                          entity['scope'].get('domain'))

        if entity['scope'].get('project'):
            self.assertIsNotNone(entity['scope']['project'].get('id'))
        else:
            self.assertIsNotNone(entity['scope']['domain'].get('id'))
        self.assertIsNotNone(entity.get('links'))
        self.assertIsNotNone(entity['links'].get('assignment'))

        if ref:
            if ref.get('user'):
                self.assertEqual(ref['user']['id'], entity['user']['id'])
            if ref.get('group'):
                self.assertEqual(ref['group']['id'], entity['group']['id'])
            if ref.get('role'):
                self.assertEqual(ref['role']['id'], entity['role']['id'])
            if ref['scope'].get('project'):
                self.assertEqual(ref['scope']['project']['id'],
                                 entity['scope']['project']['id'])
            if ref['scope'].get('domain'):
                self.assertEqual(ref['scope']['domain']['id'],
                                 entity['scope']['domain']['id'])
        if url:
            self.assertIn(url, entity['links']['assignment'])

    def assertRoleAssignmentInListResponse(
            self, resp, ref, link_url=None, expected=1):

        found_count = 0
        for entity in resp.result.get('role_assignments'):
            try:
                self.assertValidRoleAssignment(
                    entity, ref=ref, url=link_url)
            except Exception:
                # It doesn't match, so let's go onto the next one
                pass
            else:
                found_count += 1
        self.assertEqual(found_count, expected)

    def assertRoleAssignmentNotInListResponse(
            self, resp, ref, link_url=None):

        self.assertRoleAssignmentInListResponse(
            resp, ref=ref, link_url=link_url, expected=0)

    # policy validation

    def assertValidPolicyListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'policies',
            self.assertValidPolicy,
            *args,
            **kwargs)

    def assertValidPolicyResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'policy',
            self.assertValidPolicy,
            *args,
            **kwargs)

    def assertValidPolicy(self, entity, ref=None):
        self.assertIsNotNone(entity.get('blob'))
        self.assertIsNotNone(entity.get('type'))
        if ref:
            self.assertEqual(ref['blob'], entity['blob'])
            self.assertEqual(ref['type'], entity['type'])
        return entity

    # trust validation

    def assertValidTrustListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'trusts',
            self.assertValidTrust,
            *args,
            **kwargs)

    def assertValidTrustResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'trust',
            self.assertValidTrust,
            *args,
            **kwargs)

    def assertValidTrust(self, entity, ref=None):
        self.assertIsNotNone(entity.get('trustor_user_id'))
        self.assertIsNotNone(entity.get('trustee_user_id'))

        self.assertIn('expires_at', entity)
        if entity['expires_at'] is not None:
            self.assertValidISO8601ExtendedFormatDatetime(entity['expires_at'])

        # always disallow project xor project_id (neither or both is allowed)
        has_roles = bool(entity.get('roles'))
        has_project = bool(entity.get('project_id'))
        self.assertFalse(has_roles ^ has_project)

        for role in entity['roles']:
            self.assertIsNotNone(role)
            self.assertValidEntity(role)
            self.assertValidRole(role)

        self.assertValidListLinks(entity.get('roles_links'))

        # these were used during dev and shouldn't land in final impl
        self.assertNotIn('role_ids', entity)
        self.assertNotIn('role_names', entity)

        if ref:
            self.assertEqual(ref['trustor_user_id'], entity['trustor_user_id'])
            self.assertEqual(ref['trustee_user_id'], entity['trustee_user_id'])
            self.assertEqual(ref['project_id'], entity['project_id'])
            if entity.get('expires_at') or ref.get('expires_at'):
                entity_exp = self.assertValidISO8601ExtendedFormatDatetime(
                    entity['expires_at'])
                ref_exp = self.assertValidISO8601ExtendedFormatDatetime(
                    ref['expires_at'])
                self.assertCloseEnoughForGovernmentWork(entity_exp, ref_exp)
            else:
                self.assertEqual(ref.get('expires_at'),
                                 entity.get('expires_at'))

        return entity

    def build_auth_scope(self, project_id=None, project_name=None,
                         project_domain_id=None, project_domain_name=None,
                         domain_id=None, domain_name=None, trust_id=None):
        scope_data = {}
        if project_id or project_name:
            scope_data['project'] = {}
            if project_id:
                scope_data['project']['id'] = project_id
            else:
                scope_data['project']['name'] = project_name
                if project_domain_id or project_domain_name:
                    project_domain_json = {}
                    if project_domain_id:
                        project_domain_json['id'] = project_domain_id
                    else:
                        project_domain_json['name'] = project_domain_name
                    scope_data['project']['domain'] = project_domain_json
        if domain_id or domain_name:
            scope_data['domain'] = {}
            if domain_id:
                scope_data['domain']['id'] = domain_id
            else:
                scope_data['domain']['name'] = domain_name
        if trust_id:
            scope_data['OS-TRUST:trust'] = {}
            scope_data['OS-TRUST:trust']['id'] = trust_id
        return scope_data

    def build_password_auth(self, user_id=None, username=None,
                            user_domain_id=None, user_domain_name=None,
                            password=None):
        password_data = {'user': {}}
        if user_id:
            password_data['user']['id'] = user_id
        else:
            password_data['user']['name'] = username
            if user_domain_id or user_domain_name:
                password_data['user']['domain'] = {}
                if user_domain_id:
                    password_data['user']['domain']['id'] = user_domain_id
                else:
                    password_data['user']['domain']['name'] = user_domain_name
        password_data['user']['password'] = password
        return password_data

    def build_token_auth(self, token):
        return {'id': token}

    def build_authentication_request(self, token=None, user_id=None,
                                     username=None, user_domain_id=None,
                                     user_domain_name=None, password=None,
                                     **kwargs):
        """Build auth dictionary.

        It will create an auth dictionary based on all the arguments
        that it receives.
        """
        auth_data = {}
        auth_data['identity'] = {'methods': []}
        if token:
            auth_data['identity']['methods'].append('token')
            auth_data['identity']['token'] = self.build_token_auth(token)
        if user_id or username:
            auth_data['identity']['methods'].append('password')
            auth_data['identity']['password'] = self.build_password_auth(
                user_id, username, user_domain_id, user_domain_name, password)
        if kwargs:
            auth_data['scope'] = self.build_auth_scope(**kwargs)
        return {'auth': auth_data}


class VersionTestCase(RestfulTestCase):
    def test_get_version(self):
        pass
