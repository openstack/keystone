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

import datetime
import uuid

from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from testtools import matchers

from keystone import auth
from keystone.common import authorization
from keystone.common import cache
from keystone import exception
from keystone import middleware
from keystone.policy.backends import rules
from keystone.tests import unit
from keystone.tests.unit import rest


CONF = cfg.CONF
DEFAULT_DOMAIN_ID = 'default'

TIME_FORMAT = unit.TIME_FORMAT


class AuthTestMixin(object):
    """To hold auth building helper functions."""
    def build_auth_scope(self, project_id=None, project_name=None,
                         project_domain_id=None, project_domain_name=None,
                         domain_id=None, domain_name=None, trust_id=None,
                         unscoped=None):
        scope_data = {}
        if unscoped:
            scope_data['unscoped'] = {}
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
                                     kerberos=False, **kwargs):
        """Build auth dictionary.

        It will create an auth dictionary based on all the arguments
        that it receives.
        """
        auth_data = {}
        auth_data['identity'] = {'methods': []}
        if kerberos:
            auth_data['identity']['methods'].append('kerberos')
            auth_data['identity']['kerberos'] = {}
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


class RestfulTestCase(unit.SQLDriverOverrides, rest.RestfulTestCase,
                      AuthTestMixin):
    def config_files(self):
        config_files = super(RestfulTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def get_extensions(self):
        extensions = set(['revoke'])
        if hasattr(self, 'EXTENSION_NAME'):
            extensions.add(self.EXTENSION_NAME)
        return extensions

    def generate_paste_config(self):
        new_paste_file = None
        try:
            new_paste_file = unit.generate_paste_config(self.EXTENSION_TO_ADD)
        except AttributeError:
            # no need to report this error here, as most tests will not have
            # EXTENSION_TO_ADD defined.
            pass
        finally:
            return new_paste_file

    def remove_generated_paste_config(self):
        try:
            unit.remove_generated_paste_config(self.EXTENSION_TO_ADD)
        except AttributeError:
            pass

    def setUp(self, app_conf='keystone'):
        """Setup for v3 Restful Test Cases.

        """
        new_paste_file = self.generate_paste_config()
        self.addCleanup(self.remove_generated_paste_config)
        if new_paste_file:
            app_conf = 'config:%s' % (new_paste_file)

        super(RestfulTestCase, self).setUp(app_conf=app_conf)

        self.empty_context = {'environment': {}}

        # Initialize the policy engine and allow us to write to a temp
        # file in each test to create the policies
        rules.reset()

        # drop the policy rules
        self.addCleanup(rules.reset)

    def load_backends(self):
        # ensure the cache region instance is setup
        cache.configure_cache_region(cache.REGION)

        super(RestfulTestCase, self).load_backends()

    def load_fixtures(self, fixtures):
        self.load_sample_data()

    def _populate_default_domain(self):
        if CONF.database.connection == unit.IN_MEM_DB_CONN_STRING:
            # NOTE(morganfainberg): If an in-memory db is being used, be sure
            # to populate the default domain, this is typically done by
            # a migration, but the in-mem db uses model definitions  to create
            # the schema (no migrations are run).
            try:
                self.resource_api.get_domain(DEFAULT_DOMAIN_ID)
            except exception.DomainNotFound:
                domain = {'description': (u'Owns users and tenants (i.e. '
                                          u'projects) available on Identity '
                                          u'API v2.'),
                          'enabled': True,
                          'id': DEFAULT_DOMAIN_ID,
                          'name': u'Default'}
                self.resource_api.create_domain(DEFAULT_DOMAIN_ID, domain)

    def load_sample_data(self):
        self._populate_default_domain()
        self.domain_id = uuid.uuid4().hex
        self.domain = self.new_domain_ref()
        self.domain['id'] = self.domain_id
        self.resource_api.create_domain(self.domain_id, self.domain)

        self.project_id = uuid.uuid4().hex
        self.project = self.new_project_ref(
            domain_id=self.domain_id)
        self.project['id'] = self.project_id
        self.resource_api.create_project(self.project_id, self.project)

        self.user = self.new_user_ref(domain_id=self.domain_id)
        password = self.user['password']
        self.user = self.identity_api.create_user(self.user)
        self.user['password'] = password
        self.user_id = self.user['id']

        self.default_domain_project_id = uuid.uuid4().hex
        self.default_domain_project = self.new_project_ref(
            domain_id=DEFAULT_DOMAIN_ID)
        self.default_domain_project['id'] = self.default_domain_project_id
        self.resource_api.create_project(self.default_domain_project_id,
                                         self.default_domain_project)

        self.default_domain_user = self.new_user_ref(
            domain_id=DEFAULT_DOMAIN_ID)
        password = self.default_domain_user['password']
        self.default_domain_user = (
            self.identity_api.create_user(self.default_domain_user))
        self.default_domain_user['password'] = password
        self.default_domain_user_id = self.default_domain_user['id']

        # create & grant policy.json's default role for admin_required
        self.role_id = uuid.uuid4().hex
        self.role = self.new_role_ref()
        self.role['id'] = self.role_id
        self.role['name'] = 'admin'
        self.role_api.create_role(self.role_id, self.role)
        self.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, self.role_id)
        self.assignment_api.add_role_to_user_and_project(
            self.default_domain_user_id, self.default_domain_project_id,
            self.role_id)
        self.assignment_api.add_role_to_user_and_project(
            self.default_domain_user_id, self.project_id,
            self.role_id)

        self.region_id = uuid.uuid4().hex
        self.region = self.new_region_ref()
        self.region['id'] = self.region_id
        self.catalog_api.create_region(
            self.region.copy())

        self.service_id = uuid.uuid4().hex
        self.service = self.new_service_ref()
        self.service['id'] = self.service_id
        self.catalog_api.create_service(
            self.service_id,
            self.service.copy())

        self.endpoint_id = uuid.uuid4().hex
        self.endpoint = self.new_endpoint_ref(service_id=self.service_id)
        self.endpoint['id'] = self.endpoint_id
        self.endpoint['region_id'] = self.region['id']
        self.catalog_api.create_endpoint(
            self.endpoint_id,
            self.endpoint.copy())
        # The server adds 'enabled' and defaults to True.
        self.endpoint['enabled'] = True

    def new_ref(self):
        """Populates a ref with attributes common to some API entities."""
        return unit.new_ref()

    def new_region_ref(self):
        return unit.new_region_ref()

    def new_service_ref(self):
        return unit.new_service_ref()

    def new_endpoint_ref(self, service_id, interface='public', **kwargs):
        return unit.new_endpoint_ref(
            service_id, interface=interface, default_region_id=self.region_id,
            **kwargs)

    def new_domain_ref(self):
        return unit.new_domain_ref()

    def new_project_ref(self, domain_id=None, parent_id=None, is_domain=False):
        return unit.new_project_ref(domain_id=domain_id, parent_id=parent_id,
                                    is_domain=is_domain)

    def new_user_ref(self, domain_id, project_id=None):
        return unit.new_user_ref(domain_id, project_id=project_id)

    def new_group_ref(self, domain_id):
        return unit.new_group_ref(domain_id)

    def new_credential_ref(self, user_id, project_id=None, cred_type=None):
        return unit.new_credential_ref(user_id, project_id=project_id,
                                       cred_type=cred_type)

    def new_role_ref(self):
        return unit.new_role_ref()

    def new_policy_ref(self):
        return unit.new_policy_ref()

    def new_trust_ref(self, trustor_user_id, trustee_user_id, project_id=None,
                      impersonation=None, expires=None, role_ids=None,
                      role_names=None, remaining_uses=None,
                      allow_redelegation=False):
        return unit.new_trust_ref(
            trustor_user_id, trustee_user_id, project_id=project_id,
            impersonation=impersonation, expires=expires, role_ids=role_ids,
            role_names=role_names, remaining_uses=remaining_uses,
            allow_redelegation=allow_redelegation)

    def create_new_default_project_for_user(self, user_id, domain_id,
                                            enable_project=True):
        ref = self.new_project_ref(domain_id=domain_id)
        ref['enabled'] = enable_project
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)
        # set the user's preferred project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': user_id},
            body=body)
        self.assertValidUserResponse(r)

        return project

    def get_unscoped_token(self):
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
                    }
                }
            })
        return r.headers.get('X-Subject-Token')

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

    def get_domain_scoped_token(self):
        """Convenience method for requesting domain scoped token."""
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
                        'domain': {
                            'id': self.domain['id'],
                        }
                    }
                }
            })
        return r.headers.get('X-Subject-Token')

    def get_requested_token(self, auth):
        """Request the specific token we want."""

        r = self.v3_authenticate_token(auth)
        return r.headers.get('X-Subject-Token')

    def v3_authenticate_token(self, auth, expected_status=201):
        return self.admin_request(method='POST',
                                  path='/v3/auth/tokens',
                                  body=auth,
                                  expected_status=expected_status)

    def v3_noauth_request(self, path, **kwargs):
        # request does not require auth token header
        path = '/v3' + path
        return self.admin_request(path=path, **kwargs)

    def v3_request(self, path, **kwargs):
        # check to see if caller requires token for the API call.
        if kwargs.pop('noauth', None):
            return self.v3_noauth_request(path, **kwargs)

        # Check if the caller has passed in auth details for
        # use in requesting the token
        auth_arg = kwargs.pop('auth', None)
        if auth_arg:
            token = self.get_requested_token(auth_arg)
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
        self.assertEqual('', r.body)
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
        resp = r.result
        self.assertIsNotNone(resp.get('error'))
        self.assertIsNotNone(resp['error'].get('code'))
        self.assertIsNotNone(resp['error'].get('title'))
        self.assertIsNotNone(resp['error'].get('message'))
        self.assertEqual(int(resp['error']['code']), r.status_code)

    def assertValidListLinks(self, links, resource_url=None):
        self.assertIsNotNone(links)
        self.assertIsNotNone(links.get('self'))
        self.assertThat(links['self'], matchers.StartsWith('http://localhost'))

        if resource_url:
            self.assertThat(links['self'], matchers.EndsWith(resource_url))

        self.assertIn('next', links)
        if links['next'] is not None:
            self.assertThat(links['next'],
                            matchers.StartsWith('http://localhost'))

        self.assertIn('previous', links)
        if links['previous'] is not None:
            self.assertThat(links['previous'],
                            matchers.StartsWith('http://localhost'))

    def assertValidListResponse(self, resp, key, entity_validator, ref=None,
                                expected_length=None, keys_to_check=None,
                                resource_url=None):
        """Make assertions common to all API list responses.

        If a reference is provided, it's ID will be searched for in the
        response, and asserted to be equal.

        """
        entities = resp.result.get(key)
        self.assertIsNotNone(entities)

        if expected_length is not None:
            self.assertEqual(expected_length, len(entities))
        elif ref is not None:
            # we're at least expecting the ref
            self.assertNotEmpty(entities)

        # collections should have relational links
        self.assertValidListLinks(resp.result.get('links'),
                                  resource_url=resource_url)

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
        if keys_to_check is not None:
            keys = keys_to_check
        else:
            keys = ['name', 'description', 'enabled']

        for k in ['id'] + keys:
            msg = '%s unexpectedly None in %s' % (k, entity)
            self.assertIsNotNone(entity.get(k), msg)

        self.assertIsNotNone(entity.get('links'))
        self.assertIsNotNone(entity['links'].get('self'))
        self.assertThat(entity['links']['self'],
                        matchers.StartsWith('http://localhost'))
        self.assertIn(entity['id'], entity['links']['self'])

        if ref:
            for k in keys:
                msg = '%s not equal: %s != %s' % (k, ref[k], entity[k])
                self.assertEqual(ref[k], entity[k])

        return entity

    # auth validation

    def assertValidISO8601ExtendedFormatDatetime(self, dt):
        try:
            return timeutils.parse_strtime(dt, fmt=TIME_FORMAT)
        except Exception:
            msg = '%s is not a valid ISO 8601 extended format date time.' % dt
            raise AssertionError(msg)
        self.assertIsInstance(dt, datetime.datetime)

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
        endpoint_filter = kwargs.pop('endpoint_filter', False)
        ep_filter_assoc = kwargs.pop('ep_filter_assoc', 0)
        token = self.assertValidTokenResponse(r, *args, **kwargs)

        if require_catalog:
            endpoint_num = 0
            self.assertIn('catalog', token)

            if isinstance(token['catalog'], list):
                # only test JSON
                for service in token['catalog']:
                    for endpoint in service['endpoints']:
                        self.assertNotIn('enabled', endpoint)
                        self.assertNotIn('legacy_endpoint_id', endpoint)
                        self.assertNotIn('service_id', endpoint)
                        endpoint_num += 1

            # sub test for the OS-EP-FILTER extension enabled
            if endpoint_filter:
                self.assertEqual(ep_filter_assoc, endpoint_num)
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
        self.assertIsInstance(trust.get('impersonation'), bool)
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

    # catalog validation

    def assertValidCatalogResponse(self, resp, *args, **kwargs):
        self.assertEqual(set(['catalog', 'links']), set(resp.json.keys()))
        self.assertValidCatalog(resp.json['catalog'])
        self.assertIn('links', resp.json)
        self.assertIsInstance(resp.json['links'], dict)
        self.assertEqual(['self'], list(resp.json['links'].keys()))
        self.assertEqual(
            'http://localhost/v3/auth/catalog',
            resp.json['links']['self'])

    def assertValidCatalog(self, entity):
        self.assertIsInstance(entity, list)
        self.assertTrue(len(entity) > 0)
        for service in entity:
            self.assertIsNotNone(service.get('id'))
            self.assertIsNotNone(service.get('name'))
            self.assertIsNotNone(service.get('type'))
            self.assertNotIn('enabled', service)
            self.assertTrue(len(service['endpoints']) > 0)
            for endpoint in service['endpoints']:
                self.assertIsNotNone(endpoint.get('id'))
                self.assertIsNotNone(endpoint.get('interface'))
                self.assertIsNotNone(endpoint.get('url'))
                self.assertNotIn('enabled', endpoint)
                self.assertNotIn('legacy_endpoint_id', endpoint)
                self.assertNotIn('service_id', endpoint)

    # region validation

    def assertValidRegionListResponse(self, resp, *args, **kwargs):
        # NOTE(jaypipes): I have to pass in a blank keys_to_check parameter
        #                 below otherwise the base assertValidEntity method
        #                 tries to find a "name" and an "enabled" key in the
        #                 returned ref dicts. The issue is, I don't understand
        #                 how the service and endpoint entity assertions below
        #                 actually work (they don't raise assertions), since
        #                 AFAICT, the service and endpoint tables don't have
        #                 a "name" column either... :(
        return self.assertValidListResponse(
            resp,
            'regions',
            self.assertValidRegion,
            keys_to_check=[],
            *args,
            **kwargs)

    def assertValidRegionResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'region',
            self.assertValidRegion,
            keys_to_check=[],
            *args,
            **kwargs)

    def assertValidRegion(self, entity, ref=None):
        self.assertIsNotNone(entity.get('description'))
        if ref:
            self.assertEqual(ref['description'], entity['description'])
        return entity

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
        self.assertIsInstance(entity.get('enabled'), bool)
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
        self.assertIsInstance(entity['enabled'], bool)

        # this is intended to be an unexposed implementation detail
        self.assertNotIn('legacy_endpoint_id', entity)

        if ref:
            self.assertEqual(ref['interface'], entity['interface'])
            self.assertEqual(ref['service_id'], entity['service_id'])
            if ref.get('region') is not None:
                self.assertEqual(ref['region_id'], entity.get('region_id'))

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
        self.assertNotIn('tenantId', entity)
        if ref:
            self.assertEqual(ref['domain_id'], entity['domain_id'])
            self.assertEqual(ref['email'], entity['email'])
            if 'default_project_id' in ref:
                self.assertIsNotNone(ref['default_project_id'])
                self.assertEqual(ref['default_project_id'],
                                 entity['default_project_id'])
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
            keys_to_check=['blob', 'user_id', 'type'],
            *args,
            **kwargs)

    def assertValidCredentialResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'credential',
            self.assertValidCredential,
            keys_to_check=['blob', 'user_id', 'type'],
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

    # role assignment validation

    def assertValidRoleAssignmentListResponse(self, resp, expected_length=None,
                                              resource_url=None):
        entities = resp.result.get('role_assignments')

        if expected_length:
            self.assertEqual(expected_length, len(entities))

        # Collections should have relational links
        self.assertValidListLinks(resp.result.get('links'),
                                  resource_url=resource_url)

        for entity in entities:
            self.assertIsNotNone(entity)
            self.assertValidRoleAssignment(entity)
        return entities

    def assertValidRoleAssignment(self, entity, ref=None):
        # A role should be present
        self.assertIsNotNone(entity.get('role'))
        self.assertIsNotNone(entity['role'].get('id'))

        # Only one of user or group should be present
        if entity.get('user'):
            self.assertIsNone(entity.get('group'))
            self.assertIsNotNone(entity['user'].get('id'))
        else:
            self.assertIsNotNone(entity.get('group'))
            self.assertIsNotNone(entity['group'].get('id'))

        # A scope should be present and have only one of domain or project
        self.assertIsNotNone(entity.get('scope'))

        if entity['scope'].get('project'):
            self.assertIsNone(entity['scope'].get('domain'))
            self.assertIsNotNone(entity['scope']['project'].get('id'))
        else:
            self.assertIsNotNone(entity['scope'].get('domain'))
            self.assertIsNotNone(entity['scope']['domain'].get('id'))

        # An assignment link should be present
        self.assertIsNotNone(entity.get('links'))
        self.assertIsNotNone(entity['links'].get('assignment'))

        if ref:
            links = ref.pop('links')
            try:
                self.assertDictContainsSubset(ref, entity)
                self.assertIn(links['assignment'],
                              entity['links']['assignment'])
            finally:
                if links:
                    ref['links'] = links

    def assertRoleAssignmentInListResponse(self, resp, ref, expected=1):

        found_count = 0
        for entity in resp.result.get('role_assignments'):
            try:
                self.assertValidRoleAssignment(entity, ref=ref)
            except Exception:
                # It doesn't match, so let's go onto the next one
                pass
            else:
                found_count += 1
        self.assertEqual(expected, found_count)

    def assertRoleAssignmentNotInListResponse(self, resp, ref):
        self.assertRoleAssignmentInListResponse(resp, ref=ref, expected=0)

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
            self.assertValidTrustSummary,
            keys_to_check=['trustor_user_id',
                           'trustee_user_id',
                           'impersonation'],
            *args,
            **kwargs)

    def assertValidTrustResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'trust',
            self.assertValidTrust,
            keys_to_check=['trustor_user_id',
                           'trustee_user_id',
                           'impersonation'],
            *args,
            **kwargs)

    def assertValidTrustSummary(self, entity, ref=None):
        return self.assertValidTrust(entity, ref, summary=True)

    def assertValidTrust(self, entity, ref=None, summary=False):
        self.assertIsNotNone(entity.get('trustor_user_id'))
        self.assertIsNotNone(entity.get('trustee_user_id'))
        self.assertIsNotNone(entity.get('impersonation'))

        self.assertIn('expires_at', entity)
        if entity['expires_at'] is not None:
            self.assertValidISO8601ExtendedFormatDatetime(entity['expires_at'])

        if summary:
            # Trust list contains no roles, but getting a specific
            # trust by ID provides the detailed response containing roles
            self.assertNotIn('roles', entity)
            self.assertIn('project_id', entity)
        else:
            for role in entity['roles']:
                self.assertIsNotNone(role)
                self.assertValidEntity(role, keys_to_check=['name'])
                self.assertValidRole(role)

            self.assertValidListLinks(entity.get('roles_links'))

            # always disallow role xor project_id (neither or both is allowed)
            has_roles = bool(entity.get('roles'))
            has_project = bool(entity.get('project_id'))
            self.assertFalse(has_roles ^ has_project)

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

    def build_external_auth_request(self, remote_user,
                                    remote_domain=None, auth_data=None,
                                    kerberos=False):
        context = {'environment': {'REMOTE_USER': remote_user,
                                   'AUTH_TYPE': 'Negotiate'}}
        if remote_domain:
            context['environment']['REMOTE_DOMAIN'] = remote_domain
        if not auth_data:
            auth_data = self.build_authentication_request(
                kerberos=kerberos)['auth']
        no_context = None
        auth_info = auth.controllers.AuthInfo.create(no_context, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        return context, auth_info, auth_context


class VersionTestCase(RestfulTestCase):
    def test_get_version(self):
        pass


# NOTE(gyee): test AuthContextMiddleware here instead of test_middleware.py
# because we need the token
class AuthContextMiddlewareTestCase(RestfulTestCase):
    def _mock_request_object(self, token_id):

        class fake_req(object):
            headers = {middleware.AUTH_TOKEN_HEADER: token_id}
            environ = {}

        return fake_req()

    def test_auth_context_build_by_middleware(self):
        # test to make sure AuthContextMiddleware successful build the auth
        # context from the incoming auth token
        admin_token = self.get_scoped_token()
        req = self._mock_request_object(admin_token)
        application = None
        middleware.AuthContextMiddleware(application).process_request(req)
        self.assertEqual(
            self.user['id'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['user_id'])

    def test_auth_context_override(self):
        overridden_context = 'OVERRIDDEN_CONTEXT'
        # this token should not be used
        token = uuid.uuid4().hex
        req = self._mock_request_object(token)
        req.environ[authorization.AUTH_CONTEXT_ENV] = overridden_context
        application = None
        middleware.AuthContextMiddleware(application).process_request(req)
        # make sure overridden context take precedence
        self.assertEqual(overridden_context,
                         req.environ.get(authorization.AUTH_CONTEXT_ENV))

    def test_admin_token_auth_context(self):
        # test to make sure AuthContextMiddleware does not attempt to build
        # auth context if the incoming auth token is the special admin token
        req = self._mock_request_object(CONF.admin_token)
        application = None
        middleware.AuthContextMiddleware(application).process_request(req)
        self.assertDictEqual(req.environ.get(authorization.AUTH_CONTEXT_ENV),
                             {})

    def test_unscoped_token_auth_context(self):
        unscoped_token = self.get_unscoped_token()
        req = self._mock_request_object(unscoped_token)
        application = None
        middleware.AuthContextMiddleware(application).process_request(req)
        for key in ['project_id', 'domain_id', 'domain_name']:
            self.assertNotIn(
                key,
                req.environ.get(authorization.AUTH_CONTEXT_ENV))

    def test_project_scoped_token_auth_context(self):
        project_scoped_token = self.get_scoped_token()
        req = self._mock_request_object(project_scoped_token)
        application = None
        middleware.AuthContextMiddleware(application).process_request(req)
        self.assertEqual(
            self.project['id'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['project_id'])

    def test_domain_scoped_token_auth_context(self):
        # grant the domain role to user
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        domain_scoped_token = self.get_domain_scoped_token()
        req = self._mock_request_object(domain_scoped_token)
        application = None
        middleware.AuthContextMiddleware(application).process_request(req)
        self.assertEqual(
            self.domain['id'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['domain_id'])
        self.assertEqual(
            self.domain['name'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['domain_name'])


class JsonHomeTestMixin(object):
    """JSON Home test

    Mixin this class to provide a test for the JSON-Home response for an
    extension.

    The base class must set JSON_HOME_DATA to a dict of relationship URLs
    (rels) to the JSON-Home data for the relationship. The rels and associated
    data must be in the response.

    """
    def test_get_json_home(self):
        resp = self.get('/', convert=False,
                        headers={'Accept': 'application/json-home'})
        self.assertThat(resp.headers['Content-Type'],
                        matchers.Equals('application/json-home'))
        resp_data = jsonutils.loads(resp.body)

        # Check that the example relationships are present.
        for rel in self.JSON_HOME_DATA:
            self.assertThat(resp_data['resources'][rel],
                            matchers.Equals(self.JSON_HOME_DATA[rel]))


class AssignmentTestMixin(object):
    """To hold assignment helper functions."""

    def build_role_assignment_query_url(self, effective=False, **filters):
        """Build and return a role assignment query url with provided params.

        Available filters are: domain_id, project_id, user_id, group_id,
        role_id and inherited_to_projects.
        """

        query_params = '?effective' if effective else ''

        for k, v in filters.items():
            query_params += '?' if not query_params else '&'

            if k == 'inherited_to_projects':
                query_params += 'scope.OS-INHERIT:inherited_to=projects'
            else:
                if k in ['domain_id', 'project_id']:
                    query_params += 'scope.'
                elif k not in ['user_id', 'group_id', 'role_id']:
                    raise ValueError(
                        'Invalid key \'%s\' in provided filters.' % k)

                query_params += '%s=%s' % (k.replace('_', '.'), v)

        return '/role_assignments%s' % query_params

    def build_role_assignment_link(self, **attribs):
        """Build and return a role assignment link with provided attributes.

        Provided attributes are expected to contain: domain_id or project_id,
        user_id or group_id, role_id and, optionally, inherited_to_projects.
        """

        if attribs.get('domain_id'):
            link = '/domains/' + attribs['domain_id']
        else:
            link = '/projects/' + attribs['project_id']

        if attribs.get('user_id'):
            link += '/users/' + attribs['user_id']
        else:
            link += '/groups/' + attribs['group_id']

        link += '/roles/' + attribs['role_id']

        if attribs.get('inherited_to_projects'):
            return '/OS-INHERIT%s/inherited_to_projects' % link

        return link

    def build_role_assignment_entity(self, link=None, **attribs):
        """Build and return a role assignment entity with provided attributes.

        Provided attributes are expected to contain: domain_id or project_id,
        user_id or group_id, role_id and, optionally, inherited_to_projects.
        """

        entity = {'links': {'assignment': (
            link or self.build_role_assignment_link(**attribs))}}

        if attribs.get('domain_id'):
            entity['scope'] = {'domain': {'id': attribs['domain_id']}}
        else:
            entity['scope'] = {'project': {'id': attribs['project_id']}}

        if attribs.get('user_id'):
            entity['user'] = {'id': attribs['user_id']}

            if attribs.get('group_id'):
                entity['links']['membership'] = ('/groups/%s/users/%s' %
                                                 (attribs['group_id'],
                                                  attribs['user_id']))
        else:
            entity['group'] = {'id': attribs['group_id']}

        entity['role'] = {'id': attribs['role_id']}

        if attribs.get('inherited_to_projects'):
            entity['scope']['OS-INHERIT:inherited_to'] = 'projects'

        return entity
