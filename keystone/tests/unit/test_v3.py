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
import http.client
import oslo_context.context
from oslo_serialization import jsonutils
from testtools import matchers
import uuid
import webtest

from keystone.common import authorization
from keystone.common import cache
from keystone.common import provider_api
from keystone.common.validation import validators
from keystone import exception
from keystone.resource.backends import base as resource_base
from keystone.server.flask.request_processing.middleware import auth_context
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import rest


PROVIDERS = provider_api.ProviderAPIs
DEFAULT_DOMAIN_ID = 'default'

TIME_FORMAT = unit.TIME_FORMAT


class RestfulTestCase(unit.SQLDriverOverrides, rest.RestfulTestCase,
                      common_auth.AuthTestMixin):

    def generate_token_schema(self, system_scoped=False, domain_scoped=False,
                              project_scoped=False):
        """Return a dictionary of token properties to validate against."""
        ROLES_SCHEMA = {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string', },
                    'name': {'type': 'string', },
                    'description': {'type': 'string', },
                    'options': {'type': 'object', }
                },
                'required': ['id', 'name', ],
                'additionalProperties': False,
            },
            'minItems': 1,
        }

        properties = {
            'audit_ids': {
                'type': 'array',
                'items': {
                    'type': 'string',
                },
                'minItems': 1,
                'maxItems': 2,
            },
            'expires_at': {
                'type': 'string',
                'pattern': unit.TIME_FORMAT_REGEX,
            },
            'issued_at': {
                'type': 'string',
                'pattern': unit.TIME_FORMAT_REGEX,
            },
            'methods': {
                'type': 'array',
                'items': {
                    'type': 'string',
                },
            },
            'user': {
                'type': 'object',
                'required': ['id', 'name', 'domain', 'password_expires_at'],
                'properties': {
                    'id': {'type': 'string'},
                    'name': {'type': 'string'},
                    'domain': {
                        'type': 'object',
                        'properties': {
                            'id': {'type': 'string'},
                            'name': {'type': 'string'}
                        },
                        'required': ['id', 'name'],
                        'additonalProperties': False,
                    },
                    'password_expires_at': {
                        'type': ['string', 'null'],
                        'pattern': unit.TIME_FORMAT_REGEX,
                    }
                },
                'additionalProperties': False,
            }
        }

        if system_scoped:
            properties['catalog'] = {'type': 'array'}
            properties['system'] = {
                'type': 'object',
                'properties': {
                    'all': {'type': 'boolean'}
                }
            }
            properties['roles'] = ROLES_SCHEMA
        elif domain_scoped:
            properties['catalog'] = {'type': 'array'}
            properties['roles'] = ROLES_SCHEMA
            properties['domain'] = {
                'type': 'object',
                'required': ['id', 'name'],
                'properties': {
                    'id': {'type': 'string'},
                    'name': {'type': 'string'}
                },
                'additionalProperties': False
            }
        elif project_scoped:
            properties['is_admin_project'] = {'type': 'boolean'}
            properties['catalog'] = {'type': 'array'}
            # FIXME(lbragstad): Remove this in favor of the predefined
            # ROLES_SCHEMA dictionary once bug 1763510 is fixed.
            ROLES_SCHEMA['items']['properties']['domain_id'] = {
                'type': ['null', 'string', ],
            }
            properties['roles'] = ROLES_SCHEMA
            properties['is_domain'] = {'type': 'boolean'}
            properties['project'] = {
                'type': ['object'],
                'required': ['id', 'name', 'domain'],
                'properties': {
                    'id': {'type': 'string'},
                    'name': {'type': 'string'},
                    'domain': {
                        'type': ['object'],
                        'required': ['id', 'name'],
                        'properties': {
                            'id': {'type': 'string'},
                            'name': {'type': 'string'}
                        },
                        'additionalProperties': False
                    }
                },
                'additionalProperties': False
            }

        schema = {
            'type': 'object',
            'properties': properties,
            'required': ['audit_ids', 'expires_at', 'issued_at', 'methods',
                         'user'],
            'optional': [],
            'additionalProperties': False
        }

        if system_scoped:
            schema['required'].extend(['system', 'roles'])
            schema['optional'].append('catalog')
        elif domain_scoped:
            schema['required'].extend(['domain', 'roles'])
            schema['optional'].append('catalog')
        elif project_scoped:
            schema['required'].append('project')
            schema['optional'].append('catalog')
            schema['optional'].append('OS-TRUST:trust')
            schema['optional'].append('is_admin_project')
            schema['optional'].append('is_domain')

        return schema

    def config_files(self):
        config_files = super(RestfulTestCase, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def setUp(self):
        """Setup for v3 Restful Test Cases."""
        super(RestfulTestCase, self).setUp()

        self.empty_context = {'environment': {}}

    def load_backends(self):
        # ensure the cache region instance is setup
        cache.configure_cache()

        super(RestfulTestCase, self).load_backends()

    def load_fixtures(self, fixtures):
        self.load_sample_data()

    def _populate_default_domain(self):
        try:
            PROVIDERS.resource_api.get_domain(DEFAULT_DOMAIN_ID)
        except exception.DomainNotFound:
            root_domain = unit.new_domain_ref(
                id=resource_base.NULL_DOMAIN_ID,
                name=resource_base.NULL_DOMAIN_ID
            )
            PROVIDERS.resource_api.create_domain(resource_base.NULL_DOMAIN_ID,
                                                 root_domain)
            domain = unit.new_domain_ref(
                description=(u'The default domain'),
                id=DEFAULT_DOMAIN_ID,
                name=u'Default')
            PROVIDERS.resource_api.create_domain(DEFAULT_DOMAIN_ID, domain)

    def load_sample_data(self, create_region_and_endpoints=True):
        self._populate_default_domain()
        self.domain = unit.new_domain_ref()
        self.domain_id = self.domain['id']
        PROVIDERS.resource_api.create_domain(self.domain_id, self.domain)

        self.project = unit.new_project_ref(domain_id=self.domain_id)
        self.project_id = self.project['id']
        self.project = PROVIDERS.resource_api.create_project(
            self.project_id, self.project
        )

        self.user = unit.create_user(PROVIDERS.identity_api,
                                     domain_id=self.domain_id)
        self.user_id = self.user['id']

        self.default_domain_project_id = uuid.uuid4().hex
        self.default_domain_project = unit.new_project_ref(
            domain_id=DEFAULT_DOMAIN_ID)
        self.default_domain_project['id'] = self.default_domain_project_id
        PROVIDERS.resource_api.create_project(
            self.default_domain_project_id, self.default_domain_project
        )

        self.default_domain_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=DEFAULT_DOMAIN_ID)
        self.default_domain_user_id = self.default_domain_user['id']

        # create & grant policy.yaml's default role for admin_required
        self.role = unit.new_role_ref(name='admin')
        self.role_id = self.role['id']
        PROVIDERS.role_api.create_role(self.role_id, self.role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, self.role_id)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.default_domain_user_id, self.default_domain_project_id,
            self.role_id)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.default_domain_user_id, self.project_id,
            self.role_id)

        # Create "req_admin" user for simulating a real user instead of the
        # admin_token_auth middleware
        self.user_reqadmin = unit.create_user(PROVIDERS.identity_api,
                                              DEFAULT_DOMAIN_ID)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_reqadmin['id'],
            self.default_domain_project_id,
            self.role_id)

        if create_region_and_endpoints:
            self.region = unit.new_region_ref()
            self.region_id = self.region['id']
            PROVIDERS.catalog_api.create_region(self.region)

            self.service = unit.new_service_ref()
            self.service_id = self.service['id']
            PROVIDERS.catalog_api.create_service(
                self.service_id, self.service.copy()
            )

            self.endpoint = unit.new_endpoint_ref(service_id=self.service_id,
                                                  interface='public',
                                                  region_id=self.region_id)
            self.endpoint_id = self.endpoint['id']
            PROVIDERS.catalog_api.create_endpoint(
                self.endpoint_id, self.endpoint.copy()
            )
            # The server adds 'enabled' and defaults to True.
            self.endpoint['enabled'] = True

    def create_new_default_project_for_user(self, user_id, domain_id,
                                            enable_project=True):
        ref = unit.new_project_ref(domain_id=domain_id, enabled=enable_project)
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)
        # set the user's preferred project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': user_id},
            body=body)
        self.assertValidUserResponse(r)

        return project

    def get_admin_token(self):
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
                                'name': self.user_reqadmin['name'],
                                'password': self.user_reqadmin['password'],
                                'domain': {
                                    'id': self.user_reqadmin['domain_id']
                                }
                            }
                        }
                    },
                    'scope': {
                        'project': {
                            'id': self.default_domain_project_id,
                        }
                    }
                }
            })
        return r.headers.get('X-Subject-Token')

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

    def get_system_scoped_token(self):
        """Convenience method for requesting system scoped tokens."""
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
                        'system': {'all': True}
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
        r = self.v3_create_token(auth)
        return r.headers.get('X-Subject-Token')

    def v3_create_token(self, auth, expected_status=http.client.CREATED):
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

    def get(self, path, expected_status=http.client.OK, **kwargs):
        return self.v3_request(path, method='GET',
                               expected_status=expected_status, **kwargs)

    def head(self, path, expected_status=http.client.NO_CONTENT, **kwargs):
        r = self.v3_request(path, method='HEAD',
                            expected_status=expected_status, **kwargs)
        self.assertEqual(b'', r.body)
        return r

    def post(self, path, expected_status=http.client.CREATED, **kwargs):
        return self.v3_request(path, method='POST',
                               expected_status=expected_status, **kwargs)

    def put(self, path, expected_status=http.client.NO_CONTENT, **kwargs):
        return self.v3_request(path, method='PUT',
                               expected_status=expected_status, **kwargs)

    def patch(self, path, expected_status=http.client.OK, **kwargs):
        return self.v3_request(path, method='PATCH',
                               expected_status=expected_status, **kwargs)

    def delete(self, path, expected_status=http.client.NO_CONTENT, **kwargs):
        return self.v3_request(path, method='DELETE',
                               expected_status=expected_status, **kwargs)

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
            return datetime.datetime.strptime(dt, TIME_FORMAT)
        except Exception:
            msg = '%s is not a valid ISO 8601 extended format date time.' % dt
            raise AssertionError(msg)

    def assertValidTokenResponse(self, r, user=None, forbid_token_id=False):
        if forbid_token_id:
            self.assertNotIn('X-Subject-Token', r.headers)
        else:
            self.assertTrue(r.headers.get('X-Subject-Token'))
        token = r.result['token']

        self.assertIsNotNone(token.get('expires_at'))
        expires_at = self.assertValidISO8601ExtendedFormatDatetime(
            token['expires_at'])
        self.assertIsNotNone(token.get('issued_at'))
        issued_at = self.assertValidISO8601ExtendedFormatDatetime(
            token['issued_at'])
        self.assertLess(issued_at, expires_at)

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
        validator_object = validators.SchemaValidator(
            self.generate_token_schema()
        )
        validator_object.validate(token)

        return token

    def assertValidScopedTokenResponse(self, r, *args, **kwargs):
        require_catalog = kwargs.pop('require_catalog', True)
        endpoint_filter = kwargs.pop('endpoint_filter', False)
        ep_filter_assoc = kwargs.pop('ep_filter_assoc', 0)
        is_admin_project = kwargs.pop('is_admin_project', None)
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

        # NOTE(samueldmq): We want to explicitly test for boolean or None
        self.assertIs(is_admin_project, token.get('is_admin_project'))

        return token

    def assertValidProjectScopedTokenResponse(self, r, *args, **kwargs):
        token = self.assertValidScopedTokenResponse(r, *args, **kwargs)

        project_scoped_token_schema = self.generate_token_schema(
            project_scoped=True)

        if token.get('OS-TRUST:trust'):
            trust_properties = {
                'OS-TRUST:trust': {
                    'type': ['object'],
                    'required': ['id', 'impersonation', 'trustor_user',
                                 'trustee_user'],
                    'properties': {
                        'id': {'type': 'string'},
                        'impersonation': {'type': 'boolean'},
                        'trustor_user': {
                            'type': 'object',
                            'required': ['id'],
                            'properties': {
                                'id': {'type': 'string'}
                            },
                            'additionalProperties': False
                        },
                        'trustee_user': {
                            'type': 'object',
                            'required': ['id'],
                            'properties': {
                                'id': {'type': 'string'}
                            },
                            'additionalProperties': False
                        }
                    },
                    'additionalProperties': False
                }
            }
            project_scoped_token_schema['properties'].update(trust_properties)

        validator_object = validators.SchemaValidator(
            project_scoped_token_schema)
        validator_object.validate(token)

        self.assertEqual(self.role_id, token['roles'][0]['id'])

        return token

    def assertValidDomainScopedTokenResponse(self, r, *args, **kwargs):
        token = self.assertValidScopedTokenResponse(r, *args, **kwargs)

        validator_object = validators.SchemaValidator(
            self.generate_token_schema(domain_scoped=True)
        )
        validator_object.validate(token)

        return token

    def assertValidSystemScopedTokenResponse(self, r, *args, **kwargs):
        token = self.assertValidTokenResponse(r)
        self.assertTrue(token['system']['all'])

        system_scoped_token_schema = self.generate_token_schema(
            system_scoped=True
        )
        validator_object = validators.SchemaValidator(
            system_scoped_token_schema
        )
        validator_object.validate(token)

        return token

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
        self.assertGreater(len(entity), 0)
        for service in entity:
            self.assertIsNotNone(service.get('id'))
            self.assertIsNotNone(service.get('name'))
            self.assertIsNotNone(service.get('type'))
            self.assertNotIn('enabled', service)
            self.assertGreater(len(service['endpoints']), 0)
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
        if ref:
            self.assertEqual(ref['domain_id'], entity['domain_id'])
        return entity

    # user validation

    def assertValidUserListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'users',
            self.assertValidUser,
            keys_to_check=['name', 'enabled'],
            *args,
            **kwargs)

    def assertValidUserResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'user',
            self.assertValidUser,
            keys_to_check=['name', 'enabled'],
            *args,
            **kwargs)

    def assertValidUser(self, entity, ref=None):
        self.assertIsNotNone(entity.get('domain_id'))
        self.assertIsNotNone(entity.get('email'))
        self.assertNotIn('password', entity)
        self.assertNotIn('projectId', entity)
        self.assertIn('password_expires_at', entity)
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
            keys_to_check=['name', 'description', 'domain_id'],
            *args,
            **kwargs)

    def assertValidGroupResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'group',
            self.assertValidGroup,
            keys_to_check=['name', 'description', 'domain_id'],
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
        self.assertNotIn('key_hash', entity)
        self.assertNotIn('encrypted_blob', entity)
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

    def assertRoleInListResponse(self, resp, ref, expected=1):
        found_count = 0
        for entity in resp.result.get('roles'):
            try:
                self.assertValidRole(entity, ref=ref)
            except Exception:
                # It doesn't match, so let's go onto the next one
                pass
            else:
                found_count += 1
        self.assertEqual(expected, found_count)

    def assertRoleNotInListResponse(self, resp, ref):
        self.assertRoleInListResponse(resp, ref=ref, expected=0)

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
            self.assertEqual(ref['domain_id'], entity['domain_id'])
        return entity

    # role assignment validation

    def assertValidRoleAssignmentListResponse(self, resp, expected_length=None,
                                              resource_url=None):
        entities = resp.result.get('role_assignments')

        if expected_length or expected_length == 0:
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
            self.assertNotIn('group', entity)
            self.assertIsNotNone(entity['user'].get('id'))
        else:
            self.assertIsNotNone(entity.get('group'))
            self.assertIsNotNone(entity['group'].get('id'))

        # A scope should be present and have only one of domain or project
        self.assertIsNotNone(entity.get('scope'))

        if entity['scope'].get('project'):
            self.assertNotIn('domain', entity['scope'])
            self.assertIsNotNone(entity['scope']['project'].get('id'))
        elif entity['scope'].get('domain'):
            self.assertIsNotNone(entity['scope'].get('domain'))
            self.assertIsNotNone(entity['scope']['domain'].get('id'))
        else:
            self.assertIsNotNone(entity['scope'].get('system'))
            self.assertTrue(entity['scope']['system']['all'])

        # An assignment link should be present
        self.assertIsNotNone(entity.get('links'))
        self.assertIsNotNone(entity['links'].get('assignment'))

        if ref:
            links = ref.pop('links')
            try:
                self.assertLessEqual(ref.items(), entity.items())
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
            # Mirror the test tempest does to ensure the self-link is correct
            self.assertIn('v3/OS-TRUST/trusts', entity.get('links')['self'])

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

    # Service providers (federation)

    def assertValidServiceProvider(self, entity, ref=None, *args, **kwargs):

        attributes = frozenset(['auth_url', 'id', 'enabled', 'description',
                                'links', 'relay_state_prefix', 'sp_url'])
        for attribute in attributes:
            self.assertIsNotNone(entity.get(attribute))

    def build_external_auth_environ(self, remote_user, remote_domain=None):
        environment = {'REMOTE_USER': remote_user, 'AUTH_TYPE': 'Negotiate'}
        if remote_domain:
            environment['REMOTE_DOMAIN'] = remote_domain
        return environment


class OAuth2RestfulTestCase(RestfulTestCase):
    def assertValidErrorResponse(self, response):
        resp = response.result
        self.assertIsNotNone(resp.get('error'))
        self.assertIsNotNone(resp.get('error_description'))


class VersionTestCase(RestfulTestCase):
    def test_get_version(self):
        pass


# NOTE(gyee): test AuthContextMiddleware here instead of test_middleware.py
# because we need the token
class AuthContextMiddlewareTestCase(RestfulTestCase):

    def _middleware_request(self, token, extra_environ=None):

        def application(environ, start_response):
            body = b'body'
            headers = [('Content-Type', 'text/html; charset=utf8'),
                       ('Content-Length', str(len(body)))]
            start_response('200 OK', headers)
            return [body]

        app = webtest.TestApp(auth_context.AuthContextMiddleware(application),
                              extra_environ=extra_environ)
        resp = app.get('/', headers={authorization.AUTH_TOKEN_HEADER: token})
        self.assertEqual(b'body', resp.body)  # just to make sure it worked
        return resp.request

    def test_auth_context_build_by_middleware(self):
        # test to make sure AuthContextMiddleware successful build the auth
        # context from the incoming auth token
        admin_token = self.get_scoped_token()
        req = self._middleware_request(admin_token)
        self.assertEqual(
            self.user['id'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['user_id'])

    def test_auth_context_override(self):
        overridden_context = 'OVERRIDDEN_CONTEXT'
        # this token should not be used
        token = uuid.uuid4().hex

        extra_environ = {authorization.AUTH_CONTEXT_ENV: overridden_context}
        req = self._middleware_request(token, extra_environ=extra_environ)
        # make sure overridden context take precedence
        self.assertEqual(overridden_context,
                         req.environ.get(authorization.AUTH_CONTEXT_ENV))

    def test_unscoped_token_auth_context(self):
        unscoped_token = self.get_unscoped_token()
        req = self._middleware_request(unscoped_token)
        # This check originally looked that the value was unset
        # but that was an artifact of the custom context keystone
        # used to create.  Oslo-context will always provide the
        # same set of keys, but the values will be None in an
        # unscoped token
        for key in ['project_id', 'domain_id', 'domain_name']:
            self.assertIsNone(
                req.environ.get(authorization.AUTH_CONTEXT_ENV)[key])

    def test_project_scoped_token_auth_context(self):
        project_scoped_token = self.get_scoped_token()
        req = self._middleware_request(project_scoped_token)
        self.assertEqual(
            self.project['id'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['project_id'])

    def test_domain_scoped_token_auth_context(self):
        # grant the domain role to user
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        domain_scoped_token = self.get_domain_scoped_token()
        req = self._middleware_request(domain_scoped_token)
        self.assertEqual(
            self.domain['id'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['domain_id'])
        self.assertEqual(
            self.domain['name'],
            req.environ.get(authorization.AUTH_CONTEXT_ENV)['domain_name'])

    def test_oslo_context(self):
        # After AuthContextMiddleware runs, an
        # oslo_context.context.RequestContext was created so that its fields
        # can be logged. This test validates that the RequestContext was
        # created and the fields are set as expected.

        # Use a scoped token so more fields can be set.
        token = self.get_scoped_token()

        # oslo_middleware RequestId middleware sets openstack.request_id.
        request_id = uuid.uuid4().hex
        environ = {'openstack.request_id': request_id}
        self._middleware_request(token, extra_environ=environ)

        req_context = oslo_context.context.get_current()
        self.assertEqual(request_id, req_context.request_id)
        self.assertEqual(token, req_context.auth_token)
        self.assertEqual(self.user['id'], req_context.user_id)
        self.assertEqual(self.project['id'], req_context.project_id)
        self.assertIsNone(req_context.domain_id)
        self.assertEqual(self.user['domain_id'], req_context.user_domain_id)
        self.assertEqual(self.project['domain_id'],
                         req_context.project_domain_id)
        self.assertFalse(req_context.is_admin)


class JsonHomeTestMixin(object):
    """JSON Home test.

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
        elif attribs.get('system'):
            link = '/system'
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

    def build_role_assignment_entity(
            self, link=None, prior_role_link=None, **attribs):
        """Build and return a role assignment entity with provided attributes.

        Provided attributes are expected to contain: domain_id or project_id,
        user_id or group_id, role_id and, optionally, inherited_to_projects.
        """
        entity = {'links': {'assignment': (
            link or self.build_role_assignment_link(**attribs))}}

        if attribs.get('domain_id'):
            entity['scope'] = {'domain': {'id': attribs['domain_id']}}
        elif attribs.get('system'):
            entity['scope'] = {'system': {'all': True}}
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

        if prior_role_link:
            entity['links']['prior_role'] = prior_role_link

        return entity

    def build_role_assignment_entity_include_names(self,
                                                   domain_ref=None,
                                                   role_ref=None,
                                                   group_ref=None,
                                                   user_ref=None,
                                                   project_ref=None,
                                                   inherited_assignment=None):
        """Build and return a role assignment entity with provided attributes.

        The expected attributes are: domain_ref or project_ref,
        user_ref or group_ref, role_ref and, optionally, inherited_to_projects.
        """
        entity = {'links': {}}
        attributes_for_links = {}
        if project_ref:
            dmn_name = PROVIDERS.resource_api.get_domain(
                project_ref['domain_id'])['name']

            entity['scope'] = {'project': {
                               'id': project_ref['id'],
                               'name': project_ref['name'],
                               'domain': {
                                   'id': project_ref['domain_id'],
                                   'name': dmn_name}}}
            attributes_for_links['project_id'] = project_ref['id']
        else:
            entity['scope'] = {'domain': {'id': domain_ref['id'],
                                          'name': domain_ref['name']}}
            attributes_for_links['domain_id'] = domain_ref['id']
        if user_ref:
            dmn_name = PROVIDERS.resource_api.get_domain(
                user_ref['domain_id'])['name']
            entity['user'] = {'id': user_ref['id'],
                              'name': user_ref['name'],
                              'domain': {'id': user_ref['domain_id'],
                                         'name': dmn_name}}
            attributes_for_links['user_id'] = user_ref['id']
        else:
            dmn_name = PROVIDERS.resource_api.get_domain(
                group_ref['domain_id'])['name']
            entity['group'] = {'id': group_ref['id'],
                               'name': group_ref['name'],
                               'domain': {
                                   'id': group_ref['domain_id'],
                                   'name': dmn_name}}
            attributes_for_links['group_id'] = group_ref['id']

        if role_ref:
            entity['role'] = {'id': role_ref['id'],
                              'name': role_ref['name']}
            if role_ref['domain_id']:
                dmn_name = PROVIDERS.resource_api.get_domain(
                    role_ref['domain_id'])['name']
                entity['role']['domain'] = {'id': role_ref['domain_id'],
                                            'name': dmn_name}
            attributes_for_links['role_id'] = role_ref['id']

        if inherited_assignment:
            entity['scope']['OS-INHERIT:inherited_to'] = 'projects'
            attributes_for_links['inherited_to_projects'] = True

        entity['links']['assignment'] = self.build_role_assignment_link(
            **attributes_for_links)

        return entity
