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

import copy
import os
import random
import re
import subprocess
from testtools import matchers
from unittest import mock
import uuid

import fixtures
import flask
import http.client
from lxml import etree
from oslo_serialization import jsonutils
from oslo_utils import importutils
import saml2
from saml2 import saml
from saml2 import sigver
import urllib
xmldsig = importutils.try_import("saml2.xmldsig")
if not xmldsig:
    xmldsig = importutils.try_import("xmldsig")

from keystone.api._shared import authentication
from keystone.api import auth as auth_api
from keystone.common import driver_hints
from keystone.common import provider_api
from keystone.common import render_token
import keystone.conf
from keystone import exception
from keystone.federation import idp as keystone_idp
from keystone.models import token_model
from keystone import notifications
from keystone.tests import unit
from keystone.tests.unit import core
from keystone.tests.unit import federation_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import mapping_fixtures
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs
ROOTDIR = os.path.dirname(os.path.abspath(__file__))
XMLDIR = os.path.join(ROOTDIR, 'saml2/')


def dummy_validator(*args, **kwargs):
    pass


class FederatedSetupMixin(object):

    ACTION = 'authenticate'
    IDP = 'ORG_IDP'
    PROTOCOL = 'saml2'
    AUTH_METHOD = 'saml2'
    USER = 'user@ORGANIZATION'
    ASSERTION_PREFIX = 'PREFIX_'
    IDP_WITH_REMOTE = 'ORG_IDP_REMOTE'
    REMOTE_IDS = ['entityID_IDP1', 'entityID_IDP2']
    REMOTE_ID_ATTR = uuid.uuid4().hex

    UNSCOPED_V3_SAML2_REQ = {
        "identity": {
            "methods": [AUTH_METHOD],
            AUTH_METHOD: {
                "identity_provider": IDP,
                "protocol": PROTOCOL
            }
        }
    }

    def _check_domains_are_valid(self, token):
        domain = PROVIDERS.resource_api.get_domain(self.idp['domain_id'])
        self.assertEqual(domain['id'], token['user']['domain']['id'])
        self.assertEqual(domain['name'], token['user']['domain']['name'])

    def _project(self, project):
        return (project['id'], project['name'])

    def _roles(self, roles):
        return set([(r['id'], r['name']) for r in roles])

    def _check_projects_and_roles(self, token, roles, projects):
        """Check whether the projects and the roles match."""
        token_roles = token.get('roles')
        if token_roles is None:
            raise AssertionError('Roles not found in the token')
        token_roles = self._roles(token_roles)
        roles_ref = self._roles(roles)
        self.assertEqual(token_roles, roles_ref)

        token_projects = token.get('project')
        if token_projects is None:
            raise AssertionError('Projects not found in the token')
        token_projects = self._project(token_projects)
        projects_ref = self._project(projects)
        self.assertEqual(token_projects, projects_ref)

    def _check_scoped_token_attributes(self, token):

        for obj in ('user', 'catalog', 'expires_at', 'issued_at',
                    'methods', 'roles'):
            self.assertIn(obj, token)

        os_federation = token['user']['OS-FEDERATION']

        self.assertIn('groups', os_federation)
        self.assertIn('identity_provider', os_federation)
        self.assertIn('protocol', os_federation)
        self.assertThat(os_federation, matchers.HasLength(3))

        self.assertEqual(self.IDP, os_federation['identity_provider']['id'])
        self.assertEqual(self.PROTOCOL, os_federation['protocol']['id'])

    def _check_project_scoped_token_attributes(self, token, project_id):
        self.assertEqual(project_id, token['project']['id'])
        self._check_scoped_token_attributes(token)

    def _check_domain_scoped_token_attributes(self, token, domain_id):
        self.assertEqual(domain_id, token['domain']['id'])
        self._check_scoped_token_attributes(token)

    def assertValidMappedUser(self, token):
        """Check if user object meets all the criteria."""
        user = token['user']
        self.assertIn('id', user)
        self.assertIn('name', user)
        self.assertIn('domain', user)

        self.assertIn('groups', user['OS-FEDERATION'])
        self.assertIn('identity_provider', user['OS-FEDERATION'])
        self.assertIn('protocol', user['OS-FEDERATION'])

        # Make sure user_name is url safe
        self.assertEqual(urllib.parse.quote(user['name']), user['name'])

    def _issue_unscoped_token(self,
                              idp=None,
                              assertion='EMPLOYEE_ASSERTION',
                              environment=None):
        environment = environment or {}
        environment.update(getattr(mapping_fixtures, assertion))
        with self.make_request(environ=environment):
            if idp is None:
                idp = self.IDP
            r = authentication.federated_authenticate_for_token(
                protocol_id=self.PROTOCOL, identity_provider=idp)
        return r

    def idp_ref(self, id=None):
        idp = {
            'id': id or uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        return idp

    def proto_ref(self, mapping_id=None):
        proto = {
            'id': uuid.uuid4().hex,
            'mapping_id': mapping_id or uuid.uuid4().hex
        }
        return proto

    def mapping_ref(self, rules=None):
        return {
            'id': uuid.uuid4().hex,
            'rules': rules or self.rules['rules']
        }

    def _scope_request(self, unscoped_token_id, scope, scope_id):
        return {
            'auth': {
                'identity': {
                    'methods': [
                        'token'
                    ],
                    'token': {
                        'id': unscoped_token_id
                    }
                },
                'scope': {
                    scope: {
                        'id': scope_id
                    }
                }
            }
        }

    def _inject_assertion(self, variant):
        assertion = getattr(mapping_fixtures, variant)
        flask.request.environ.update(assertion)

    def load_federation_sample_data(self):
        """Inject additional data."""
        # Create and add domains
        self.domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(
            self.domainA['id'], self.domainA
        )

        self.domainB = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(
            self.domainB['id'], self.domainB
        )

        self.domainC = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(
            self.domainC['id'], self.domainC
        )

        self.domainD = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(
            self.domainD['id'], self.domainD
        )

        # Create and add projects
        self.proj_employees = unit.new_project_ref(
            domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(
            self.proj_employees['id'], self.proj_employees
        )
        self.proj_customers = unit.new_project_ref(
            domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(
            self.proj_customers['id'], self.proj_customers
        )

        self.project_all = unit.new_project_ref(
            domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(
            self.project_all['id'], self.project_all
        )

        self.project_inherited = unit.new_project_ref(
            domain_id=self.domainD['id'])
        PROVIDERS.resource_api.create_project(
            self.project_inherited['id'], self.project_inherited
        )

        # Create and add groups
        self.group_employees = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group_employees = (
            PROVIDERS.identity_api.create_group(self.group_employees))

        self.group_customers = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group_customers = (
            PROVIDERS.identity_api.create_group(self.group_customers))

        self.group_admins = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group_admins = PROVIDERS.identity_api.create_group(
            self.group_admins
        )

        # Create and add roles
        self.role_employee = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            self.role_employee['id'], self.role_employee
        )
        self.role_customer = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            self.role_customer['id'], self.role_customer
        )

        self.role_admin = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role_admin['id'], self.role_admin)

        # Employees can access
        # * proj_employees
        # * project_all
        PROVIDERS.assignment_api.create_grant(
            self.role_employee['id'], group_id=self.group_employees['id'],
            project_id=self.proj_employees['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_employee['id'], group_id=self.group_employees['id'],
            project_id=self.project_all['id']
        )
        # Customers can access
        # * proj_customers
        PROVIDERS.assignment_api.create_grant(
            self.role_customer['id'], group_id=self.group_customers['id'],
            project_id=self.proj_customers['id']
        )

        # Admins can access:
        # * proj_customers
        # * proj_employees
        # * project_all
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], group_id=self.group_admins['id'],
            project_id=self.proj_customers['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], group_id=self.group_admins['id'],
            project_id=self.proj_employees['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], group_id=self.group_admins['id'],
            project_id=self.project_all['id']
        )

        # Customers can access:
        # * domain A
        PROVIDERS.assignment_api.create_grant(
            self.role_customer['id'], group_id=self.group_customers['id'],
            domain_id=self.domainA['id']
        )

        # Customers can access projects via inheritance:
        # * domain D
        PROVIDERS.assignment_api.create_grant(
            self.role_customer['id'], group_id=self.group_customers['id'],
            domain_id=self.domainD['id'], inherited_to_projects=True
        )

        # Employees can access:
        # * domain A
        # * domain B

        PROVIDERS.assignment_api.create_grant(
            self.role_employee['id'], group_id=self.group_employees['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_employee['id'], group_id=self.group_employees['id'],
            domain_id=self.domainB['id']
        )

        # Admins can access:
        # * domain A
        # * domain B
        # * domain C
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], group_id=self.group_admins['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], group_id=self.group_admins['id'],
            domain_id=self.domainB['id']
        )

        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], group_id=self.group_admins['id'],
            domain_id=self.domainC['id']
        )
        self.rules = {
            'rules': [
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_employees['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'Email',
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Employee'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_employees['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': self.ASSERTION_PREFIX + 'UserName'
                        },
                        {
                            'type': self.ASSERTION_PREFIX + 'Email',
                        },
                        {
                            'type': self.ASSERTION_PREFIX + 'orgPersonType',
                            'any_one_of': [
                                'SuperEmployee'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_customers['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'Email'
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Customer'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_admins['id']
                            }
                        },
                        {
                            'group': {
                                'id': self.group_employees['id']
                            }
                        },
                        {
                            'group': {
                                'id': self.group_customers['id']
                            }
                        },

                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'Email'
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Admin',
                                'Chief'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': uuid.uuid4().hex
                            }
                        },
                        {
                            'group': {
                                'id': self.group_customers['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName',
                        },
                        {
                            'type': 'Email',
                        },
                        {
                            'type': 'FirstName',
                            'any_one_of': [
                                'Jill'
                            ]
                        },
                        {
                            'type': 'LastName',
                            'any_one_of': [
                                'Smith'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': 'this_group_no_longer_exists'
                            }
                        },
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName',
                        },
                        {
                            'type': 'Email',
                        },
                        {
                            'type': 'Email',
                            'any_one_of': [
                                'testacct@example.com'
                            ]
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Tester'
                            ]
                        }
                    ]
                },
                # rules with local group names
                {
                    "local": [
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        },
                        {
                            "group": {
                                "name": self.group_customers['name'],
                                "domain": {
                                    "name": self.domainA['name']
                                }
                            }
                        }
                    ],
                    "remote": [
                        {
                            'type': 'UserName',
                        },
                        {
                            'type': 'Email',
                        },
                        {
                            "type": "orgPersonType",
                            "any_one_of": [
                                "CEO",
                                "CTO"
                            ],
                        }
                    ]
                },
                {
                    "local": [
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        },
                        {
                            "group": {
                                "name": self.group_admins['name'],
                                "domain": {
                                    "id": self.domainA['id']
                                }
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "UserName",
                        },
                        {
                            "type": "Email",
                        },
                        {
                            "type": "orgPersonType",
                            "any_one_of": [
                                "Managers"
                            ]
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "user": {
                                "name": "{0}",
                                "id": "{1}"
                            }
                        },
                        {
                            "group": {
                                "name": "NON_EXISTING",
                                "domain": {
                                    "id": self.domainA['id']
                                }
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "UserName",
                        },
                        {
                            "type": "Email",
                        },
                        {
                            "type": "UserName",
                            "any_one_of": [
                                "IamTester"
                            ]
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "user": {
                                "type": "local",
                                "name": self.user['name'],
                                "domain": {
                                    "id": self.user['domain_id']
                                }
                            }
                        },
                        {
                            "group": {
                                "id": self.group_customers['id']
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "UserType",
                            "any_one_of": [
                                "random"
                            ]
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "user": {
                                "type": "local",
                                "name": self.user['name'],
                                "domain": {
                                    "id": uuid.uuid4().hex
                                }
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "Position",
                            "any_one_of": [
                                "DirectorGeneral"
                            ]
                        }
                    ]
                },
                # rules for users with no groups
                {
                    "local": [
                        {
                            'user': {
                                'name': '{0}',
                                'id': '{1}'
                            }
                        }
                    ],
                    "remote": [
                        {
                            'type': 'UserName',
                        },
                        {
                            'type': 'Email',
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'NoGroupsOrg'
                            ]
                        }
                    ]
                }
            ]
        }

        # Add unused IdP first so it is indexed first (#1838592)
        self.dummy_idp = self.idp_ref()
        PROVIDERS.federation_api.create_idp(
            self.dummy_idp['id'], self.dummy_idp
        )
        # Add IDP
        self.idp = self.idp_ref(id=self.IDP)
        PROVIDERS.federation_api.create_idp(
            self.idp['id'], self.idp
        )
        # Add IDP with remote
        self.idp_with_remote = self.idp_ref(id=self.IDP_WITH_REMOTE)
        self.idp_with_remote['remote_ids'] = self.REMOTE_IDS
        PROVIDERS.federation_api.create_idp(
            self.idp_with_remote['id'], self.idp_with_remote
        )
        # Add a mapping
        self.mapping = self.mapping_ref()
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        # Add protocols
        self.proto_saml = self.proto_ref(mapping_id=self.mapping['id'])
        self.proto_saml['id'] = self.PROTOCOL
        PROVIDERS.federation_api.create_protocol(
            self.idp['id'], self.proto_saml['id'], self.proto_saml
        )
        # Add protocols IDP with remote
        PROVIDERS.federation_api.create_protocol(
            self.idp_with_remote['id'], self.proto_saml['id'], self.proto_saml
        )
        # Add unused protocol to go with unused IdP (#1838592)
        self.proto_dummy = self.proto_ref(mapping_id=self.mapping['id'])
        PROVIDERS.federation_api.create_protocol(
            self.dummy_idp['id'], self.proto_dummy['id'], self.proto_dummy
        )

        with self.make_request():
            self.tokens = {}
            VARIANTS = ('EMPLOYEE_ASSERTION', 'CUSTOMER_ASSERTION',
                        'ADMIN_ASSERTION')
            for variant in VARIANTS:
                self._inject_assertion(variant)
                r = authentication.authenticate_for_token(
                    self.UNSCOPED_V3_SAML2_REQ)
                self.tokens[variant] = r.id

            self.TOKEN_SCOPE_PROJECT_FROM_NONEXISTENT_TOKEN = (
                self._scope_request(
                    uuid.uuid4().hex, 'project', self.proj_customers['id']))

            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE = (
                self._scope_request(
                    self.tokens['EMPLOYEE_ASSERTION'], 'project',
                    self.proj_employees['id']))

            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN = self._scope_request(
                self.tokens['ADMIN_ASSERTION'], 'project',
                self.proj_employees['id'])

            self.TOKEN_SCOPE_PROJECT_CUSTOMER_FROM_ADMIN = self._scope_request(
                self.tokens['ADMIN_ASSERTION'], 'project',
                self.proj_customers['id'])

            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER = (
                self._scope_request(
                    self.tokens['CUSTOMER_ASSERTION'], 'project',
                    self.proj_employees['id']))

            self.TOKEN_SCOPE_PROJECT_INHERITED_FROM_CUSTOMER = (
                self._scope_request(
                    self.tokens['CUSTOMER_ASSERTION'], 'project',
                    self.project_inherited['id']))

            self.TOKEN_SCOPE_DOMAIN_A_FROM_CUSTOMER = self._scope_request(
                self.tokens['CUSTOMER_ASSERTION'], 'domain',
                self.domainA['id'])

            self.TOKEN_SCOPE_DOMAIN_B_FROM_CUSTOMER = self._scope_request(
                self.tokens['CUSTOMER_ASSERTION'], 'domain',
                self.domainB['id'])

            self.TOKEN_SCOPE_DOMAIN_D_FROM_CUSTOMER = self._scope_request(
                self.tokens['CUSTOMER_ASSERTION'], 'domain',
                self.domainD['id'])

            self.TOKEN_SCOPE_DOMAIN_A_FROM_ADMIN = self._scope_request(
                self.tokens['ADMIN_ASSERTION'], 'domain', self.domainA['id'])

            self.TOKEN_SCOPE_DOMAIN_B_FROM_ADMIN = self._scope_request(
                self.tokens['ADMIN_ASSERTION'], 'domain', self.domainB['id'])

            self.TOKEN_SCOPE_DOMAIN_C_FROM_ADMIN = self._scope_request(
                self.tokens['ADMIN_ASSERTION'], 'domain',
                self.domainC['id'])


class FederatedIdentityProviderTests(test_v3.RestfulTestCase):
    """A test class for Identity Providers."""

    idp_keys = ['description', 'enabled']

    default_body = {'description': None, 'enabled': True}

    def base_url(self, suffix=None):
        if suffix is not None:
            return '/OS-FEDERATION/identity_providers/' + str(suffix)
        return '/OS-FEDERATION/identity_providers'

    def _fetch_attribute_from_response(self, resp, parameter,
                                       assert_is_not_none=True):
        """Fetch single attribute from TestResponse object."""
        result = resp.result.get(parameter)
        if assert_is_not_none:
            self.assertIsNotNone(result)
        return result

    def _create_and_decapsulate_response(self, body=None):
        """Create IdP and fetch it's random id along with entity."""
        default_resp = self._create_default_idp(body=body)
        idp = self._fetch_attribute_from_response(default_resp,
                                                  'identity_provider')
        self.assertIsNotNone(idp)
        idp_id = idp.get('id')
        return (idp_id, idp)

    def _get_idp(self, idp_id):
        """Fetch IdP entity based on its id."""
        url = self.base_url(suffix=idp_id)
        resp = self.get(url)
        return resp

    def _create_default_idp(self, body=None,
                            expected_status=http.client.CREATED):
        """Create default IdP."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        if body is None:
            body = self._http_idp_input()
        resp = self.put(url, body={'identity_provider': body},
                        expected_status=expected_status)
        return resp

    def _http_idp_input(self):
        """Create default input dictionary for IdP data."""
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        return body

    def _assign_protocol_to_idp(self, idp_id=None, proto=None, url=None,
                                mapping_id=None, validate=True, **kwargs):
        if url is None:
            url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')
        if idp_id is None:
            idp_id, _ = self._create_and_decapsulate_response()
        if proto is None:
            proto = uuid.uuid4().hex
        if mapping_id is None:
            mapping_id = uuid.uuid4().hex
        self._create_mapping(mapping_id)
        body = {'mapping_id': mapping_id}
        url = url % {'idp_id': idp_id, 'protocol_id': proto}
        resp = self.put(url, body={'protocol': body}, **kwargs)
        if validate:
            self.assertValidResponse(resp, 'protocol', dummy_validator,
                                     keys_to_check=['id', 'mapping_id'],
                                     ref={'id': proto,
                                          'mapping_id': mapping_id})
        return (resp, idp_id, proto)

    def _get_protocol(self, idp_id, protocol_id):
        url = '%s/protocols/%s' % (idp_id, protocol_id)
        url = self.base_url(suffix=url)
        r = self.get(url)
        return r

    def _create_mapping(self, mapping_id):
        mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        mapping['id'] = mapping_id
        url = '/OS-FEDERATION/mappings/%s' % mapping_id
        self.put(url,
                 body={'mapping': mapping},
                 expected_status=http.client.CREATED)

    def assertIdpDomainCreated(self, idp_id, domain_id):
        domain = PROVIDERS.resource_api.get_domain(domain_id)
        self.assertEqual(domain_id, domain['name'])
        self.assertIn(idp_id, domain['description'])

    def test_create_idp_without_domain_id(self):
        """Create the IdentityProvider entity associated to remote_ids."""
        keys_to_check = list(self.idp_keys)
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        resp = self._create_default_idp(body=body)
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)
        attr = self._fetch_attribute_from_response(resp, 'identity_provider')
        self.assertIdpDomainCreated(attr['id'], attr['domain_id'])

    def test_create_idp_with_domain_id(self):
        keys_to_check = list(self.idp_keys)
        keys_to_check.append('domain_id')
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        body['domain_id'] = domain['id']
        resp = self._create_default_idp(body=body)
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)

    def test_create_idp_domain_id_none(self):
        keys_to_check = list(self.idp_keys)
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['domain_id'] = None
        resp = self._create_default_idp(body=body)
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)
        attr = self._fetch_attribute_from_response(resp, 'identity_provider')
        self.assertIdpDomainCreated(attr['id'], attr['domain_id'])

    def test_conflicting_idp_cleans_up_auto_generated_domain(self):
        # NOTE(lbragstad): Create an identity provider, save its ID, and count
        # the number of domains.
        resp = self._create_default_idp()
        idp_id = resp.json_body['identity_provider']['id']
        domains = PROVIDERS.resource_api.list_domains()
        number_of_domains = len(domains)

        # Create an identity provider with the same ID to intentionally cause a
        # conflict, this is going to result in a domain getting created for the
        # new identity provider. The domain for the new identity provider is
        # going to be created before the conflict is raised from the database
        # layer. This makes sure the domain is cleaned up after a Conflict is
        # detected.
        resp = self.put(
            self.base_url(suffix=idp_id),
            body={'identity_provider': self.default_body.copy()},
            expected_status=http.client.CONFLICT
        )
        domains = PROVIDERS.resource_api.list_domains()
        self.assertEqual(number_of_domains, len(domains))

    def test_conflicting_idp_does_not_delete_existing_domain(self):
        # Create a new domain
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        # Create an identity provider and specify the domain
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['domain_id'] = domain['id']
        resp = self._create_default_idp(body=body)
        idp = resp.json_body['identity_provider']
        idp_id = idp['id']
        self.assertEqual(idp['domain_id'], domain['id'])

        # Create an identity provider with the same domain and ID to ensure a
        # Conflict is raised and then to verify the existing domain not deleted
        # below
        body = self.default_body.copy()
        body['domain_id'] = domain['id']
        resp = self.put(
            self.base_url(suffix=idp_id),
            body={'identity_provider': body},
            expected_status=http.client.CONFLICT
        )

        # Make sure the domain specified in the second request was not deleted,
        # since it wasn't auto-generated
        self.assertIsNotNone(PROVIDERS.resource_api.get_domain(domain['id']))

    def test_create_multi_idp_to_one_domain(self):
        # create domain and add domain_id to keys to check
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        keys_to_check = list(self.idp_keys)
        keys_to_check.append('domain_id')
        # create idp with the domain_id
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['domain_id'] = domain['id']
        idp1 = self._create_default_idp(body=body)
        self.assertValidResponse(idp1, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)
        # create a 2nd idp with the same domain_id
        url = self.base_url(suffix=uuid.uuid4().hex)
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['domain_id'] = domain['id']
        idp2 = self.put(url, body={'identity_provider': body},
                        expected_status=http.client.CREATED)
        self.assertValidResponse(idp2, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)

        self.assertEqual(idp1.result['identity_provider']['domain_id'],
                         idp2.result['identity_provider']['domain_id'])

    def test_cannot_update_idp_domain(self):
        # create new idp
        body = self.default_body.copy()
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        self.assertIsNotNone(idp_id)
        # create domain and try to update the idp's domain
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        body['domain_id'] = domain['id']
        body = {'identity_provider': body}
        url = self.base_url(suffix=idp_id)
        self.patch(url, body=body, expected_status=http.client.BAD_REQUEST)

    def test_create_idp_with_nonexistent_domain_id_fails(self):
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['domain_id'] = uuid.uuid4().hex
        self._create_default_idp(body=body,
                                 expected_status=http.client.NOT_FOUND)

    def test_create_idp_remote(self):
        """Create the IdentityProvider entity associated to remote_ids."""
        keys_to_check = list(self.idp_keys)
        keys_to_check.append('remote_ids')
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['remote_ids'] = [uuid.uuid4().hex,
                              uuid.uuid4().hex,
                              uuid.uuid4().hex]
        resp = self._create_default_idp(body=body)
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)
        attr = self._fetch_attribute_from_response(resp, 'identity_provider')
        self.assertIdpDomainCreated(attr['id'], attr['domain_id'])

    def test_create_idp_remote_repeated(self):
        """Create two IdentityProvider entities with some remote_ids.

        A remote_id is the same for both so the second IdP is not
        created because of the uniqueness of the remote_ids

        Expect HTTP 409 Conflict code for the latter call.

        """
        body = self.default_body.copy()
        repeated_remote_id = uuid.uuid4().hex
        body['remote_ids'] = [uuid.uuid4().hex,
                              uuid.uuid4().hex,
                              uuid.uuid4().hex,
                              repeated_remote_id]
        self._create_default_idp(body=body)

        url = self.base_url(suffix=uuid.uuid4().hex)
        body['remote_ids'] = [uuid.uuid4().hex,
                              repeated_remote_id]
        resp = self.put(url, body={'identity_provider': body},
                        expected_status=http.client.CONFLICT)

        resp_data = jsonutils.loads(resp.body)
        self.assertIn('Duplicate remote ID',
                      resp_data.get('error', {}).get('message'))

    def test_create_idp_remote_empty(self):
        """Create an IdP with empty remote_ids."""
        keys_to_check = list(self.idp_keys)
        keys_to_check.append('remote_ids')
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['remote_ids'] = []
        resp = self._create_default_idp(body=body)
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)

    def test_create_idp_remote_none(self):
        """Create an IdP with a None remote_ids."""
        keys_to_check = list(self.idp_keys)
        keys_to_check.append('remote_ids')
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['remote_ids'] = None
        resp = self._create_default_idp(body=body)
        expected = body.copy()
        expected['remote_ids'] = []
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=expected)

    def test_create_idp_authorization_ttl(self):
        keys_to_check = list(self.idp_keys)
        keys_to_check.append('authorization_ttl')
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        body['authorization_ttl'] = 10080
        resp = self._create_default_idp(body)
        expected = body.copy()
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=expected)

    def test_update_idp_remote_ids(self):
        """Update IdP's remote_ids parameter."""
        body = self.default_body.copy()
        body['remote_ids'] = [uuid.uuid4().hex]
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        self.assertIsNotNone(idp_id)

        body['remote_ids'] = [uuid.uuid4().hex, uuid.uuid4().hex]

        body = {'identity_provider': body}
        resp = self.patch(url, body=body)
        updated_idp = self._fetch_attribute_from_response(resp,
                                                          'identity_provider')
        body = body['identity_provider']
        self.assertEqual(sorted(body['remote_ids']),
                         sorted(updated_idp.get('remote_ids')))

        resp = self.get(url)
        returned_idp = self._fetch_attribute_from_response(resp,
                                                           'identity_provider')
        self.assertEqual(sorted(body['remote_ids']),
                         sorted(returned_idp.get('remote_ids')))

    def test_update_idp_clean_remote_ids(self):
        """Update IdP's remote_ids parameter with an empty list."""
        body = self.default_body.copy()
        body['remote_ids'] = [uuid.uuid4().hex]
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        self.assertIsNotNone(idp_id)

        body['remote_ids'] = []

        body = {'identity_provider': body}
        resp = self.patch(url, body=body)
        updated_idp = self._fetch_attribute_from_response(resp,
                                                          'identity_provider')
        body = body['identity_provider']
        self.assertEqual(sorted(body['remote_ids']),
                         sorted(updated_idp.get('remote_ids')))

        resp = self.get(url)
        returned_idp = self._fetch_attribute_from_response(resp,
                                                           'identity_provider')
        self.assertEqual(sorted(body['remote_ids']),
                         sorted(returned_idp.get('remote_ids')))

    def test_update_idp_remote_repeated(self):
        """Update an IdentityProvider entity reusing a remote_id.

        A remote_id is the same for both so the second IdP is not
        updated because of the uniqueness of the remote_ids.

        Expect HTTP 409 Conflict code for the latter call.

        """
        # Create first identity provider
        body = self.default_body.copy()
        repeated_remote_id = uuid.uuid4().hex
        body['remote_ids'] = [uuid.uuid4().hex, repeated_remote_id]
        self._create_default_idp(body=body)

        # Create second identity provider (without remote_ids)
        body = self.default_body.copy()
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)

        body['remote_ids'] = [repeated_remote_id]
        resp = self.patch(url, body={'identity_provider': body},
                          expected_status=http.client.CONFLICT)
        resp_data = jsonutils.loads(resp.body)
        self.assertIn('Duplicate remote ID',
                      resp_data['error']['message'])

    def test_update_idp_authorization_ttl(self):
        body = self.default_body.copy()
        body['authorization_ttl'] = 10080
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        self.assertIsNotNone(idp_id)

        body['authorization_ttl'] = None

        body = {'identity_provider': body}
        resp = self.patch(url, body=body)
        updated_idp = self._fetch_attribute_from_response(resp,
                                                          'identity_provider')
        body = body['identity_provider']
        self.assertEqual(body['authorization_ttl'],
                         updated_idp.get('authorization_ttl'))

        resp = self.get(url)
        returned_idp = self._fetch_attribute_from_response(resp,
                                                           'identity_provider')
        self.assertEqual(body['authorization_ttl'],
                         returned_idp.get('authorization_ttl'))

    def test_list_head_idps(self, iterations=5):
        """List all available IdentityProviders.

        This test collects ids of created IdPs and
        intersects it with the list of all available IdPs.
        List of all IdPs can be a superset of IdPs created in this test,
        because other tests also create IdPs.

        """
        def get_id(resp):
            r = self._fetch_attribute_from_response(resp,
                                                    'identity_provider')
            return r.get('id')

        ids = []
        for _ in range(iterations):
            id = get_id(self._create_default_idp())
            ids.append(id)
        ids = set(ids)

        keys_to_check = self.idp_keys
        keys_to_check.append('domain_id')
        url = self.base_url()
        resp = self.get(url)
        self.assertValidListResponse(resp, 'identity_providers',
                                     dummy_validator,
                                     keys_to_check=keys_to_check)
        entities = self._fetch_attribute_from_response(resp,
                                                       'identity_providers')
        entities_ids = set([e['id'] for e in entities])
        ids_intersection = entities_ids.intersection(ids)
        self.assertEqual(ids_intersection, ids)

        self.head(url, expected_status=http.client.OK)

    def test_filter_list_head_idp_by_id(self):
        def get_id(resp):
            r = self._fetch_attribute_from_response(resp,
                                                    'identity_provider')
            return r.get('id')

        idp1_id = get_id(self._create_default_idp())
        idp2_id = get_id(self._create_default_idp())

        # list the IdP, should get two IdP.
        url = self.base_url()
        resp = self.get(url)
        entities = self._fetch_attribute_from_response(resp,
                                                       'identity_providers')
        entities_ids = [e['id'] for e in entities]
        self.assertCountEqual(entities_ids, [idp1_id, idp2_id])

        # filter the IdP by ID.
        url = self.base_url() + '?id=' + idp1_id
        resp = self.get(url)
        filtered_service_list = resp.json['identity_providers']
        self.assertThat(filtered_service_list, matchers.HasLength(1))
        self.assertEqual(idp1_id, filtered_service_list[0].get('id'))

        self.head(url, expected_status=http.client.OK)

    def test_filter_list_head_idp_by_enabled(self):
        def get_id(resp):
            r = self._fetch_attribute_from_response(resp,
                                                    'identity_provider')
            return r.get('id')

        idp1_id = get_id(self._create_default_idp())

        body = self.default_body.copy()
        body['enabled'] = False
        idp2_id = get_id(self._create_default_idp(body=body))

        # list the IdP, should get two IdP.
        url = self.base_url()
        resp = self.get(url)
        entities = self._fetch_attribute_from_response(resp,
                                                       'identity_providers')
        entities_ids = [e['id'] for e in entities]
        self.assertCountEqual(entities_ids, [idp1_id, idp2_id])

        # filter the IdP by 'enabled'.
        url = self.base_url() + '?enabled=True'
        resp = self.get(url)
        filtered_service_list = resp.json['identity_providers']
        self.assertThat(filtered_service_list, matchers.HasLength(1))
        self.assertEqual(idp1_id, filtered_service_list[0].get('id'))

        self.head(url, expected_status=http.client.OK)

    def test_check_idp_uniqueness(self):
        """Add same IdP twice.

        Expect HTTP 409 Conflict code for the latter call.

        """
        url = self.base_url(suffix=uuid.uuid4().hex)
        body = self._http_idp_input()
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        body['domain_id'] = domain['id']
        self.put(url, body={'identity_provider': body},
                 expected_status=http.client.CREATED)
        resp = self.put(url, body={'identity_provider': body},
                        expected_status=http.client.CONFLICT)

        resp_data = jsonutils.loads(resp.body)
        self.assertIn('Duplicate entry',
                      resp_data.get('error', {}).get('message'))

    def test_get_head_idp(self):
        """Create and later fetch IdP."""
        body = self._http_idp_input()
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        body['domain_id'] = domain['id']
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        resp = self.get(url)
        # Strip keys out of `body` dictionary. This is done
        # to be python 3 compatible
        body_keys = list(body)
        self.assertValidResponse(resp, 'identity_provider',
                                 dummy_validator, keys_to_check=body_keys,
                                 ref=body)

        self.head(url, expected_status=http.client.OK)

    def test_get_nonexisting_idp(self):
        """Fetch nonexisting IdP entity.

        Expected HTTP 404 Not Found status code.

        """
        idp_id = uuid.uuid4().hex
        self.assertIsNotNone(idp_id)

        url = self.base_url(suffix=idp_id)
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_delete_existing_idp(self):
        """Create and later delete IdP.

        Expect HTTP 404 Not Found for the GET IdP call.
        """
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        self.assertIsNotNone(idp_id)
        url = self.base_url(suffix=idp_id)
        self.delete(url)
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_delete_idp_also_deletes_assigned_protocols(self):
        """Deleting an IdP will delete its assigned protocol."""
        # create default IdP
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp['id']
        protocol_id = uuid.uuid4().hex

        url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')
        idp_url = self.base_url(suffix=idp_id)

        # assign protocol to IdP
        kwargs = {'expected_status': http.client.CREATED}
        resp, idp_id, proto = self._assign_protocol_to_idp(
            url=url,
            idp_id=idp_id,
            proto=protocol_id,
            **kwargs)

        # removing IdP will remove the assigned protocol as well
        self.assertEqual(
            1, len(PROVIDERS.federation_api.list_protocols(idp_id))
        )
        self.delete(idp_url)
        self.get(idp_url, expected_status=http.client.NOT_FOUND)
        self.assertEqual(
            0, len(PROVIDERS.federation_api.list_protocols(idp_id))
        )

    def test_delete_nonexisting_idp(self):
        """Delete nonexisting IdP.

        Expect HTTP 404 Not Found for the GET IdP call.
        """
        idp_id = uuid.uuid4().hex
        url = self.base_url(suffix=idp_id)
        self.delete(url, expected_status=http.client.NOT_FOUND)

    def test_update_idp_mutable_attributes(self):
        """Update IdP's mutable parameters."""
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        self.assertIsNotNone(idp_id)

        _enabled = not default_idp.get('enabled')
        body = {'remote_ids': [uuid.uuid4().hex, uuid.uuid4().hex],
                'description': uuid.uuid4().hex,
                'enabled': _enabled}

        body = {'identity_provider': body}
        resp = self.patch(url, body=body)
        updated_idp = self._fetch_attribute_from_response(resp,
                                                          'identity_provider')
        body = body['identity_provider']
        for key in body.keys():
            if isinstance(body[key], list):
                self.assertEqual(sorted(body[key]),
                                 sorted(updated_idp.get(key)))
            else:
                self.assertEqual(body[key], updated_idp.get(key))

        resp = self.get(url)
        updated_idp = self._fetch_attribute_from_response(resp,
                                                          'identity_provider')
        for key in body.keys():
            if isinstance(body[key], list):
                self.assertEqual(sorted(body[key]),
                                 sorted(updated_idp.get(key)))
            else:
                self.assertEqual(body[key], updated_idp.get(key))

    def test_update_idp_immutable_attributes(self):
        """Update IdP's immutable parameters.

        Expect HTTP BAD REQUEST.

        """
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        self.assertIsNotNone(idp_id)

        body = self._http_idp_input()
        body['id'] = uuid.uuid4().hex
        body['protocols'] = [uuid.uuid4().hex, uuid.uuid4().hex]

        url = self.base_url(suffix=idp_id)
        self.patch(url, body={'identity_provider': body},
                   expected_status=http.client.BAD_REQUEST)

    def test_update_nonexistent_idp(self):
        """Update nonexistent IdP.

        Expect HTTP 404 Not Found code.

        """
        idp_id = uuid.uuid4().hex
        url = self.base_url(suffix=idp_id)
        body = self._http_idp_input()
        body['enabled'] = False
        body = {'identity_provider': body}

        self.patch(url, body=body, expected_status=http.client.NOT_FOUND)

    def test_assign_protocol_to_idp(self):
        """Assign a protocol to existing IdP."""
        self._assign_protocol_to_idp(expected_status=http.client.CREATED)

    def test_protocol_composite_pk(self):
        """Test that Keystone can add two entities.

        The entities have identical names, however, attached to different
        IdPs.

        1. Add IdP and assign it protocol with predefined name
        2. Add another IdP and assign it a protocol with same name.

        Expect HTTP 201 code

        """
        url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')

        kwargs = {'expected_status': http.client.CREATED}
        self._assign_protocol_to_idp(proto='saml2',
                                     url=url, **kwargs)

        self._assign_protocol_to_idp(proto='saml2',
                                     url=url, **kwargs)

    def test_protocol_idp_pk_uniqueness(self):
        """Test whether Keystone checks for unique idp/protocol values.

        Add same protocol twice, expect Keystone to reject a latter call and
        return HTTP 409 Conflict code.

        """
        url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')

        kwargs = {'expected_status': http.client.CREATED}
        resp, idp_id, proto = self._assign_protocol_to_idp(proto='saml2',
                                                           url=url, **kwargs)
        kwargs = {'expected_status': http.client.CONFLICT}
        self._assign_protocol_to_idp(
            idp_id=idp_id, proto='saml2', validate=False, url=url, **kwargs
        )

    def test_assign_protocol_to_nonexistent_idp(self):
        """Assign protocol to IdP that doesn't exist.

        Expect HTTP 404 Not Found code.

        """
        idp_id = uuid.uuid4().hex
        kwargs = {'expected_status': http.client.NOT_FOUND}
        self._assign_protocol_to_idp(proto='saml2',
                                     idp_id=idp_id,
                                     validate=False,
                                     **kwargs)

    def test_crud_protocol_without_protocol_id_in_url(self):
        # NOTE(morgan): This test is redundant but is added to ensure
        # the url routing error in bug 1817313 is explicitly covered.
        # create a protocol, but do not put the ID in the URL
        idp_id, _ = self._create_and_decapsulate_response()
        mapping_id = uuid.uuid4().hex
        self._create_mapping(mapping_id=mapping_id)
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': mapping_id
        }
        with self.test_client() as c:
            token = self.get_scoped_token()
            # DELETE/PATCH/PUT on non-trailing `/` results in
            # METHOD_NOT_ALLOWED
            c.delete('/v3/OS-FEDERATION/identity_providers/%(idp_id)s'
                     '/protocols' % {'idp_id': idp_id},
                     headers={'X-Auth-Token': token},
                     expected_status_code=http.client.METHOD_NOT_ALLOWED)
            c.patch('/v3/OS-FEDERATION/identity_providers/%(idp_id)s'
                    '/protocols/' % {'idp_id': idp_id},
                    json={'protocol': protocol},
                    headers={'X-Auth-Token': token},
                    expected_status_code=http.client.METHOD_NOT_ALLOWED)
            c.put('/v3/OS-FEDERATION/identity_providers/%(idp_id)s'
                  '/protocols' % {'idp_id': idp_id},
                  json={'protocol': protocol},
                  headers={'X-Auth-Token': token},
                  expected_status_code=http.client.METHOD_NOT_ALLOWED)

            # DELETE/PATCH/PUT should raise 405 with trailing '/', it is
            # remapped to without the trailing '/' by the normalization
            # middleware.
            c.delete('/v3/OS-FEDERATION/identity_providers/%(idp_id)s'
                     '/protocols/' % {'idp_id': idp_id},
                     headers={'X-Auth-Token': token},
                     expected_status_code=http.client.METHOD_NOT_ALLOWED)
            c.patch('/v3/OS-FEDERATION/identity_providers/%(idp_id)s'
                    '/protocols/' % {'idp_id': idp_id},
                    json={'protocol': protocol},
                    headers={'X-Auth-Token': token},
                    expected_status_code=http.client.METHOD_NOT_ALLOWED)
            c.put('/v3/OS-FEDERATION/identity_providers/%(idp_id)s'
                  '/protocols/' % {'idp_id': idp_id},
                  json={'protocol': protocol},
                  headers={'X-Auth-Token': token},
                  expected_status_code=http.client.METHOD_NOT_ALLOWED)

    def test_get_head_protocol(self):
        """Create and later fetch protocol tied to IdP."""
        resp, idp_id, proto = self._assign_protocol_to_idp(
            expected_status=http.client.CREATED)
        proto_id = self._fetch_attribute_from_response(resp, 'protocol')['id']
        url = "%s/protocols/%s" % (idp_id, proto_id)
        url = self.base_url(suffix=url)

        resp = self.get(url)

        reference = {'id': proto_id}
        # Strip keys out of `body` dictionary. This is done
        # to be python 3 compatible
        reference_keys = list(reference)
        self.assertValidResponse(resp, 'protocol',
                                 dummy_validator,
                                 keys_to_check=reference_keys,
                                 ref=reference)

        self.head(url, expected_status=http.client.OK)

    def test_list_head_protocols(self):
        """Create set of protocols and later list them.

        Compare input and output id sets.

        """
        resp, idp_id, proto = self._assign_protocol_to_idp(
            expected_status=http.client.CREATED)
        iterations = random.randint(0, 16)
        protocol_ids = []
        for _ in range(iterations):
            resp, _, proto = self._assign_protocol_to_idp(
                idp_id=idp_id,
                expected_status=http.client.CREATED)
            proto_id = self._fetch_attribute_from_response(resp, 'protocol')
            proto_id = proto_id['id']
            protocol_ids.append(proto_id)

        url = "%s/protocols" % idp_id
        url = self.base_url(suffix=url)
        resp = self.get(url)
        self.assertValidListResponse(resp, 'protocols',
                                     dummy_validator,
                                     keys_to_check=['id'])
        entities = self._fetch_attribute_from_response(resp, 'protocols')
        entities = set([entity['id'] for entity in entities])
        protocols_intersection = entities.intersection(protocol_ids)
        self.assertEqual(protocols_intersection, set(protocol_ids))

        self.head(url, expected_status=http.client.OK)

    def test_update_protocols_attribute(self):
        """Update protocol's attribute."""
        resp, idp_id, proto = self._assign_protocol_to_idp(
            expected_status=http.client.CREATED)
        new_mapping_id = uuid.uuid4().hex
        self._create_mapping(mapping_id=new_mapping_id)

        url = "%s/protocols/%s" % (idp_id, proto)
        url = self.base_url(suffix=url)
        body = {'mapping_id': new_mapping_id}
        resp = self.patch(url, body={'protocol': body})
        self.assertValidResponse(resp, 'protocol', dummy_validator,
                                 keys_to_check=['id', 'mapping_id'],
                                 ref={'id': proto,
                                      'mapping_id': new_mapping_id}
                                 )

    def test_delete_protocol(self):
        """Delete protocol.

        Expect HTTP 404 Not Found code for the GET call after the protocol is
        deleted.

        """
        url = self.base_url(suffix='%(idp_id)s/'
                                   'protocols/%(protocol_id)s')
        resp, idp_id, proto = self._assign_protocol_to_idp(
            expected_status=http.client.CREATED)
        url = url % {'idp_id': idp_id,
                     'protocol_id': proto}
        self.delete(url)
        self.get(url, expected_status=http.client.NOT_FOUND)


class MappingCRUDTests(test_v3.RestfulTestCase):
    """A class for testing CRUD operations for Mappings."""

    MAPPING_URL = '/OS-FEDERATION/mappings/'

    def assertValidMappingListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'mappings',
            self.assertValidMapping,
            keys_to_check=[],
            *args,
            **kwargs)

    def assertValidMappingResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'mapping',
            self.assertValidMapping,
            keys_to_check=[],
            *args,
            **kwargs)

    def assertValidMapping(self, entity, ref=None):
        self.assertIsNotNone(entity.get('id'))
        self.assertIsNotNone(entity.get('rules'))
        if ref:
            self.assertEqual(entity['rules'], ref['rules'])
        return entity

    def _create_default_mapping_entry(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        resp = self.put(url,
                        body={'mapping': mapping_fixtures.MAPPING_LARGE},
                        expected_status=http.client.CREATED)
        return resp

    def _get_id_from_response(self, resp):
        r = resp.result.get('mapping')
        return r.get('id')

    def test_mapping_create(self):
        resp = self._create_default_mapping_entry()
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_LARGE)

    def test_mapping_list_head(self):
        url = self.MAPPING_URL
        self._create_default_mapping_entry()
        resp = self.get(url)
        entities = resp.result.get('mappings')
        self.assertIsNotNone(entities)
        self.assertResponseStatus(resp, http.client.OK)
        self.assertValidListLinks(resp.result.get('links'))
        self.assertEqual(1, len(entities))
        self.head(url, expected_status=http.client.OK)

    def test_mapping_delete(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': str(mapping_id)}
        resp = self.delete(url)
        self.assertResponseStatus(resp, http.client.NO_CONTENT)
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_mapping_get_head(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': mapping_id}
        resp = self.get(url)
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_LARGE)
        self.head(url, expected_status=http.client.OK)

    def test_mapping_update(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': mapping_id}
        resp = self.patch(url,
                          body={'mapping': mapping_fixtures.MAPPING_SMALL})
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_SMALL)
        resp = self.get(url)
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_SMALL)

    def test_delete_mapping_dne(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.delete(url, expected_status=http.client.NOT_FOUND)

    def test_get_mapping_dne(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_create_mapping_bad_requirements(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_BAD_REQ})

    def test_create_mapping_no_rules(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_NO_RULES})

    def test_create_mapping_no_remote_objects(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_NO_REMOTE})

    def test_create_mapping_bad_value(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_BAD_VALUE})

    def test_create_mapping_missing_local(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_MISSING_LOCAL})

    def test_create_mapping_missing_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_MISSING_TYPE})

    def test_create_mapping_wrong_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_WRONG_TYPE})

    def test_create_mapping_extra_remote_properties_not_any_of(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_NOT_ANY_OF
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping})

    def test_create_mapping_extra_remote_properties_any_one_of(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_ANY_ONE_OF
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping})

    def test_create_mapping_extra_remote_properties_just_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_JUST_TYPE
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping})

    def test_create_mapping_empty_map(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': {}})

    def test_create_mapping_extra_rules_properties(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_EXTRA_RULES_PROPS})

    def test_create_mapping_with_blacklist_and_whitelist(self):
        """Test for adding whitelist and blacklist in the rule.

        Server should respond with HTTP 400 Bad Request error upon discovering
        both ``whitelist`` and ``blacklist`` keywords in the same rule.

        """
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_AND_BLACKLIST
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': mapping})

    def test_create_mapping_with_local_user_and_local_domain(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        resp = self.put(
            url,
            body={
                'mapping': mapping_fixtures.MAPPING_LOCAL_USER_LOCAL_DOMAIN
            },
            expected_status=http.client.CREATED)
        self.assertValidMappingResponse(
            resp, mapping_fixtures.MAPPING_LOCAL_USER_LOCAL_DOMAIN)

    def test_create_mapping_with_ephemeral(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        resp = self.put(
            url,
            body={'mapping': mapping_fixtures.MAPPING_EPHEMERAL_USER},
            expected_status=http.client.CREATED)
        self.assertValidMappingResponse(
            resp, mapping_fixtures.MAPPING_EPHEMERAL_USER)

    def test_create_mapping_with_bad_user_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        # get a copy of a known good map
        bad_mapping = copy.deepcopy(mapping_fixtures.MAPPING_EPHEMERAL_USER)
        # now sabotage the user type
        bad_mapping['rules'][0]['local'][0]['user']['type'] = uuid.uuid4().hex
        self.put(url, expected_status=http.client.BAD_REQUEST,
                 body={'mapping': bad_mapping})

    def test_create_shadow_mapping_without_roles_fails(self):
        """Validate that mappings with projects contain roles when created."""
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(
            url,
            body={'mapping': mapping_fixtures.MAPPING_PROJECTS_WITHOUT_ROLES},
            expected_status=http.client.BAD_REQUEST
        )

    def test_update_shadow_mapping_without_roles_fails(self):
        """Validate that mappings with projects contain roles when updated."""
        url = self.MAPPING_URL + uuid.uuid4().hex
        resp = self.put(
            url,
            body={'mapping': mapping_fixtures.MAPPING_PROJECTS},
            expected_status=http.client.CREATED
        )
        self.assertValidMappingResponse(
            resp, mapping_fixtures.MAPPING_PROJECTS
        )
        self.patch(
            url,
            body={'mapping': mapping_fixtures.MAPPING_PROJECTS_WITHOUT_ROLES},
            expected_status=http.client.BAD_REQUEST
        )

    def test_create_shadow_mapping_without_name_fails(self):
        """Validate project mappings contain the project name when created."""
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(
            url,
            body={'mapping': mapping_fixtures.MAPPING_PROJECTS_WITHOUT_NAME},
            expected_status=http.client.BAD_REQUEST
        )

    def test_update_shadow_mapping_without_name_fails(self):
        """Validate project mappings contain the project name when updated."""
        url = self.MAPPING_URL + uuid.uuid4().hex
        resp = self.put(
            url,
            body={'mapping': mapping_fixtures.MAPPING_PROJECTS},
            expected_status=http.client.CREATED
        )
        self.assertValidMappingResponse(
            resp, mapping_fixtures.MAPPING_PROJECTS
        )
        self.patch(
            url,
            body={'mapping': mapping_fixtures.MAPPING_PROJECTS_WITHOUT_NAME},
            expected_status=http.client.BAD_REQUEST
        )


class FederatedTokenTests(test_v3.RestfulTestCase, FederatedSetupMixin):

    def auth_plugin_config_override(self):
        methods = ['saml2', 'token']
        super(FederatedTokenTests, self).auth_plugin_config_override(methods)

    def setUp(self):
        super(FederatedTokenTests, self).setUp()
        self._notifications = []

        def fake_saml_notify(action, user_id, group_ids,
                             identity_provider, protocol, token_id, outcome):
            note = {
                'action': action,
                'user_id': user_id,
                'identity_provider': identity_provider,
                'protocol': protocol,
                'send_notification_called': True}
            self._notifications.append(note)

        self.useFixture(fixtures.MockPatchObject(
            notifications,
            'send_saml_audit_notification',
            fake_saml_notify))

    def _assert_last_notify(self, action, identity_provider, protocol,
                            user_id=None):
        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        if user_id:
            self.assertEqual(note['user_id'], user_id)
        self.assertEqual(note['action'], action)
        self.assertEqual(note['identity_provider'], identity_provider)
        self.assertEqual(note['protocol'], protocol)
        self.assertTrue(note['send_notification_called'])

    def load_fixtures(self, fixtures):
        super(FederatedTokenTests, self).load_fixtures(fixtures)
        self.load_federation_sample_data()

    def test_issue_unscoped_token_notify(self):
        self._issue_unscoped_token()
        self._assert_last_notify(self.ACTION, self.IDP, self.PROTOCOL)

    def test_issue_unscoped_token(self):
        r = self._issue_unscoped_token()
        token_resp = render_token.render_token_response_from_model(r)['token']
        self.assertValidMappedUser(token_resp)

    def test_default_domain_scoped_token(self):
        # Make sure federated users can get tokens scoped to the default
        # domain, which has a non-uuid ID by default (e.g., `default`). We want
        # to make sure the token provider handles string types properly if the
        # ID isn't compressed into byte format during validation. Turn off
        # cache on issue so that we validate the token online right after we
        # get it to make sure the token provider is called.
        self.config_fixture.config(group='token', cache_on_issue=False)

        # Grab an unscoped token to get a domain-scoped token with.
        token = self._issue_unscoped_token()

        # Give the user a direct role assignment on the default domain, so they
        # can get a federated domain-scoped token.
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], user_id=token.user_id,
            domain_id=CONF.identity.default_domain_id
        )

        # Get a token scoped to the default domain with an ID of `default`,
        # which isn't a uuid type, but we should be able to handle it
        # accordingly in the token formatters/providers.
        auth_request = {
            'auth': {
                'identity': {
                    'methods': [
                        'token'
                    ],
                    'token': {
                        'id': token.id
                    }
                },
                'scope': {
                    'domain': {
                        'id': CONF.identity.default_domain_id
                    }
                }
            }
        }
        r = self.v3_create_token(auth_request)
        domain_scoped_token_id = r.headers.get('X-Subject-Token')

        # Validate the token to make sure the token providers handle non-uuid
        # domain IDs properly.
        headers = {'X-Subject-Token': domain_scoped_token_id}
        self.get(
            '/auth/tokens',
            token=domain_scoped_token_id,
            headers=headers
        )

    def test_issue_the_same_unscoped_token_with_user_deleted(self):
        r = self._issue_unscoped_token()
        token = render_token.render_token_response_from_model(r)['token']
        user1 = token['user']
        user_id1 = user1.pop('id')

        # delete the referenced user, and authenticate again. Keystone should
        # create another new shadow user.
        PROVIDERS.identity_api.delete_user(user_id1)

        r = self._issue_unscoped_token()
        token = render_token.render_token_response_from_model(r)['token']
        user2 = token['user']
        user_id2 = user2.pop('id')

        # Only the user_id is different. Other properties include
        # identity_provider, protocol, groups and domain are the same.
        self.assertIsNot(user_id2, user_id1)
        self.assertEqual(user1, user2)

    def test_issue_unscoped_token_disabled_idp(self):
        """Check if authentication works with disabled identity providers.

        Test plan:
        1) Disable default IdP
        2) Try issuing unscoped token for that IdP
        3) Expect server to forbid authentication

        """
        enabled_false = {'enabled': False}
        PROVIDERS.federation_api.update_idp(self.IDP, enabled_false)
        self.assertRaises(exception.Forbidden,
                          self._issue_unscoped_token)

    def test_issue_unscoped_token_group_names_in_mapping(self):
        r = self._issue_unscoped_token(assertion='ANOTHER_CUSTOMER_ASSERTION')
        ref_groups = set([self.group_customers['id'], self.group_admins['id']])
        token_groups = r.federated_groups
        token_groups = set([group['id'] for group in token_groups])
        self.assertEqual(ref_groups, token_groups)

    def test_issue_unscoped_tokens_nonexisting_group(self):
        self._issue_unscoped_token(assertion='ANOTHER_TESTER_ASSERTION')

    def test_issue_unscoped_token_with_remote_no_attribute(self):
        self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                   environment={
                                       self.REMOTE_ID_ATTR:
                                           self.REMOTE_IDS[0]
                                   })

    def test_issue_unscoped_token_with_remote(self):
        self.config_fixture.config(group='federation',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                   environment={
                                       self.REMOTE_ID_ATTR:
                                           self.REMOTE_IDS[0]
                                   })

    def test_issue_unscoped_token_with_saml2_remote(self):
        self.config_fixture.config(group='saml2',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                   environment={
                                       self.REMOTE_ID_ATTR:
                                           self.REMOTE_IDS[0]
                                   })

    def test_issue_unscoped_token_with_remote_different(self):
        self.config_fixture.config(group='federation',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        self.assertRaises(exception.Forbidden,
                          self._issue_unscoped_token,
                          idp=self.IDP_WITH_REMOTE,
                          environment={
                              self.REMOTE_ID_ATTR: uuid.uuid4().hex
                          })

    def test_issue_unscoped_token_with_remote_default_overwritten(self):
        """Test that protocol remote_id_attribute has higher priority.

        Make sure the parameter stored under ``protocol`` section has higher
        priority over parameter from default ``federation`` configuration
        section.

        """
        self.config_fixture.config(group='saml2',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        self.config_fixture.config(group='federation',
                                   remote_id_attribute=uuid.uuid4().hex)
        self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                   environment={
                                       self.REMOTE_ID_ATTR:
                                           self.REMOTE_IDS[0]
                                   })

    def test_issue_unscoped_token_with_remote_unavailable(self):
        self.config_fixture.config(group='federation',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token,
                          idp=self.IDP_WITH_REMOTE,
                          environment={
                              uuid.uuid4().hex: uuid.uuid4().hex
                          })

    def test_issue_unscoped_token_with_remote_user_as_empty_string(self):
        # make sure that REMOTE_USER set as the empty string won't interfere
        self._issue_unscoped_token(environment={'REMOTE_USER': ''})

    def test_issue_unscoped_token_no_groups(self):
        r = self._issue_unscoped_token(assertion='USER_NO_GROUPS_ASSERTION')
        token_groups = r.federated_groups
        self.assertEqual(0, len(token_groups))

    def test_issue_scoped_token_no_groups(self):
        """Verify that token without groups cannot get scoped to project.

        This test is required because of bug 1677723.
        """
        # issue unscoped token with no groups
        r = self._issue_unscoped_token(assertion='USER_NO_GROUPS_ASSERTION')
        token_groups = r.federated_groups
        self.assertEqual(0, len(token_groups))
        unscoped_token = r.id

        # let admin get roles in a project
        self.proj_employees
        admin = unit.new_user_ref(CONF.identity.default_domain_id)
        PROVIDERS.identity_api.create_user(admin)
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], user_id=admin['id'],
            project_id=self.proj_employees['id']
        )

        # try to scope the token. It should fail
        scope = self._scope_request(
            unscoped_token, 'project', self.proj_employees['id']
        )
        self.v3_create_token(
            scope, expected_status=http.client.UNAUTHORIZED)

    def test_issue_unscoped_token_malformed_environment(self):
        """Test whether non string objects are filtered out.

        Put non string objects into the environment, inject
        correct assertion and try to get an unscoped token.
        Expect server not to fail on using split() method on
        non string objects and return token id in the HTTP header.

        """
        environ = {
            'malformed_object': object(),
            'another_bad_idea': tuple(range(10)),
            'yet_another_bad_param': dict(zip(uuid.uuid4().hex, range(32)))
        }
        environ.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environ):
            authentication.authenticate_for_token(self.UNSCOPED_V3_SAML2_REQ)

    def test_scope_to_project_once_notify(self):
        r = self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE)
        user_id = r.json['token']['user']['id']
        self._assert_last_notify(self.ACTION, self.IDP, self.PROTOCOL, user_id)

    def test_scope_to_project_once(self):
        r = self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE)
        token_resp = r.result['token']
        project_id = token_resp['project']['id']
        self._check_project_scoped_token_attributes(token_resp, project_id)
        roles_ref = [self.role_employee]

        projects_ref = self.proj_employees
        self._check_projects_and_roles(token_resp, roles_ref, projects_ref)
        self.assertValidMappedUser(token_resp)

    def test_scope_token_with_idp_disabled(self):
        """Scope token issued by disabled IdP.

        Try scoping the token issued by an IdP which is disabled now. Expect
        server to refuse scoping operation.

        This test confirms correct behaviour when IdP was enabled and unscoped
        token was issued, but disabled before user tries to scope the token.
        Here we assume the unscoped token was already issued and start from
        the moment where IdP is being disabled and unscoped token is being
        used.

        Test plan:
        1) Disable IdP
        2) Try scoping unscoped token

        """
        enabled_false = {'enabled': False}
        PROVIDERS.federation_api.update_idp(self.IDP, enabled_false)
        self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER,
            expected_status=http.client.FORBIDDEN)

    def test_validate_token_after_deleting_idp_raises_not_found(self):
        token = self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN
        )
        token_id = token.headers.get('X-Subject-Token')
        federated_info = token.json_body['token']['user']['OS-FEDERATION']
        idp_id = federated_info['identity_provider']['id']
        PROVIDERS.federation_api.delete_idp(idp_id)
        headers = {
            'X-Subject-Token': token_id
        }
        # NOTE(lbragstad): This raises a 404 NOT FOUND because the identity
        # provider is no longer present. We raise 404 NOT FOUND when we
        # validate a token and a project or domain no longer exists.
        self.get(
            '/auth/tokens/',
            token=token_id,
            headers=headers,
            expected_status=http.client.NOT_FOUND
        )

    def test_deleting_idp_cascade_deleting_fed_user(self):
        token = self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN
        )
        federated_info = token.json_body['token']['user']['OS-FEDERATION']
        idp_id = federated_info['identity_provider']['id']

        # There are three fed users (from 'EMPLOYEE_ASSERTION',
        # 'CUSTOMER_ASSERTION', 'ADMIN_ASSERTION') with the specified idp.
        hints = driver_hints.Hints()
        hints.add_filter('idp_id', idp_id)
        fed_users = PROVIDERS.shadow_users_api.get_federated_users(hints)
        self.assertEqual(3, len(fed_users))
        idp_domain_id = PROVIDERS.federation_api.get_idp(idp_id)['domain_id']
        for fed_user in fed_users:
            self.assertEqual(idp_domain_id, fed_user['domain_id'])

        # Delete the idp
        PROVIDERS.federation_api.delete_idp(idp_id)

        # The related federated user should be deleted as well.
        hints = driver_hints.Hints()
        hints.add_filter('idp_id', idp_id)
        fed_users = PROVIDERS.shadow_users_api.get_federated_users(hints)
        self.assertEqual([], fed_users)

    def test_scope_to_bad_project(self):
        """Scope unscoped token with a project we don't have access to."""
        self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER,
            expected_status=http.client.UNAUTHORIZED)

    def test_scope_to_project_multiple_times(self):
        """Try to scope the unscoped token multiple times.

        The new tokens should be scoped to:

        * Customers' project
        * Employees' project

        """
        bodies = (self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN,
                  self.TOKEN_SCOPE_PROJECT_CUSTOMER_FROM_ADMIN)
        project_ids = (self.proj_employees['id'],
                       self.proj_customers['id'])
        for body, project_id_ref in zip(bodies, project_ids):
            r = self.v3_create_token(body)
            token_resp = r.result['token']
            self._check_project_scoped_token_attributes(token_resp,
                                                        project_id_ref)

    def test_scope_to_project_with_duplicate_roles_returns_single_role(self):
        r = self.v3_create_token(self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN)

        # Even though the process of obtaining a token shows that there is a
        # role assignment on a project, we should attempt to create a duplicate
        # assignment somewhere. Do this by creating a direct role assignment
        # with each role against the project the token was scoped to.
        user_id = r.json_body['token']['user']['id']
        project_id = r.json_body['token']['project']['id']
        for role in r.json_body['token']['roles']:
            PROVIDERS.assignment_api.create_grant(
                role_id=role['id'], user_id=user_id, project_id=project_id
            )

        # Ensure all roles in the token are unique even though we know there
        # should be duplicate role assignment from the assertions and the
        # direct role assignments we just created.
        r = self.v3_create_token(self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN)
        known_role_ids = []
        for role in r.json_body['token']['roles']:
            self.assertNotIn(role['id'], known_role_ids)
            known_role_ids.append(role['id'])

    def test_scope_to_project_with_only_inherited_roles(self):
        """Try to scope token whose only roles are inherited."""
        r = self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_INHERITED_FROM_CUSTOMER)
        token_resp = r.result['token']
        self._check_project_scoped_token_attributes(
            token_resp, self.project_inherited['id'])
        roles_ref = [self.role_customer]
        projects_ref = self.project_inherited
        self._check_projects_and_roles(token_resp, roles_ref, projects_ref)
        self.assertValidMappedUser(token_resp)

    def test_scope_token_from_nonexistent_unscoped_token(self):
        """Try to scope token from non-existent unscoped token."""
        self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_FROM_NONEXISTENT_TOKEN,
            expected_status=http.client.NOT_FOUND)

    def test_issue_token_from_rules_without_user(self):
        environ = copy.deepcopy(mapping_fixtures.BAD_TESTER_ASSERTION)
        with self.make_request(environ=environ):
            self.assertRaises(exception.Unauthorized,
                              authentication.authenticate_for_token,
                              self.UNSCOPED_V3_SAML2_REQ)

    def test_issue_token_with_nonexistent_group(self):
        """Inject assertion that matches rule issuing bad group id.

        Expect server to find out that some groups are missing in the
        backend and raise exception.MappedGroupNotFound exception.

        """
        self.assertRaises(exception.MappedGroupNotFound,
                          self._issue_unscoped_token,
                          assertion='CONTRACTOR_ASSERTION')

    def test_scope_to_domain_once(self):
        r = self.v3_create_token(self.TOKEN_SCOPE_DOMAIN_A_FROM_CUSTOMER)
        token_resp = r.result['token']
        self._check_domain_scoped_token_attributes(token_resp,
                                                   self.domainA['id'])

    def test_scope_to_domain_multiple_tokens(self):
        """Issue multiple tokens scoping to different domains.

        The new tokens should be scoped to:

        * domainA
        * domainB
        * domainC

        """
        bodies = (self.TOKEN_SCOPE_DOMAIN_A_FROM_ADMIN,
                  self.TOKEN_SCOPE_DOMAIN_B_FROM_ADMIN,
                  self.TOKEN_SCOPE_DOMAIN_C_FROM_ADMIN)
        domain_ids = (self.domainA['id'],
                      self.domainB['id'],
                      self.domainC['id'])

        for body, domain_id_ref in zip(bodies, domain_ids):
            r = self.v3_create_token(body)
            token_resp = r.result['token']
            self._check_domain_scoped_token_attributes(token_resp,
                                                       domain_id_ref)

    def test_scope_to_domain_with_only_inherited_roles_fails(self):
        """Try to scope to a domain that has no direct roles."""
        self.v3_create_token(
            self.TOKEN_SCOPE_DOMAIN_D_FROM_CUSTOMER,
            expected_status=http.client.UNAUTHORIZED)

    def test_list_projects(self):
        urls = ('/OS-FEDERATION/projects', '/auth/projects')

        token = (self.tokens['CUSTOMER_ASSERTION'],
                 self.tokens['EMPLOYEE_ASSERTION'],
                 self.tokens['ADMIN_ASSERTION'])

        projects_refs = (set([self.proj_customers['id'],
                              self.project_inherited['id']]),
                         set([self.proj_employees['id'],
                              self.project_all['id']]),
                         set([self.proj_employees['id'],
                              self.project_all['id'],
                              self.proj_customers['id'],
                              self.project_inherited['id']]))

        for token, projects_ref in zip(token, projects_refs):
            for url in urls:
                r = self.get(url, token=token)
                projects_resp = r.result['projects']
                projects = set(p['id'] for p in projects_resp)
                self.assertEqual(projects_ref, projects,
                                 'match failed for url %s' % url)

    # TODO(samueldmq): Create another test class for role inheritance tests.
    # The advantage would be to reduce the complexity of this test class and
    # have tests specific to this functionality grouped, easing readability and
    # maintenability.
    def test_list_projects_for_inherited_project_assignment(self):
        # Create a subproject
        subproject_inherited = unit.new_project_ref(
            domain_id=self.domainD['id'],
            parent_id=self.project_inherited['id'])
        PROVIDERS.resource_api.create_project(
            subproject_inherited['id'], subproject_inherited
        )

        # Create an inherited role assignment
        PROVIDERS.assignment_api.create_grant(
            role_id=self.role_employee['id'],
            group_id=self.group_employees['id'],
            project_id=self.project_inherited['id'],
            inherited_to_projects=True)

        # Define expected projects from employee assertion, which contain
        # the created subproject
        expected_project_ids = [self.project_all['id'],
                                self.proj_employees['id'],
                                subproject_inherited['id']]

        # Assert expected projects for both available URLs
        for url in ('/OS-FEDERATION/projects', '/auth/projects'):
            r = self.get(url, token=self.tokens['EMPLOYEE_ASSERTION'])
            project_ids = [project['id'] for project in r.result['projects']]

            self.assertEqual(len(expected_project_ids), len(project_ids))
            for expected_project_id in expected_project_ids:
                self.assertIn(expected_project_id, project_ids,
                              'Projects match failed for url %s' % url)

    def test_list_domains(self):
        urls = ('/OS-FEDERATION/domains', '/auth/domains')

        tokens = (self.tokens['CUSTOMER_ASSERTION'],
                  self.tokens['EMPLOYEE_ASSERTION'],
                  self.tokens['ADMIN_ASSERTION'])

        # NOTE(henry-nash): domain D does not appear in the expected results
        # since it only had inherited roles (which only apply to projects
        # within the domain)

        domain_refs = (set([self.domainA['id']]),
                       set([self.domainA['id'],
                            self.domainB['id']]),
                       set([self.domainA['id'],
                            self.domainB['id'],
                            self.domainC['id']]))

        for token, domains_ref in zip(tokens, domain_refs):
            for url in urls:
                r = self.get(url, token=token)
                domains_resp = r.result['domains']
                domains = set(p['id'] for p in domains_resp)
                self.assertEqual(domains_ref, domains,
                                 'match failed for url %s' % url)

    def test_full_workflow(self):
        """Test 'standard' workflow for granting access tokens.

        * Issue unscoped token
        * List available projects based on groups
        * Scope token to one of available projects

        """
        r = self._issue_unscoped_token()
        token_resp = render_token.render_token_response_from_model(r)['token']
        # NOTE(lbragstad): Ensure only 'saml2' is in the method list.
        self.assertListEqual(['saml2'], r.methods)
        self.assertValidMappedUser(token_resp)
        employee_unscoped_token_id = r.id
        r = self.get('/auth/projects', token=employee_unscoped_token_id)
        projects = r.result['projects']
        random_project = random.randint(0, len(projects) - 1)
        project = projects[random_project]

        v3_scope_request = self._scope_request(employee_unscoped_token_id,
                                               'project', project['id'])

        r = self.v3_create_token(v3_scope_request)
        token_resp = r.result['token']
        self.assertIn('token', token_resp['methods'])
        self.assertIn('saml2', token_resp['methods'])
        self._check_project_scoped_token_attributes(token_resp, project['id'])

    def test_workflow_with_groups_deletion(self):
        """Test full workflow with groups deletion before token scoping.

        The test scenario is as follows:
         - Create group ``group``
         - Create and assign roles to ``group`` and ``project_all``
         - Patch mapping rules for existing IdP so it issues group id
         - Issue unscoped token with ``group``'s id
         - Delete group ``group``
         - Scope token to ``project_all``
         - Expect HTTP 500 response

        """
        # create group and role
        group = unit.new_group_ref(domain_id=self.domainA['id'])
        group = PROVIDERS.identity_api.create_group(group)
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        # assign role to group and project_admins
        PROVIDERS.assignment_api.create_grant(
            role['id'], group_id=group['id'], project_id=self.project_all['id']
        )

        rules = {
            'rules': [
                {
                    'local': [
                        {
                            'group': {
                                'id': group['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'LastName',
                            'any_one_of': [
                                'Account'
                            ]
                        }
                    ]
                }
            ]
        }

        PROVIDERS.federation_api.update_mapping(self.mapping['id'], rules)

        r = self._issue_unscoped_token(assertion='TESTER_ASSERTION')

        # delete group
        PROVIDERS.identity_api.delete_group(group['id'])

        # scope token to project_all, expect HTTP 500
        scoped_token = self._scope_request(
            r.id, 'project',
            self.project_all['id'])

        self.v3_create_token(
            scoped_token, expected_status=http.client.INTERNAL_SERVER_ERROR)

    def test_lists_with_missing_group_in_backend(self):
        """Test a mapping that points to a group that does not exist.

        For explicit mappings, we expect the group to exist in the backend,
        but for lists, specifically blacklists, a missing group is expected
        as many groups will be specified by the IdP that are not Keystone
        groups.

        The test scenario is as follows:
         - Create group ``EXISTS``
         - Set mapping rules for existing IdP with a blacklist
           that passes through as REMOTE_USER_GROUPS
         - Issue unscoped token with on group  ``EXISTS`` id in it

        """
        domain_id = self.domainA['id']
        domain_name = self.domainA['name']
        group = unit.new_group_ref(domain_id=domain_id, name='EXISTS')
        group = PROVIDERS.identity_api.create_group(group)
        rules = {
            'rules': [
                {
                    "local": [
                        {
                            "user": {
                                "name": "{0}",
                                "id": "{0}"
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER"
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "groups": "{0}",
                            "domain": {"name": domain_name}
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER_GROUPS",
                        }
                    ]
                }
            ]
        }
        PROVIDERS.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_group_ids = r.federated_groups
        self.assertEqual(1, len(assigned_group_ids))
        self.assertEqual(group['id'], assigned_group_ids[0]['id'])

    def test_empty_blacklist_passess_all_values(self):
        """Test a mapping with empty blacklist specified.

        Not adding a ``blacklist`` keyword to the mapping rules has the same
        effect as adding an empty ``blacklist``.
        In both cases, the mapping engine will not discard any groups that are
        associated with apache environment variables.

        This test checks scenario where an empty blacklist was specified.
        Expected result is to allow any value.

        The test scenario is as follows:
         - Create group ``EXISTS``
         - Create group ``NO_EXISTS``
         - Set mapping rules for existing IdP with a blacklist
           that passes through as REMOTE_USER_GROUPS
         - Issue unscoped token with groups  ``EXISTS`` and ``NO_EXISTS``
           assigned

        """
        domain_id = self.domainA['id']
        domain_name = self.domainA['name']

        # Add a group "EXISTS"
        group_exists = unit.new_group_ref(domain_id=domain_id, name='EXISTS')
        group_exists = PROVIDERS.identity_api.create_group(group_exists)

        # Add a group "NO_EXISTS"
        group_no_exists = unit.new_group_ref(domain_id=domain_id,
                                             name='NO_EXISTS')
        group_no_exists = PROVIDERS.identity_api.create_group(group_no_exists)

        group_ids = set([group_exists['id'], group_no_exists['id']])

        rules = {
            'rules': [
                {
                    "local": [
                        {
                            "user": {
                                "name": "{0}",
                                "id": "{0}"
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER"
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "groups": "{0}",
                            "domain": {"name": domain_name}
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER_GROUPS",
                            "blacklist": []
                        }
                    ]
                }
            ]
        }
        PROVIDERS.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_group_ids = r.federated_groups
        self.assertEqual(len(group_ids), len(assigned_group_ids))
        for group in assigned_group_ids:
            self.assertIn(group['id'], group_ids)

    def test_not_adding_blacklist_passess_all_values(self):
        """Test a mapping without blacklist specified.

        Not adding a ``blacklist`` keyword to the mapping rules has the same
        effect as adding an empty ``blacklist``. In both cases all values will
        be accepted and passed.

        This test checks scenario where an blacklist was not specified.
        Expected result is to allow any value.

        The test scenario is as follows:
         - Create group ``EXISTS``
         - Create group ``NO_EXISTS``
         - Set mapping rules for existing IdP with a blacklist
           that passes through as REMOTE_USER_GROUPS
         - Issue unscoped token with on groups ``EXISTS`` and ``NO_EXISTS``
           assigned

        """
        domain_id = self.domainA['id']
        domain_name = self.domainA['name']

        # Add a group "EXISTS"
        group_exists = unit.new_group_ref(domain_id=domain_id,
                                          name='EXISTS')
        group_exists = PROVIDERS.identity_api.create_group(group_exists)

        # Add a group "NO_EXISTS"
        group_no_exists = unit.new_group_ref(domain_id=domain_id,
                                             name='NO_EXISTS')
        group_no_exists = PROVIDERS.identity_api.create_group(group_no_exists)

        group_ids = set([group_exists['id'], group_no_exists['id']])

        rules = {
            'rules': [
                {
                    "local": [
                        {
                            "user": {
                                "name": "{0}",
                                "id": "{0}"
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER"
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "groups": "{0}",
                            "domain": {"name": domain_name}
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER_GROUPS",
                        }
                    ]
                }
            ]
        }
        PROVIDERS.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_group_ids = r.federated_groups
        self.assertEqual(len(group_ids), len(assigned_group_ids))
        for group in assigned_group_ids:
            self.assertIn(group['id'], group_ids)

    def test_empty_whitelist_discards_all_values(self):
        """Test that empty whitelist blocks all the values.

        Not adding a ``whitelist`` keyword to the mapping value is different
        than adding empty whitelist.  The former case will simply pass all the
        values, whereas the latter would discard all the values.

        This test checks scenario where an empty whitelist was specified.
        The expected result is that no groups are matched.

        The test scenario is as follows:
         - Create group ``EXISTS``
         - Set mapping rules for existing IdP with an empty whitelist
           that whould discard any values from the assertion
         - Try issuing unscoped token, no groups were matched and that the
           federated user does not have any group assigned.

        """
        domain_id = self.domainA['id']
        domain_name = self.domainA['name']
        group = unit.new_group_ref(domain_id=domain_id, name='EXISTS')
        group = PROVIDERS.identity_api.create_group(group)
        rules = {
            'rules': [
                {
                    "local": [
                        {
                            "user": {
                                "name": "{0}",
                                "id": "{0}"
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER"
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "groups": "{0}",
                            "domain": {"name": domain_name}
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER_GROUPS",
                            "whitelist": []
                        }
                    ]
                }
            ]
        }
        PROVIDERS.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_groups = r.federated_groups
        self.assertEqual(len(assigned_groups), 0)

    def test_not_setting_whitelist_accepts_all_values(self):
        """Test that not setting whitelist passes.

        Not adding a ``whitelist`` keyword to the mapping value is different
        than adding empty whitelist.  The former case will simply pass all the
        values, whereas the latter would discard all the values.

        This test checks a scenario where a ``whitelist`` was not specified.
        Expected result is that no groups are ignored.

        The test scenario is as follows:
         - Create group ``EXISTS``
         - Set mapping rules for existing IdP with an empty whitelist
           that whould discard any values from the assertion
         - Issue an unscoped token and make sure ephemeral user is a member of
           two groups.

        """
        domain_id = self.domainA['id']
        domain_name = self.domainA['name']

        # Add a group "EXISTS"
        group_exists = unit.new_group_ref(domain_id=domain_id,
                                          name='EXISTS')
        group_exists = PROVIDERS.identity_api.create_group(group_exists)

        # Add a group "NO_EXISTS"
        group_no_exists = unit.new_group_ref(domain_id=domain_id,
                                             name='NO_EXISTS')
        group_no_exists = PROVIDERS.identity_api.create_group(group_no_exists)

        group_ids = set([group_exists['id'], group_no_exists['id']])

        rules = {
            'rules': [
                {
                    "local": [
                        {
                            "user": {
                                "name": "{0}",
                                "id": "{0}"
                            }
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER"
                        }
                    ]
                },
                {
                    "local": [
                        {
                            "groups": "{0}",
                            "domain": {"name": domain_name}
                        }
                    ],
                    "remote": [
                        {
                            "type": "REMOTE_USER_GROUPS",
                        }
                    ]
                }
            ]
        }
        PROVIDERS.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_group_ids = r.federated_groups
        self.assertEqual(len(group_ids), len(assigned_group_ids))
        for group in assigned_group_ids:
            self.assertIn(group['id'], group_ids)

    def test_assertion_prefix_parameter(self):
        """Test parameters filtering based on the prefix.

        With ``assertion_prefix`` set to fixed, non default value,
        issue an unscoped token from assertion EMPLOYEE_ASSERTION_PREFIXED.
        Expect server to return unscoped token.

        """
        self.config_fixture.config(group='federation',
                                   assertion_prefix=self.ASSERTION_PREFIX)
        self._issue_unscoped_token(assertion='EMPLOYEE_ASSERTION_PREFIXED')

    def test_assertion_prefix_parameter_expect_fail(self):
        """Test parameters filtering based on the prefix.

        With ``assertion_prefix`` default value set to empty string
        issue an unscoped token from assertion EMPLOYEE_ASSERTION.
        Next, configure ``assertion_prefix`` to value ``UserName``.
        Try issuing unscoped token with EMPLOYEE_ASSERTION.
        Expect server to raise exception.Unathorized exception.

        """
        self._issue_unscoped_token()
        self.config_fixture.config(group='federation',
                                   assertion_prefix='UserName')

        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token)

    def test_unscoped_token_has_user_domain(self):
        r = self._issue_unscoped_token()
        self._check_domains_are_valid(
            render_token.render_token_response_from_model(r)['token'])

    def test_scoped_token_has_user_domain(self):
        r = self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE)
        self._check_domains_are_valid(r.json_body['token'])

    def test_issue_unscoped_token_for_local_user(self):
        r = self._issue_unscoped_token(assertion='LOCAL_USER_ASSERTION')
        self.assertListEqual(['saml2'], r.methods)
        self.assertEqual(self.user['id'], r.user_id)
        self.assertEqual(self.user['name'], r.user['name'])
        self.assertEqual(self.domain['id'], r.user_domain['id'])
        # Make sure the token is not scoped
        self.assertIsNone(r.domain_id)
        self.assertIsNone(r.project_id)
        self.assertTrue(r.unscoped)

    def test_issue_token_for_local_user_user_not_found(self):
        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token,
                          assertion='ANOTHER_LOCAL_USER_ASSERTION')

    def test_user_name_and_id_in_federation_token(self):
        r = self._issue_unscoped_token(assertion='EMPLOYEE_ASSERTION')
        self.assertEqual(
            mapping_fixtures.EMPLOYEE_ASSERTION['UserName'],
            r.user['name'])
        self.assertNotEqual(r.user['name'], r.user_id)
        r = self.v3_create_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE)
        token = r.json_body['token']
        self.assertEqual(
            mapping_fixtures.EMPLOYEE_ASSERTION['UserName'],
            token['user']['name'])
        self.assertNotEqual(token['user']['name'], token['user']['id'])

    def test_issue_unscoped_token_with_remote_different_from_protocol(self):
        protocol = PROVIDERS.federation_api.get_protocol(
            self.IDP_WITH_REMOTE, self.PROTOCOL
        )
        protocol['remote_id_attribute'] = uuid.uuid4().hex
        PROVIDERS.federation_api.update_protocol(
            self.IDP_WITH_REMOTE, protocol['id'], protocol
        )
        self._issue_unscoped_token(
            idp=self.IDP_WITH_REMOTE,
            environment={
                protocol['remote_id_attribute']: self.REMOTE_IDS[0]
            }
        )
        self.assertRaises(
            exception.Unauthorized,
            self._issue_unscoped_token,
            idp=self.IDP_WITH_REMOTE,
            environment={uuid.uuid4().hex: self.REMOTE_IDS[0]}
        )


class FernetFederatedTokenTests(test_v3.RestfulTestCase, FederatedSetupMixin):
    AUTH_METHOD = 'token'

    def load_fixtures(self, fixtures):
        super(FernetFederatedTokenTests, self).load_fixtures(fixtures)
        self.load_federation_sample_data()

    def config_overrides(self):
        super(FernetFederatedTokenTests, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def auth_plugin_config_override(self):
        methods = ['saml2', 'token', 'password']
        super(FernetFederatedTokenTests,
              self).auth_plugin_config_override(methods)

    def test_federated_unscoped_token(self):
        resp = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(resp)['token'])

    def test_federated_unscoped_token_with_multiple_groups(self):
        assertion = 'ANOTHER_CUSTOMER_ASSERTION'
        resp = self._issue_unscoped_token(assertion=assertion)
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(resp)['token'])

    def test_validate_federated_unscoped_token(self):
        resp = self._issue_unscoped_token()
        unscoped_token = resp.id
        # assert that the token we received is valid
        self.get('/auth/tokens/', headers={'X-Subject-Token': unscoped_token})

    def test_fernet_full_workflow(self):
        """Test 'standard' workflow for granting Fernet access tokens.

        * Issue unscoped token
        * List available projects based on groups
        * Scope token to one of available projects

        """
        resp = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(resp)['token'])
        unscoped_token = resp.id
        resp = self.get('/auth/projects', token=unscoped_token)
        projects = resp.result['projects']
        random_project = random.randint(0, len(projects) - 1)
        project = projects[random_project]

        v3_scope_request = self._scope_request(unscoped_token,
                                               'project', project['id'])

        resp = self.v3_create_token(v3_scope_request)
        token_resp = resp.result['token']
        self._check_project_scoped_token_attributes(token_resp, project['id'])


class JWSFederatedTokenTests(test_v3.RestfulTestCase, FederatedSetupMixin):
    AUTH_METHOD = 'token'

    def load_fixtures(self, fixtures):
        super(JWSFederatedTokenTests, self).load_fixtures(fixtures)
        self.load_federation_sample_data()

    def config_overrides(self):
        super(JWSFederatedTokenTests, self).config_overrides()
        self.config_fixture.config(group='token', provider='jws')
        self.useFixture(ksfixtures.JWSKeyRepository(self.config_fixture))

    def auth_plugin_config_override(self):
        methods = ['saml2', 'token', 'password']
        super(JWSFederatedTokenTests,
              self).auth_plugin_config_override(methods)

    def test_federated_unscoped_token(self):
        token_model = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(token_model)['token']
        )

    def test_federated_unscoped_token_with_multiple_groups(self):
        assertion = 'ANOTHER_CUSTOMER_ASSERTION'
        token_model = self._issue_unscoped_token(assertion=assertion)
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(token_model)['token']
        )

    def test_validate_federated_unscoped_token(self):
        token_model = self._issue_unscoped_token()
        unscoped_token = token_model.id
        # assert that the token we received is valid
        self.get('/auth/tokens/', headers={'X-Subject-Token': unscoped_token})

    def test_jws_full_workflow(self):
        """Test 'standard' workflow for granting JWS tokens.

        * Issue unscoped token
        * List available projects based on groups
        * Scope token to one of available projects

        """
        token_model = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(token_model)['token']
        )
        unscoped_token = token_model.id
        resp = self.get('/auth/projects', token=unscoped_token)
        projects = resp.result['projects']
        random_project = random.randint(0, len(projects) - 1)
        project = projects[random_project]

        v3_scope_request = self._scope_request(unscoped_token,
                                               'project', project['id'])

        resp = self.v3_create_token(v3_scope_request)
        token_resp = resp.result['token']
        self._check_project_scoped_token_attributes(token_resp, project['id'])


class FederatedTokenTestsMethodToken(FederatedTokenTests):
    """Test federation operation with unified scoping auth method.

    Test all the operations with auth method set to ``token`` as a new, unified
    way for scoping all the tokens.

    """

    AUTH_METHOD = 'token'

    def auth_plugin_config_override(self):
        methods = ['saml2', 'token']
        super(FederatedTokenTests,
              self).auth_plugin_config_override(methods)

    def test_full_workflow(self):
        """Test 'standard' workflow for granting access tokens.

        * Issue unscoped token
        * List available projects based on groups
        * Scope token to one of available projects

        """
        r = self._issue_unscoped_token()
        token_resp = render_token.render_token_response_from_model(r)['token']
        # NOTE(lbragstad): Ensure only 'saml2' is in the method list.
        self.assertListEqual(['saml2'], r.methods)
        self.assertValidMappedUser(token_resp)
        employee_unscoped_token_id = r.id
        r = self.get('/auth/projects', token=employee_unscoped_token_id)
        projects = r.result['projects']
        random_project = random.randint(0, len(projects) - 1)
        project = projects[random_project]

        v3_scope_request = self._scope_request(employee_unscoped_token_id,
                                               'project', project['id'])

        r = self.v3_create_token(v3_scope_request)
        token_resp = r.result['token']
        self.assertIn('token', token_resp['methods'])
        self.assertIn('saml2', token_resp['methods'])
        self._check_project_scoped_token_attributes(token_resp, project['id'])


class FederatedUserTests(test_v3.RestfulTestCase, FederatedSetupMixin):
    """Test for federated users.

    Tests new shadow users functionality

    """

    def auth_plugin_config_override(self):
        methods = ['saml2', 'token']
        super(FederatedUserTests, self).auth_plugin_config_override(methods)

    def load_fixtures(self, fixtures):
        super(FederatedUserTests, self).load_fixtures(fixtures)
        self.load_federation_sample_data()

    def test_user_id_persistense(self):
        """Ensure user_id is persistend for multiple federated authn calls."""
        r = self._issue_unscoped_token()
        user_id = r.user_id
        self.assertNotEmpty(PROVIDERS.identity_api.get_user(user_id))

        r = self._issue_unscoped_token()
        user_id2 = r.user_id
        self.assertNotEmpty(PROVIDERS.identity_api.get_user(user_id2))
        self.assertEqual(user_id, user_id2)

    def test_user_role_assignment(self):
        # create project and role
        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)

        # authenticate via saml get back a user id
        user_id, unscoped_token = self._authenticate_via_saml()

        # exchange an unscoped token for a scoped token; resulting in
        # unauthorized because the user doesn't have any role assignments
        v3_scope_request = self._scope_request(unscoped_token, 'project',
                                               project_ref['id'])
        r = self.v3_create_token(v3_scope_request,
                                 expected_status=http.client.UNAUTHORIZED)

        # assign project role to federated user
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user_id, project_ref['id'], role_ref['id'])

        # exchange an unscoped token for a scoped token
        r = self.v3_create_token(v3_scope_request,
                                 expected_status=http.client.CREATED)
        scoped_token = r.headers['X-Subject-Token']

        # ensure user can access resource based on role assignment
        path = '/projects/%(project_id)s' % {'project_id': project_ref['id']}
        r = self.v3_request(path=path, method='GET',
                            expected_status=http.client.OK,
                            token=scoped_token)
        self.assertValidProjectResponse(r, project_ref)

        # create a 2nd project
        project_ref2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project_ref2['id'], project_ref2)

        # ensure the user cannot access the 2nd resource (forbidden)
        path = '/projects/%(project_id)s' % {'project_id': project_ref2['id']}
        r = self.v3_request(path=path, method='GET',
                            expected_status=http.client.FORBIDDEN,
                            token=scoped_token)

    def test_domain_scoped_user_role_assignment(self):
        # create domain and role
        domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)

        # authenticate via saml get back a user id
        user_id, unscoped_token = self._authenticate_via_saml()

        # exchange an unscoped token for a scoped token; resulting in
        # unauthorized because the user doesn't have any role assignments
        v3_scope_request = self._scope_request(unscoped_token, 'domain',
                                               domain_ref['id'])
        r = self.v3_create_token(v3_scope_request,
                                 expected_status=http.client.UNAUTHORIZED)

        # assign domain role to user
        PROVIDERS.assignment_api.create_grant(
            role_ref['id'], user_id=user_id, domain_id=domain_ref['id']
        )

        # exchange an unscoped token for domain scoped token and test
        r = self.v3_create_token(v3_scope_request,
                                 expected_status=http.client.CREATED)
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))
        token_resp = r.result['token']
        self.assertIn('domain', token_resp)

    def test_auth_projects_matches_federation_projects(self):
        # create project and role
        project_ref = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)

        # authenticate via saml get back a user id
        user_id, unscoped_token = self._authenticate_via_saml()

        # assign project role to federated user
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user_id, project_ref['id'], role_ref['id'])

        # get auth projects
        r = self.get('/auth/projects', token=unscoped_token)
        auth_projects = r.result['projects']

        # get federation projects
        r = self.get('/OS-FEDERATION/projects', token=unscoped_token)
        fed_projects = r.result['projects']

        # compare
        self.assertCountEqual(auth_projects, fed_projects)

    def test_auth_projects_matches_federation_projects_with_group_assign(self):
        # create project, role, group
        domain_id = CONF.identity.default_domain_id
        project_ref = unit.new_project_ref(domain_id=domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        group_ref = unit.new_group_ref(domain_id=domain_id)
        group_ref = PROVIDERS.identity_api.create_group(group_ref)

        # authenticate via saml get back a user id
        user_id, unscoped_token = self._authenticate_via_saml()

        # assign role to group at project
        PROVIDERS.assignment_api.create_grant(
            role_ref['id'], group_id=group_ref['id'],
            project_id=project_ref['id'], domain_id=domain_id
        )

        # add user to group
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user_id, group_id=group_ref['id']
        )

        # get auth projects
        r = self.get('/auth/projects', token=unscoped_token)
        auth_projects = r.result['projects']

        # get federation projects
        r = self.get('/OS-FEDERATION/projects', token=unscoped_token)
        fed_projects = r.result['projects']

        # compare
        self.assertCountEqual(auth_projects, fed_projects)

    def test_auth_domains_matches_federation_domains(self):
        # create domain and role
        domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)

        # authenticate via saml get back a user id and token
        user_id, unscoped_token = self._authenticate_via_saml()

        # assign domain role to user
        PROVIDERS.assignment_api.create_grant(
            role_ref['id'], user_id=user_id, domain_id=domain_ref['id']
        )

        # get auth domains
        r = self.get('/auth/domains', token=unscoped_token)
        auth_domains = r.result['domains']

        # get federation domains
        r = self.get('/OS-FEDERATION/domains', token=unscoped_token)
        fed_domains = r.result['domains']

        # compare
        self.assertCountEqual(auth_domains, fed_domains)

    def test_auth_domains_matches_federation_domains_with_group_assign(self):
        # create role, group, and domain
        domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        group_ref = unit.new_group_ref(domain_id=domain_ref['id'])
        group_ref = PROVIDERS.identity_api.create_group(group_ref)

        # authenticate via saml get back a user id and token
        user_id, unscoped_token = self._authenticate_via_saml()

        # assign domain role to group
        PROVIDERS.assignment_api.create_grant(
            role_ref['id'], group_id=group_ref['id'],
            domain_id=domain_ref['id']
        )

        # add user to group
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user_id, group_id=group_ref['id']
        )

        # get auth domains
        r = self.get('/auth/domains', token=unscoped_token)
        auth_domains = r.result['domains']

        # get federation domains
        r = self.get('/OS-FEDERATION/domains', token=unscoped_token)
        fed_domains = r.result['domains']

        # compare
        self.assertCountEqual(auth_domains, fed_domains)

    def test_list_head_domains_for_user_duplicates(self):
        # create role
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)

        # authenticate via saml get back a user id and token
        user_id, unscoped_token = self._authenticate_via_saml()

        # get federation group domains
        r = self.get('/OS-FEDERATION/domains', token=unscoped_token)
        group_domains = r.result['domains']
        domain_from_group = group_domains[0]

        self.head(
            '/OS-FEDERATION/domains',
            token=unscoped_token,
            expected_status=http.client.OK
        )

        # assign group domain and role to user, this should create a
        # duplicate domain
        PROVIDERS.assignment_api.create_grant(
            role_ref['id'], user_id=user_id, domain_id=domain_from_group['id']
        )

        # get user domains via /OS-FEDERATION/domains and test for duplicates
        r = self.get('/OS-FEDERATION/domains', token=unscoped_token)
        user_domains = r.result['domains']
        user_domain_ids = []
        for domain in user_domains:
            self.assertNotIn(domain['id'], user_domain_ids)
            user_domain_ids.append(domain['id'])

        # get user domains via /auth/domains and test for duplicates
        r = self.get('/auth/domains', token=unscoped_token)
        user_domains = r.result['domains']
        user_domain_ids = []
        for domain in user_domains:
            self.assertNotIn(domain['id'], user_domain_ids)
            user_domain_ids.append(domain['id'])

    def test_list_head_projects_for_user_duplicates(self):
        # create role
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)

        # authenticate via saml get back a user id and token
        user_id, unscoped_token = self._authenticate_via_saml()

        # get federation group projects
        r = self.get('/OS-FEDERATION/projects', token=unscoped_token)
        group_projects = r.result['projects']
        project_from_group = group_projects[0]

        self.head(
            '/OS-FEDERATION/projects',
            token=unscoped_token,
            expected_status=http.client.OK
        )

        # assign group project and role to user, this should create a
        # duplicate project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user_id, project_from_group['id'], role_ref['id'])

        # get user projects via /OS-FEDERATION/projects and test for duplicates
        r = self.get('/OS-FEDERATION/projects', token=unscoped_token)
        user_projects = r.result['projects']
        user_project_ids = []
        for project in user_projects:
            self.assertNotIn(project['id'], user_project_ids)
            user_project_ids.append(project['id'])

        # get user projects via /auth/projects and test for duplicates
        r = self.get('/auth/projects', token=unscoped_token)
        user_projects = r.result['projects']
        user_project_ids = []
        for project in user_projects:
            self.assertNotIn(project['id'], user_project_ids)
            user_project_ids.append(project['id'])

    def test_delete_protocol_after_federated_authentication(self):
        # Create a protocol
        protocol = self.proto_ref(mapping_id=self.mapping['id'])
        PROVIDERS.federation_api.create_protocol(
            self.IDP, protocol['id'], protocol)

        # Authenticate to create a new federated_user entry with a foreign
        # key pointing to the protocol
        r = self._issue_unscoped_token()
        user_id = r.user_id
        self.assertNotEmpty(PROVIDERS.identity_api.get_user(user_id))

        # Now we should be able to delete the protocol
        PROVIDERS.federation_api.delete_protocol(self.IDP, protocol['id'])

    def _authenticate_via_saml(self):
        r = self._issue_unscoped_token()
        unscoped_token = r.id
        token_resp = render_token.render_token_response_from_model(r)['token']
        self.assertValidMappedUser(token_resp)
        return r.user_id, unscoped_token


class ShadowMappingTests(test_v3.RestfulTestCase, FederatedSetupMixin):
    """Test class dedicated to auto-provisioning resources at login.

    A shadow mapping is a mapping that contains extra properties about that
    specific federated user's situation based on attributes from the assertion.
    For example, a shadow mapping can tell us that a user should have specific
    role assignments on certain projects within a domain. When a federated user
    authenticates, the shadow mapping will create these entities before
    returning the authenticated response to the user. This test class is
    dedicated to testing specific aspects of shadow mapping when performing
    federated authentication.
    """

    def setUp(self):
        super(ShadowMappingTests, self).setUp()
        # update the mapping we have already setup to have specific projects
        # and roles.
        PROVIDERS.federation_api.update_mapping(
            self.mapping['id'],
            mapping_fixtures.MAPPING_PROJECTS
        )

        # The shadow mapping we're using in these tests contain a role named
        # `member` and `observer` for the sake of using something other than
        # `admin`. We'll need to create those before hand, otherwise the
        # mapping will fail during authentication because the roles defined in
        # the mapping do not exist yet. The shadow mapping mechanism currently
        # doesn't support creating roles on-the-fly, but this could change in
        # the future after we get some feedback from shadow mapping being used
        # in real deployments. We also want to make sure we are dealing with
        # global roles and not domain-scoped roles. We have specific tests
        # below that test that behavior and the setup is done in the test.
        member_role_ref = unit.new_role_ref(name='member')
        assert member_role_ref['domain_id'] is None
        self.member_role = PROVIDERS.role_api.create_role(
            member_role_ref['id'], member_role_ref
        )
        observer_role_ref = unit.new_role_ref(name='observer')
        assert observer_role_ref['domain_id'] is None
        self.observer_role = PROVIDERS.role_api.create_role(
            observer_role_ref['id'], observer_role_ref
        )

        # This is a mapping of the project name to the role that is supposed to
        # be assigned to the user on that project from the shadow mapping.
        self.expected_results = {
            'Production': 'observer',
            'Staging': 'member',
            'Project for tbo': 'admin'
        }

    def auth_plugin_config_override(self):
        methods = ['saml2', 'token']
        super(ShadowMappingTests, self).auth_plugin_config_override(methods)

    def load_fixtures(self, fixtures):
        super(ShadowMappingTests, self).load_fixtures(fixtures)
        self.load_federation_sample_data()

    def test_shadow_mapping_creates_projects(self):
        projects = PROVIDERS.resource_api.list_projects()
        for project in projects:
            self.assertNotIn(project['name'], self.expected_results)

        response = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(response)['token'])
        unscoped_token = response.id
        response = self.get('/auth/projects', token=unscoped_token)
        projects = response.json_body['projects']
        for project in projects:
            project = PROVIDERS.resource_api.get_project_by_name(
                project['name'],
                self.idp['domain_id']
            )
            self.assertIn(project['name'], self.expected_results)

    def test_shadow_mapping_create_projects_role_assignments(self):
        response = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(response)['token'])
        unscoped_token = response.id
        response = self.get('/auth/projects', token=unscoped_token)
        projects = response.json_body['projects']
        for project in projects:
            # Ask for a scope token to each project in the mapping. Each token
            # should contain a different role so let's check that is right,
            # too.
            scope = self._scope_request(
                unscoped_token, 'project', project['id']
            )
            response = self.v3_create_token(scope)
            project_name = response.json_body['token']['project']['name']
            roles = response.json_body['token']['roles']
            self.assertEqual(
                self.expected_results[project_name], roles[0]['name']
            )

    def test_shadow_mapping_does_not_create_roles(self):
        # If a role required by the mapping does not exist, then we should fail
        # the mapping since shadow mapping currently does not support creating
        # mappings on-the-fly.
        PROVIDERS.role_api.delete_role(self.observer_role['id'])
        self.assertRaises(exception.RoleNotFound, self._issue_unscoped_token)

    def test_shadow_mapping_creates_project_in_identity_provider_domain(self):
        response = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(response)['token'])
        unscoped_token = response.id
        response = self.get('/auth/projects', token=unscoped_token)
        projects = response.json_body['projects']
        for project in projects:
            self.assertEqual(project['domain_id'], self.idp['domain_id'])

    def test_shadow_mapping_is_idempotent(self):
        """Test that projects remain idempotent for every federated auth."""
        response = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(response)['token'])
        unscoped_token = response.id
        response = self.get('/auth/projects', token=unscoped_token)
        project_ids = [p['id'] for p in response.json_body['projects']]
        response = self._issue_unscoped_token()
        unscoped_token = response.id
        response = self.get('/auth/projects', token=unscoped_token)
        projects = response.json_body['projects']
        for project in projects:
            self.assertIn(project['id'], project_ids)

    def test_roles_outside_idp_domain_fail_mapping(self):
        # Create a new domain
        d = unit.new_domain_ref()
        new_domain = PROVIDERS.resource_api.create_domain(d['id'], d)

        # Delete the member role and recreate it in a different domain
        PROVIDERS.role_api.delete_role(self.member_role['id'])
        member_role_ref = unit.new_role_ref(
            name='member',
            domain_id=new_domain['id']
        )
        PROVIDERS.role_api.create_role(member_role_ref['id'], member_role_ref)
        self.assertRaises(
            exception.DomainSpecificRoleNotWithinIdPDomain,
            self._issue_unscoped_token
        )

    def test_roles_in_idp_domain_can_be_assigned_from_mapping(self):
        # Delete the member role and recreate it in the domain of the idp
        PROVIDERS.role_api.delete_role(self.member_role['id'])
        member_role_ref = unit.new_role_ref(
            name='member',
            domain_id=self.idp['domain_id']
        )
        PROVIDERS.role_api.create_role(member_role_ref['id'], member_role_ref)
        response = self._issue_unscoped_token()
        user_id = response.user_id
        unscoped_token = response.id
        response = self.get('/auth/projects', token=unscoped_token)
        projects = response.json_body['projects']
        staging_project = PROVIDERS.resource_api.get_project_by_name(
            'Staging', self.idp['domain_id']
        )
        for project in projects:
            # Even though the mapping successfully assigned the Staging project
            # a member role for our user, the /auth/projects response doesn't
            # include projects with only domain-specific role assignments.
            self.assertNotEqual(project['name'], 'Staging')
        domain_role_assignments = (
            PROVIDERS.assignment_api.list_role_assignments(
                user_id=user_id,
                project_id=staging_project['id'],
                strip_domain_roles=False
            )
        )
        self.assertEqual(
            staging_project['id'], domain_role_assignments[0]['project_id']
        )
        self.assertEqual(
            user_id, domain_role_assignments[0]['user_id']
        )

    def test_mapping_with_groups_includes_projects_with_group_assignment(self):
        # create a group called Observers
        observer_group = unit.new_group_ref(
            domain_id=self.idp['domain_id'],
            name='Observers'
        )
        observer_group = PROVIDERS.identity_api.create_group(observer_group)
        # make sure the Observers group has a role on the finance project
        finance_project = unit.new_project_ref(
            domain_id=self.idp['domain_id'],
            name='Finance'
        )
        finance_project = PROVIDERS.resource_api.create_project(
            finance_project['id'], finance_project
        )
        PROVIDERS.assignment_api.create_grant(
            self.observer_role['id'],
            group_id=observer_group['id'],
            project_id=finance_project['id']
        )
        # update the mapping
        group_rule = {
            'group': {
                'name': 'Observers',
                'domain': {
                    'id': self.idp['domain_id']
                }
            }
        }
        updated_mapping = copy.deepcopy(mapping_fixtures.MAPPING_PROJECTS)
        updated_mapping['rules'][0]['local'].append(group_rule)
        PROVIDERS.federation_api.update_mapping(
            self.mapping['id'], updated_mapping
        )
        response = self._issue_unscoped_token()
        # user_id = response.json_body['token']['user']['id']
        unscoped_token = response.id
        response = self.get('/auth/projects', token=unscoped_token)
        projects = response.json_body['projects']
        self.expected_results = {
            # These assignments are all a result of a direct mapping from the
            # shadow user to the newly created project.
            'Production': 'observer',
            'Staging': 'member',
            'Project for tbo': 'admin',
            # This is a result of the mapping engine maintaining its old
            # behavior.
            'Finance': 'observer'
        }
        for project in projects:
            # Ask for a scope token to each project in the mapping. Each token
            # should contain a different role so let's check that is right,
            # too.
            scope = self._scope_request(
                unscoped_token, 'project', project['id']
            )
            response = self.v3_create_token(scope)
            project_name = response.json_body['token']['project']['name']
            roles = response.json_body['token']['roles']
            self.assertEqual(
                self.expected_results[project_name], roles[0]['name']
            )

    def test_user_gets_only_assigned_roles(self):
        # in bug 1677723 user could get roles outside of what was assigned
        # to them. This test verifies that this is no longer true.
        # Authenticate once to create the projects
        response = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(response)['token'])

        # Assign admin role to newly-created project to another user
        staging_project = PROVIDERS.resource_api.get_project_by_name(
            'Staging', self.idp['domain_id']
        )
        admin = unit.new_user_ref(CONF.identity.default_domain_id)
        PROVIDERS.identity_api.create_user(admin)
        PROVIDERS.assignment_api.create_grant(
            self.role_admin['id'], user_id=admin['id'],
            project_id=staging_project['id']
        )

        # Authenticate again with the federated user and verify roles
        response = self._issue_unscoped_token()
        self.assertValidMappedUser(
            render_token.render_token_response_from_model(response)['token'])
        unscoped_token = response.id
        scope = self._scope_request(
            unscoped_token, 'project', staging_project['id']
        )
        response = self.v3_create_token(scope)
        roles = response.json_body['token']['roles']
        role_ids = [r['id'] for r in roles]
        self.assertNotIn(self.role_admin['id'], role_ids)


class JsonHomeTests(test_v3.RestfulTestCase, test_v3.JsonHomeTestMixin):
    JSON_HOME_DATA = {
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION'
        '/1.0/rel/identity_provider': {
            'href-template': '/OS-FEDERATION/identity_providers/{idp_id}',
            'href-vars': {
                'idp_id': 'https://docs.openstack.org/api/openstack-identity/3'
                '/ext/OS-FEDERATION/1.0/param/idp_id'
            },
        },
    }


def _is_xmlsec1_installed():
    p = subprocess.Popen(
        ['which', 'xmlsec1'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    # invert the return code
    return not bool(p.wait())


def _load_xml(filename):
    with open(os.path.join(XMLDIR, filename), 'r') as xml:
        return xml.read()


class SAMLGenerationTests(test_v3.RestfulTestCase):

    SP_AUTH_URL = ('http://beta.com:5000/v3/OS-FEDERATION/identity_providers'
                   '/BETA/protocols/saml2/auth')

    ASSERTION_FILE = 'signed_saml2_assertion.xml'

    # The values of the following variables match the attributes values found
    # in ASSERTION_FILE
    ISSUER = 'https://acme.com/FIM/sps/openstack/saml20'
    RECIPIENT = 'http://beta.com/Shibboleth.sso/SAML2/POST'
    SUBJECT = 'test_user'
    SUBJECT_DOMAIN = 'user_domain'
    ROLES = ['admin', 'member']
    PROJECT = 'development'
    PROJECT_DOMAIN = 'project_domain'
    GROUPS = ['JSON:{"name":"group1","domain":{"name":"Default"}}',
              'JSON:{"name":"group2","domain":{"name":"Default"}}']
    SAML_GENERATION_ROUTE = '/auth/OS-FEDERATION/saml2'
    ECP_GENERATION_ROUTE = '/auth/OS-FEDERATION/saml2/ecp'
    ASSERTION_VERSION = "2.0"
    SERVICE_PROVDIER_ID = 'ACME'

    def setUp(self):
        super(SAMLGenerationTests, self).setUp()
        self.signed_assertion = saml2.create_class_from_xml_string(
            saml.Assertion, _load_xml(self.ASSERTION_FILE))
        self.sp = core.new_service_provider_ref(
            auth_url=self.SP_AUTH_URL, sp_url=self.RECIPIENT
        )
        url = '/OS-FEDERATION/service_providers/' + self.SERVICE_PROVDIER_ID
        self.put(url, body={'service_provider': self.sp},
                 expected_status=http.client.CREATED)

    def test_samlize_token_values(self):
        """Test the SAML generator produces a SAML object.

        Test the SAML generator directly by passing known arguments, the result
        should be a SAML object that consistently includes attributes based on
        the known arguments that were passed in.

        """
        with mock.patch.object(keystone_idp, '_sign_assertion',
                               return_value=self.signed_assertion):
            generator = keystone_idp.SAMLGenerator()
            response = generator.samlize_token(self.ISSUER, self.RECIPIENT,
                                               self.SUBJECT,
                                               self.SUBJECT_DOMAIN,
                                               self.ROLES, self.PROJECT,
                                               self.PROJECT_DOMAIN,
                                               self.GROUPS)

        assertion = response.assertion
        self.assertIsNotNone(assertion)
        self.assertIsInstance(assertion, saml.Assertion)
        issuer = response.issuer
        self.assertEqual(self.RECIPIENT, response.destination)
        self.assertEqual(self.ISSUER, issuer.text)

        user_attribute = assertion.attribute_statement[0].attribute[0]
        self.assertEqual(self.SUBJECT, user_attribute.attribute_value[0].text)

        user_domain_attribute = (
            assertion.attribute_statement[0].attribute[1])
        self.assertEqual(self.SUBJECT_DOMAIN,
                         user_domain_attribute.attribute_value[0].text)

        role_attribute = assertion.attribute_statement[0].attribute[2]
        for attribute_value in role_attribute.attribute_value:
            self.assertIn(attribute_value.text, self.ROLES)

        project_attribute = assertion.attribute_statement[0].attribute[3]
        self.assertEqual(self.PROJECT,
                         project_attribute.attribute_value[0].text)

        project_domain_attribute = (
            assertion.attribute_statement[0].attribute[4])
        self.assertEqual(self.PROJECT_DOMAIN,
                         project_domain_attribute.attribute_value[0].text)

        group_attribute = assertion.attribute_statement[0].attribute[5]
        for attribute_value in group_attribute.attribute_value:
            self.assertIn(attribute_value.text, self.GROUPS)

    def test_comma_in_certfile_path(self):
        self.config_fixture.config(
            group='saml',
            certfile=CONF.saml.certfile + ',')
        generator = keystone_idp.SAMLGenerator()
        self.assertRaises(
            exception.UnexpectedError,
            generator.samlize_token,
            self.ISSUER,
            self.RECIPIENT,
            self.SUBJECT,
            self.SUBJECT_DOMAIN,
            self.ROLES,
            self.PROJECT,
            self.PROJECT_DOMAIN,
            self.GROUPS)

    def test_comma_in_keyfile_path(self):
        self.config_fixture.config(
            group='saml',
            keyfile=CONF.saml.keyfile + ',')
        generator = keystone_idp.SAMLGenerator()
        self.assertRaises(
            exception.UnexpectedError,
            generator.samlize_token,
            self.ISSUER,
            self.RECIPIENT,
            self.SUBJECT,
            self.SUBJECT_DOMAIN,
            self.ROLES,
            self.PROJECT,
            self.PROJECT_DOMAIN,
            self.GROUPS)

    def test_verify_assertion_object(self):
        """Test that the Assertion object is built properly.

        The Assertion doesn't need to be signed in this test, so
        _sign_assertion method is patched and doesn't alter the assertion.

        """
        with mock.patch.object(keystone_idp, '_sign_assertion',
                               side_effect=lambda x: x):
            generator = keystone_idp.SAMLGenerator()
            response = generator.samlize_token(self.ISSUER, self.RECIPIENT,
                                               self.SUBJECT,
                                               self.SUBJECT_DOMAIN,
                                               self.ROLES, self.PROJECT,
                                               self.PROJECT_DOMAIN,
                                               self.GROUPS)
        assertion = response.assertion
        self.assertEqual(self.ASSERTION_VERSION, assertion.version)

    def test_valid_saml_xml(self):
        """Test the generated SAML object can become valid XML.

        Test the generator directly by passing known arguments, the result
        should be a SAML object that consistently includes attributes based on
        the known arguments that were passed in.

        """
        with mock.patch.object(keystone_idp, '_sign_assertion',
                               return_value=self.signed_assertion):
            generator = keystone_idp.SAMLGenerator()
            response = generator.samlize_token(self.ISSUER, self.RECIPIENT,
                                               self.SUBJECT,
                                               self.SUBJECT_DOMAIN,
                                               self.ROLES, self.PROJECT,
                                               self.PROJECT_DOMAIN,
                                               self.GROUPS)

        saml_str = response.to_string()
        response = etree.fromstring(saml_str)
        issuer = response[0]
        assertion = response[2]

        self.assertEqual(self.RECIPIENT, response.get('Destination'))
        self.assertEqual(self.ISSUER, issuer.text)

        user_attribute = assertion[4][0]
        self.assertEqual(self.SUBJECT, user_attribute[0].text)

        user_domain_attribute = assertion[4][1]
        self.assertEqual(self.SUBJECT_DOMAIN, user_domain_attribute[0].text)

        role_attribute = assertion[4][2]
        for attribute_value in role_attribute:
            self.assertIn(attribute_value.text, self.ROLES)

        project_attribute = assertion[4][3]
        self.assertEqual(self.PROJECT, project_attribute[0].text)

        project_domain_attribute = assertion[4][4]
        self.assertEqual(self.PROJECT_DOMAIN, project_domain_attribute[0].text)

        group_attribute = assertion[4][5]
        for attribute_value in group_attribute:
            self.assertIn(attribute_value.text, self.GROUPS)

    def test_assertion_using_explicit_namespace_prefixes(self):
        def mocked_subprocess_check_output(*popenargs, **kwargs):
            # the last option is the assertion file to be signed
            if popenargs[0] != ['/usr/bin/which', CONF.saml.xmlsec1_binary]:
                filename = popenargs[0][-1]
                with open(filename, 'r') as f:
                    assertion_content = f.read()
                # since we are not testing the signature itself, we can return
                # the assertion as is without signing it
                return assertion_content

        with mock.patch.object(subprocess, 'check_output',
                               side_effect=mocked_subprocess_check_output):
            generator = keystone_idp.SAMLGenerator()
            response = generator.samlize_token(self.ISSUER, self.RECIPIENT,
                                               self.SUBJECT,
                                               self.SUBJECT_DOMAIN,
                                               self.ROLES, self.PROJECT,
                                               self.PROJECT_DOMAIN,
                                               self.GROUPS)
            assertion_xml = response.assertion.to_string()
            # The expected values in the assertions bellow need to be 'str' in
            # Python 2 and 'bytes' in Python 3
            # make sure we have the proper tag and prefix for the assertion
            # namespace
            self.assertIn(b'<saml:Assertion', assertion_xml)
            self.assertIn(
                ('xmlns:saml="' + saml2.NAMESPACE + '"').encode('utf-8'),
                assertion_xml)
            self.assertIn(
                ('xmlns:xmldsig="' + xmldsig.NAMESPACE).encode('utf-8'),
                assertion_xml)

    def test_saml_signing(self):
        """Test that the SAML generator produces a SAML object.

        Test the SAML generator directly by passing known arguments, the result
        should be a SAML object that consistently includes attributes based on
        the known arguments that were passed in.

        """
        if not _is_xmlsec1_installed():
            self.skipTest('xmlsec1 is not installed')

        generator = keystone_idp.SAMLGenerator()
        response = generator.samlize_token(self.ISSUER, self.RECIPIENT,
                                           self.SUBJECT, self.SUBJECT_DOMAIN,
                                           self.ROLES, self.PROJECT,
                                           self.PROJECT_DOMAIN,
                                           self.GROUPS)

        signature = response.assertion.signature
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, xmldsig.Signature)

        idp_public_key = sigver.read_cert_from_file(CONF.saml.certfile, 'pem')
        cert_text = signature.key_info.x509_data[0].x509_certificate.text
        # NOTE(stevemar): Rather than one line of text, the certificate is
        # printed with newlines for readability, we remove these so we can
        # match it with the key that we used.
        cert_text = cert_text.replace(os.linesep, '')
        self.assertEqual(idp_public_key, cert_text)

    def _create_generate_saml_request(self, token_id, sp_id):
        return {
            "auth": {
                "identity": {
                    "methods": [
                        "token"
                    ],
                    "token": {
                        "id": token_id
                    }
                },
                "scope": {
                    "service_provider": {
                        "id": sp_id
                    }
                }
            }
        }

    def _fetch_valid_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        resp = self.v3_create_token(auth_data)
        token_id = resp.headers.get('X-Subject-Token')
        return token_id

    def _fetch_domain_scoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            user_domain_id=self.domain['id'])
        resp = self.v3_create_token(auth_data)
        token_id = resp.headers.get('X-Subject-Token')
        return token_id

    def test_not_project_scoped_token(self):
        """Ensure SAML generation fails when passing domain-scoped tokens.

        The server should return a 403 Forbidden Action.

        """
        self.config_fixture.config(group='saml', idp_entity_id=self.ISSUER)
        token_id = self._fetch_domain_scoped_token()
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        with mock.patch.object(keystone_idp, '_sign_assertion',
                               return_value=self.signed_assertion):
            self.post(self.SAML_GENERATION_ROUTE, body=body,
                      expected_status=http.client.FORBIDDEN)

    def test_generate_saml_route(self):
        """Test that the SAML generation endpoint produces XML.

        The SAML endpoint /v3/auth/OS-FEDERATION/saml2 should take as input,
        a scoped token ID, and a Service Provider ID.
        The controller should fetch details about the user from the token,
        and details about the service provider from its ID.
        This should be enough information to invoke the SAML generator and
        provide a valid SAML (XML) document back.

        """
        self.config_fixture.config(group='saml', idp_entity_id=self.ISSUER)
        token_id = self._fetch_valid_token()
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)

        with mock.patch.object(keystone_idp, '_sign_assertion',
                               return_value=self.signed_assertion):
            http_response = self.post(self.SAML_GENERATION_ROUTE, body=body,
                                      response_content_type='text/xml',
                                      expected_status=http.client.OK)

        response = etree.fromstring(http_response.result)
        issuer = response[0]
        assertion = response[2]

        self.assertEqual(self.RECIPIENT, response.get('Destination'))
        self.assertEqual(self.ISSUER, issuer.text)

        # NOTE(stevemar): We should test this against expected values,
        # but the self.xyz attribute names are uuids, and we mock out
        # the result. Ideally we should update the mocked result with
        # some known data, and create the roles/project/user before
        # these tests run.
        user_attribute = assertion[4][0]
        self.assertIsInstance(user_attribute[0].text, str)

        user_domain_attribute = assertion[4][1]
        self.assertIsInstance(user_domain_attribute[0].text, str)

        role_attribute = assertion[4][2]
        self.assertIsInstance(role_attribute[0].text, str)

        project_attribute = assertion[4][3]
        self.assertIsInstance(project_attribute[0].text, str)

        project_domain_attribute = assertion[4][4]
        self.assertIsInstance(project_domain_attribute[0].text, str)

        group_attribute = assertion[4][5]
        self.assertIsInstance(group_attribute[0].text, str)

    def test_invalid_scope_body(self):
        """Test that missing the scope in request body raises an exception.

        Raises exception.SchemaValidationError() - error 400 Bad Request

        """
        token_id = uuid.uuid4().hex
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        del body['auth']['scope']

        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http.client.BAD_REQUEST)

    def test_invalid_token_body(self):
        """Test that missing the token in request body raises an exception.

        Raises exception.SchemaValidationError() - error 400 Bad Request

        """
        token_id = uuid.uuid4().hex
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        del body['auth']['identity']['token']

        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http.client.BAD_REQUEST)

    def test_sp_not_found(self):
        """Test SAML generation with an invalid service provider ID.

        Raises exception.ServiceProviderNotFound() - error Not Found 404

        """
        sp_id = uuid.uuid4().hex
        token_id = self._fetch_valid_token()
        body = self._create_generate_saml_request(token_id, sp_id)
        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http.client.NOT_FOUND)

    def test_sp_disabled(self):
        """Try generating assertion for disabled Service Provider."""
        # Disable Service Provider
        sp_ref = {'enabled': False}
        PROVIDERS.federation_api.update_sp(self.SERVICE_PROVDIER_ID, sp_ref)

        token_id = self._fetch_valid_token()
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http.client.FORBIDDEN)

    def test_token_not_found(self):
        """Test that an invalid token in the request body raises an exception.

        Raises exception.TokenNotFound() - error Not Found 404

        """
        token_id = uuid.uuid4().hex
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http.client.NOT_FOUND)

    def test_generate_ecp_route(self):
        """Test that the ECP generation endpoint produces XML.

        The ECP endpoint /v3/auth/OS-FEDERATION/saml2/ecp should take the same
        input as the SAML generation endpoint (scoped token ID + Service
        Provider ID).
        The controller should return a SAML assertion that is wrapped in a
        SOAP envelope.
        """
        self.config_fixture.config(group='saml', idp_entity_id=self.ISSUER)
        token_id = self._fetch_valid_token()
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)

        with mock.patch.object(keystone_idp, '_sign_assertion',
                               return_value=self.signed_assertion):
            http_response = self.post(self.ECP_GENERATION_ROUTE, body=body,
                                      response_content_type='text/xml',
                                      expected_status=http.client.OK)

        env_response = etree.fromstring(http_response.result)
        header = env_response[0]

        # Verify the relay state starts with 'ss:mem'
        prefix = CONF.saml.relay_state_prefix
        self.assertThat(header[0].text, matchers.StartsWith(prefix))

        # Verify that the content in the body matches the expected assertion
        body = env_response[1]
        response = body[0]
        issuer = response[0]
        assertion = response[2]

        self.assertEqual(self.RECIPIENT, response.get('Destination'))
        self.assertEqual(self.ISSUER, issuer.text)

        user_attribute = assertion[4][0]
        self.assertIsInstance(user_attribute[0].text, str)

        user_domain_attribute = assertion[4][1]
        self.assertIsInstance(user_domain_attribute[0].text, str)

        role_attribute = assertion[4][2]
        self.assertIsInstance(role_attribute[0].text, str)

        project_attribute = assertion[4][3]
        self.assertIsInstance(project_attribute[0].text, str)

        project_domain_attribute = assertion[4][4]
        self.assertIsInstance(project_domain_attribute[0].text, str)

        group_attribute = assertion[4][5]
        self.assertIsInstance(group_attribute[0].text, str)

    @mock.patch('saml2.create_class_from_xml_string')
    @mock.patch('oslo_utils.fileutils.write_to_tempfile')
    @mock.patch.object(subprocess, 'check_output')
    def test_sign_assertion(self, check_output_mock,
                            write_to_tempfile_mock, create_class_mock):
        write_to_tempfile_mock.return_value = 'tmp_path'
        check_output_mock.return_value = 'fakeoutput'

        keystone_idp._sign_assertion(self.signed_assertion)

        create_class_mock.assert_called_with(saml.Assertion, 'fakeoutput')

    @mock.patch('oslo_utils.fileutils.write_to_tempfile')
    def test_sign_assertion_exc(self, write_to_tempfile_mock):
        # If the command fails the command output is logged.
        sample_returncode = 1
        sample_output = self.getUniqueString()
        write_to_tempfile_mock.return_value = 'tmp_path'

        def side_effect(*args, **kwargs):
            if args[0] == ['/usr/bin/which', CONF.saml.xmlsec1_binary]:
                return '/usr/bin/xmlsec1\n'
            else:
                raise subprocess.CalledProcessError(
                    returncode=sample_returncode, cmd=CONF.saml.xmlsec1_binary,
                    output=sample_output
                )

        with mock.patch.object(subprocess, 'check_output',
                               side_effect=side_effect):
            logger_fixture = self.useFixture(fixtures.LoggerFixture())
            self.assertRaises(
                exception.SAMLSigningError,
                keystone_idp._sign_assertion,
                self.signed_assertion
            )

            # The function __str__ in subprocess.CalledProcessError is
            # different between py3.6 and lower python version.
            expected_log = (
                r"Error when signing assertion, reason: Command '%s' returned "
                r"non-zero exit status %s\.? %s\n" %
                (CONF.saml.xmlsec1_binary, sample_returncode, sample_output))
            self.assertRegex(logger_fixture.output,
                             re.compile(r'%s' % expected_log))

    @mock.patch('oslo_utils.fileutils.write_to_tempfile')
    @mock.patch.object(subprocess, 'check_output')
    def test_sign_assertion_fileutils_exc(self, check_output_mock,
                                          write_to_tempfile_mock):
        exception_msg = 'fake'
        write_to_tempfile_mock.side_effect = Exception(exception_msg)
        check_output_mock.return_value = '/usr/bin/xmlsec1'

        logger_fixture = self.useFixture(fixtures.LoggerFixture())
        self.assertRaises(exception.SAMLSigningError,
                          keystone_idp._sign_assertion,
                          self.signed_assertion)
        expected_log = (
            'Error when signing assertion, reason: %s\n' % exception_msg)
        self.assertEqual(expected_log, logger_fixture.output)

    def test_sign_assertion_logs_message_if_xmlsec1_is_not_installed(self):
        with mock.patch.object(subprocess, 'check_output') as co_mock:
            co_mock.side_effect = subprocess.CalledProcessError(
                returncode=1, cmd=CONF.saml.xmlsec1_binary,
            )
            logger_fixture = self.useFixture(fixtures.LoggerFixture())
            self.assertRaises(
                exception.SAMLSigningError,
                keystone_idp._sign_assertion,
                self.signed_assertion
            )

            expected_log = ('Unable to locate xmlsec1 binary on the system. '
                            'Check to make sure it is installed.\n')
            self.assertEqual(expected_log, logger_fixture.output)


class IdPMetadataGenerationTests(test_v3.RestfulTestCase):
    """A class for testing Identity Provider Metadata generation."""

    METADATA_URL = '/OS-FEDERATION/saml2/metadata'

    def setUp(self):
        super(IdPMetadataGenerationTests, self).setUp()
        self.generator = keystone_idp.MetadataGenerator()

    def config_overrides(self):
        super(IdPMetadataGenerationTests, self).config_overrides()
        self.config_fixture.config(
            group='saml',
            idp_entity_id=federation_fixtures.IDP_ENTITY_ID,
            idp_sso_endpoint=federation_fixtures.IDP_SSO_ENDPOINT,
            idp_organization_name=federation_fixtures.IDP_ORGANIZATION_NAME,
            idp_organization_display_name=(
                federation_fixtures.IDP_ORGANIZATION_DISPLAY_NAME),
            idp_organization_url=federation_fixtures.IDP_ORGANIZATION_URL,
            idp_contact_company=federation_fixtures.IDP_CONTACT_COMPANY,
            idp_contact_name=federation_fixtures.IDP_CONTACT_GIVEN_NAME,
            idp_contact_surname=federation_fixtures.IDP_CONTACT_SURNAME,
            idp_contact_email=federation_fixtures.IDP_CONTACT_EMAIL,
            idp_contact_telephone=(
                federation_fixtures.IDP_CONTACT_TELEPHONE_NUMBER),
            idp_contact_type=federation_fixtures.IDP_CONTACT_TYPE)

    def test_check_entity_id(self):
        metadata = self.generator.generate_metadata()
        self.assertEqual(federation_fixtures.IDP_ENTITY_ID, metadata.entity_id)

    def test_metadata_validity(self):
        """Call md.EntityDescriptor method that does internal verification."""
        self.generator.generate_metadata().verify()

    def test_serialize_metadata_object(self):
        """Check whether serialization doesn't raise any exceptions."""
        self.generator.generate_metadata().to_string()
        # TODO(marek-denis): Check values here

    def test_check_idp_sso(self):
        metadata = self.generator.generate_metadata()
        idpsso_descriptor = metadata.idpsso_descriptor
        self.assertIsNotNone(metadata.idpsso_descriptor)
        self.assertEqual(federation_fixtures.IDP_SSO_ENDPOINT,
                         idpsso_descriptor.single_sign_on_service.location)

        self.assertIsNotNone(idpsso_descriptor.organization)
        organization = idpsso_descriptor.organization
        self.assertEqual(federation_fixtures.IDP_ORGANIZATION_DISPLAY_NAME,
                         organization.organization_display_name.text)
        self.assertEqual(federation_fixtures.IDP_ORGANIZATION_NAME,
                         organization.organization_name.text)
        self.assertEqual(federation_fixtures.IDP_ORGANIZATION_URL,
                         organization.organization_url.text)

        self.assertIsNotNone(idpsso_descriptor.contact_person)
        contact_person = idpsso_descriptor.contact_person

        self.assertEqual(federation_fixtures.IDP_CONTACT_GIVEN_NAME,
                         contact_person.given_name.text)
        self.assertEqual(federation_fixtures.IDP_CONTACT_SURNAME,
                         contact_person.sur_name.text)
        self.assertEqual(federation_fixtures.IDP_CONTACT_EMAIL,
                         contact_person.email_address.text)
        self.assertEqual(federation_fixtures.IDP_CONTACT_TELEPHONE_NUMBER,
                         contact_person.telephone_number.text)
        self.assertEqual(federation_fixtures.IDP_CONTACT_TYPE,
                         contact_person.contact_type)

    def test_metadata_no_organization(self):
        self.config_fixture.config(
            group='saml',
            idp_organization_display_name=None,
            idp_organization_url=None,
            idp_organization_name=None)
        metadata = self.generator.generate_metadata()
        idpsso_descriptor = metadata.idpsso_descriptor
        self.assertIsNotNone(metadata.idpsso_descriptor)
        self.assertIsNone(idpsso_descriptor.organization)
        self.assertIsNotNone(idpsso_descriptor.contact_person)

    def test_metadata_no_contact_person(self):
        self.config_fixture.config(
            group='saml',
            idp_contact_name=None,
            idp_contact_surname=None,
            idp_contact_email=None,
            idp_contact_telephone=None)
        metadata = self.generator.generate_metadata()
        idpsso_descriptor = metadata.idpsso_descriptor
        self.assertIsNotNone(metadata.idpsso_descriptor)
        self.assertIsNotNone(idpsso_descriptor.organization)
        self.assertEqual([], idpsso_descriptor.contact_person)

    def test_metadata_invalid_idp_sso_endpoint(self):
        self.config_fixture.config(
            group='saml',
            idp_sso_endpoint=None)
        self.assertRaises(exception.ValidationError,
                          self.generator.generate_metadata)

    def test_metadata_invalid_idp_entity_id(self):
        self.config_fixture.config(
            group='saml',
            idp_entity_id=None)
        self.assertRaises(exception.ValidationError,
                          self.generator.generate_metadata)

    def test_get_metadata_with_no_metadata_file_configured(self):
        self.get(self.METADATA_URL,
                 expected_status=http.client.INTERNAL_SERVER_ERROR)

    def test_get_head_metadata(self):
        self.config_fixture.config(
            group='saml', idp_metadata_path=XMLDIR + '/idp_saml2_metadata.xml')
        self.head(self.METADATA_URL, expected_status=http.client.OK)
        r = self.get(self.METADATA_URL, response_content_type='text/xml')
        self.assertEqual('text/xml', r.headers.get('Content-Type'))

        reference_file = _load_xml('idp_saml2_metadata.xml')

        # `reference_file` needs to be converted to bytes to be able to be
        # compared to `r.result` in the case of Python 3.
        reference_file = str.encode(reference_file)
        self.assertEqual(reference_file, r.result)


class ServiceProviderTests(test_v3.RestfulTestCase):
    """A test class for Service Providers."""

    MEMBER_NAME = 'service_provider'
    COLLECTION_NAME = 'service_providers'
    SERVICE_PROVIDER_ID = 'ACME'
    SP_KEYS = ['auth_url', 'id', 'enabled', 'description',
               'relay_state_prefix', 'sp_url']

    def setUp(self):
        super(ServiceProviderTests, self).setUp()
        # Add a Service Provider
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.SP_REF = core.new_service_provider_ref()
        self.SERVICE_PROVIDER = self.put(
            url, body={'service_provider': self.SP_REF},
            expected_status=http.client.CREATED).result

    def base_url(self, suffix=None):
        if suffix is not None:
            return '/OS-FEDERATION/service_providers/' + str(suffix)
        return '/OS-FEDERATION/service_providers'

    def _create_default_sp(self, body=None):
        """Create default Service Provider."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        if body is None:
            body = core.new_service_provider_ref()
        resp = self.put(url, body={'service_provider': body},
                        expected_status=http.client.CREATED)
        return resp

    def test_get_head_service_provider(self):
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        resp = self.get(url)
        self.assertValidEntity(resp.result['service_provider'],
                               keys_to_check=self.SP_KEYS)
        resp = self.head(url, expected_status=http.client.OK)

    def test_get_service_provider_fail(self):
        url = self.base_url(suffix=uuid.uuid4().hex)
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_create_service_provider(self):
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = core.new_service_provider_ref()
        resp = self.put(url, body={'service_provider': sp},
                        expected_status=http.client.CREATED)
        self.assertValidEntity(resp.result['service_provider'],
                               keys_to_check=self.SP_KEYS)

    @unit.skip_if_cache_disabled('federation')
    def test_create_service_provider_invalidates_cache(self):
        # List all service providers and make sure we only have one in the
        # list. This service provider is from testing setup.
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(1)
        )

        # Create a new service provider.
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = core.new_service_provider_ref()
        self.put(url, body={'service_provider': sp},
                 expected_status=http.client.CREATED)

        # List all service providers again and make sure we have two in the
        # returned list.
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(2)
        )

    @unit.skip_if_cache_disabled('federation')
    def test_delete_service_provider_invalidates_cache(self):
        # List all service providers and make sure we only have one in the
        # list. This service provider is from testing setup.
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(1)
        )

        # Create a new service provider.
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = core.new_service_provider_ref()
        self.put(url, body={'service_provider': sp},
                 expected_status=http.client.CREATED)

        # List all service providers again and make sure we have two in the
        # returned list.
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(2)
        )

        # Delete the service provider we created, which should invalidate the
        # service provider cache. Get the list of service providers again and
        # if the cache invalidated properly then we should only have one
        # service provider in the list.
        self.delete(url, expected_status=http.client.NO_CONTENT)
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(1)
        )

    @unit.skip_if_cache_disabled('federation')
    def test_update_service_provider_invalidates_cache(self):
        # List all service providers and make sure we only have one in the
        # list. This service provider is from testing setup.
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(1)
        )

        # Create a new service provider.
        service_provider_id = uuid.uuid4().hex
        url = self.base_url(suffix=service_provider_id)
        sp = core.new_service_provider_ref()
        self.put(url, body={'service_provider': sp},
                 expected_status=http.client.CREATED)

        # List all service providers again and make sure we have two in the
        # returned list.
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(2)
        )

        # Update the service provider we created, which should invalidate the
        # service provider cache. Get the list of service providers again and
        # if the cache invalidated properly then we see the value we updated.
        updated_description = uuid.uuid4().hex
        body = {'service_provider': {'description': updated_description}}
        self.patch(url, body=body, expected_status=http.client.OK)
        resp = self.get(self.base_url(), expected_status=http.client.OK)
        self.assertThat(
            resp.json_body['service_providers'],
            matchers.HasLength(2)
        )
        for sp in resp.json_body['service_providers']:
            if sp['id'] == service_provider_id:
                self.assertEqual(sp['description'], updated_description)

    def test_create_sp_relay_state_default(self):
        """Create an SP without relay state, should default to `ss:mem`."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = core.new_service_provider_ref()
        del sp['relay_state_prefix']
        resp = self.put(url, body={'service_provider': sp},
                        expected_status=http.client.CREATED)
        sp_result = resp.result['service_provider']
        self.assertEqual(CONF.saml.relay_state_prefix,
                         sp_result['relay_state_prefix'])

    def test_create_sp_relay_state_non_default(self):
        """Create an SP with custom relay state."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = core.new_service_provider_ref()
        non_default_prefix = uuid.uuid4().hex
        sp['relay_state_prefix'] = non_default_prefix
        resp = self.put(url, body={'service_provider': sp},
                        expected_status=http.client.CREATED)
        sp_result = resp.result['service_provider']
        self.assertEqual(non_default_prefix,
                         sp_result['relay_state_prefix'])

    def test_create_service_provider_fail(self):
        """Try adding SP object with unallowed attribute."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = core.new_service_provider_ref()
        sp[uuid.uuid4().hex] = uuid.uuid4().hex
        self.put(url, body={'service_provider': sp},
                 expected_status=http.client.BAD_REQUEST)

    def test_list_head_service_providers(self):
        """Test listing of service provider objects.

        Add two new service providers. List all available service providers.
        Expect to get list of three service providers (one created by setUp())
        Test if attributes match.

        """
        ref_service_providers = {
            uuid.uuid4().hex: core.new_service_provider_ref(),
            uuid.uuid4().hex: core.new_service_provider_ref(),
        }
        for id, sp in ref_service_providers.items():
            url = self.base_url(suffix=id)
            self.put(url, body={'service_provider': sp},
                     expected_status=http.client.CREATED)

        # Insert ids into service provider object, we will compare it with
        # responses from server and those include 'id' attribute.

        ref_service_providers[self.SERVICE_PROVIDER_ID] = self.SP_REF
        for id, sp in ref_service_providers.items():
            sp['id'] = id

        url = self.base_url()
        resp = self.get(url)
        service_providers = resp.result
        for service_provider in service_providers['service_providers']:
            id = service_provider['id']
            self.assertValidEntity(
                service_provider, ref=ref_service_providers[id],
                keys_to_check=self.SP_KEYS)

        self.head(url, expected_status=http.client.OK)

    def test_update_service_provider(self):
        """Update existing service provider.

        Update default existing service provider and make sure it has been
        properly changed.

        """
        new_sp_ref = core.new_service_provider_ref()
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        resp = self.patch(url, body={'service_provider': new_sp_ref})
        patch_result = resp.result
        new_sp_ref['id'] = self.SERVICE_PROVIDER_ID
        self.assertValidEntity(patch_result['service_provider'],
                               ref=new_sp_ref,
                               keys_to_check=self.SP_KEYS)

        resp = self.get(url)
        get_result = resp.result

        self.assertDictEqual(patch_result['service_provider'],
                             get_result['service_provider'])

    def test_update_service_provider_immutable_parameters(self):
        """Update immutable attributes in service provider.

        In this particular case the test will try to change ``id`` attribute.
        The server should return an HTTP 403 Forbidden error code.

        """
        new_sp_ref = {'id': uuid.uuid4().hex}
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.patch(url, body={'service_provider': new_sp_ref},
                   expected_status=http.client.BAD_REQUEST)

    def test_update_service_provider_unknown_parameter(self):
        new_sp_ref = core.new_service_provider_ref()
        new_sp_ref[uuid.uuid4().hex] = uuid.uuid4().hex
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.patch(url, body={'service_provider': new_sp_ref},
                   expected_status=http.client.BAD_REQUEST)

    def test_update_service_provider_returns_not_found(self):
        new_sp_ref = core.new_service_provider_ref()
        new_sp_ref['description'] = uuid.uuid4().hex
        url = self.base_url(suffix=uuid.uuid4().hex)
        self.patch(url, body={'service_provider': new_sp_ref},
                   expected_status=http.client.NOT_FOUND)

    def test_update_sp_relay_state(self):
        """Update an SP with custom relay state."""
        new_sp_ref = core.new_service_provider_ref()
        non_default_prefix = uuid.uuid4().hex
        new_sp_ref['relay_state_prefix'] = non_default_prefix
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        resp = self.patch(url, body={'service_provider': new_sp_ref})
        sp_result = resp.result['service_provider']
        self.assertEqual(non_default_prefix,
                         sp_result['relay_state_prefix'])

    def test_delete_service_provider(self):
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.delete(url)

    def test_delete_service_provider_returns_not_found(self):
        url = self.base_url(suffix=uuid.uuid4().hex)
        self.delete(url, expected_status=http.client.NOT_FOUND)

    def test_filter_list_sp_by_id(self):
        def get_id(resp):
            sp = resp.result.get('service_provider')
            return sp.get('id')

        sp1_id = get_id(self._create_default_sp())
        sp2_id = get_id(self._create_default_sp())

        # list the SP, should get SPs.
        url = self.base_url()
        resp = self.get(url)
        sps = resp.result.get('service_providers')
        entities_ids = [e['id'] for e in sps]
        self.assertIn(sp1_id, entities_ids)
        self.assertIn(sp2_id, entities_ids)

        # filter the SP by 'id'. Only SP1 should appear.
        url = self.base_url() + '?id=' + sp1_id
        resp = self.get(url)
        sps = resp.result.get('service_providers')
        entities_ids = [e['id'] for e in sps]
        self.assertIn(sp1_id, entities_ids)
        self.assertNotIn(sp2_id, entities_ids)

    def test_filter_list_sp_by_enabled(self):
        def get_id(resp):
            sp = resp.result.get('service_provider')
            return sp.get('id')

        sp1_id = get_id(self._create_default_sp())
        sp2_ref = core.new_service_provider_ref()
        sp2_ref['enabled'] = False
        sp2_id = get_id(self._create_default_sp(body=sp2_ref))

        # list the SP, should get two SPs.
        url = self.base_url()
        resp = self.get(url)
        sps = resp.result.get('service_providers')
        entities_ids = [e['id'] for e in sps]
        self.assertIn(sp1_id, entities_ids)
        self.assertIn(sp2_id, entities_ids)

        # filter the SP by 'enabled'. Only SP1 should appear.
        url = self.base_url() + '?enabled=True'
        resp = self.get(url)
        sps = resp.result.get('service_providers')
        entities_ids = [e['id'] for e in sps]
        self.assertIn(sp1_id, entities_ids)
        self.assertNotIn(sp2_id, entities_ids)


class WebSSOTests(FederatedTokenTests):
    """A class for testing Web SSO."""

    SSO_URL = '/auth/OS-FEDERATION/websso/'
    SSO_TEMPLATE_NAME = 'sso_callback_template.html'
    SSO_TEMPLATE_PATH = os.path.join(core.dirs.etc(), SSO_TEMPLATE_NAME)
    TRUSTED_DASHBOARD = 'http://horizon.com'
    ORIGIN = urllib.parse.quote_plus(TRUSTED_DASHBOARD)
    PROTOCOL_REMOTE_ID_ATTR = uuid.uuid4().hex

    def config_overrides(self):
        super(WebSSOTests, self).config_overrides()
        self.config_fixture.config(
            group='federation',
            trusted_dashboard=[self.TRUSTED_DASHBOARD],
            sso_callback_template=self.SSO_TEMPLATE_PATH,
            remote_id_attribute=self.REMOTE_ID_ATTR)

    def test_render_callback_template(self):
        token_id = uuid.uuid4().hex
        with self.make_request():
            resp = (
                auth_api._AuthFederationWebSSOBase._render_template_response(
                    self.TRUSTED_DASHBOARD, token_id))
        # The expected value in the assertions bellow need to be 'str' in
        # Python 2 and 'bytes' in Python 3
        self.assertIn(token_id.encode('utf-8'), resp.data)
        self.assertIn(self.TRUSTED_DASHBOARD.encode('utf-8'), resp.data)

    def test_federated_sso_auth(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0],
                       'QUERY_STRING': 'origin=%s' % self.ORIGIN}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            resp = auth_api.AuthFederationWebSSOResource._perform_auth(
                self.PROTOCOL)
        # `resp.data` will be `str` in Python 2 and `bytes` in Python 3
        # which is why expected value: `self.TRUSTED_DASHBOARD`
        # needs to be encoded
        self.assertIn(self.TRUSTED_DASHBOARD.encode('utf-8'), resp.data)

    def test_get_sso_origin_host_case_insensitive(self):
        # test lowercase hostname in trusted_dashboard
        environ = {'QUERY_STRING': 'origin=http://horizon.com'}
        with self.make_request(environ=environ):
            host = auth_api._get_sso_origin_host()
            self.assertEqual("http://horizon.com", host)
            # test uppercase hostname in trusted_dashboard
            self.config_fixture.config(
                group='federation',
                trusted_dashboard=['http://Horizon.com'])
            host = auth_api._get_sso_origin_host()
            self.assertEqual("http://horizon.com", host)

    def test_federated_sso_auth_with_protocol_specific_remote_id(self):
        self.config_fixture.config(
            group=self.PROTOCOL,
            remote_id_attribute=self.PROTOCOL_REMOTE_ID_ATTR)

        environment = {self.PROTOCOL_REMOTE_ID_ATTR: self.REMOTE_IDS[0],
                       'QUERY_STRING': 'origin=%s' % self.ORIGIN}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            resp = auth_api.AuthFederationWebSSOResource._perform_auth(
                self.PROTOCOL)
        # `resp.data` will be `str` in Python 2 and `bytes` in Python 3
        # which is why expected value: `self.TRUSTED_DASHBOARD`
        # needs to be encoded
        self.assertIn(self.TRUSTED_DASHBOARD.encode('utf-8'), resp.data)

    def test_federated_sso_auth_bad_remote_id(self):
        environment = {self.REMOTE_ID_ATTR: self.IDP,
                       'QUERY_STRING': 'origin=%s' % self.ORIGIN}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            self.assertRaises(
                exception.IdentityProviderNotFound,
                auth_api.AuthFederationWebSSOResource._perform_auth,
                self.PROTOCOL)

    def test_federated_sso_missing_query(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0]}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            self.assertRaises(
                exception.ValidationError,
                auth_api.AuthFederationWebSSOResource._perform_auth,
                self.PROTOCOL)

    def test_federated_sso_missing_query_bad_remote_id(self):
        environment = {self.REMOTE_ID_ATTR: self.IDP}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            self.assertRaises(
                exception.ValidationError,
                auth_api.AuthFederationWebSSOResource._perform_auth,
                self.PROTOCOL)

    def test_federated_sso_auth_protocol_not_found(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0],
                       'QUERY_STRING': 'origin=%s' % self.ORIGIN}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            self.assertRaises(
                exception.Unauthorized,
                auth_api.AuthFederationWebSSOResource._perform_auth,
                'no_this_protocol')

    def test_federated_sso_untrusted_dashboard(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0],
                       'QUERY_STRING': 'origin=%s' % uuid.uuid4().hex}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            self.assertRaises(
                exception.Unauthorized,
                auth_api.AuthFederationWebSSOResource._perform_auth,
                self.PROTOCOL)

    def test_federated_sso_untrusted_dashboard_bad_remote_id(self):
        environment = {self.REMOTE_ID_ATTR: self.IDP,
                       'QUERY_STRING': 'origin=%s' % uuid.uuid4().hex}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            self.assertRaises(
                exception.Unauthorized,
                auth_api.AuthFederationWebSSOResource._perform_auth,
                self.PROTOCOL)

    def test_federated_sso_missing_remote_id(self):
        environment = copy.deepcopy(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment,
                               query_string='origin=%s' % self.ORIGIN):
            self.assertRaises(
                exception.Unauthorized,
                auth_api.AuthFederationWebSSOResource._perform_auth,
                self.PROTOCOL)

    def test_identity_provider_specific_federated_authentication(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0]}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment,
                               query_string='origin=%s' % self.ORIGIN):
            resp = auth_api.AuthFederationWebSSOIDPsResource._perform_auth(
                self.idp['id'], self.PROTOCOL)
        # `resp.data` will be `str` in Python 2 and `bytes` in Python 3
        # which is why the expected value: `self.TRUSTED_DASHBOARD`
        # needs to be encoded
        self.assertIn(self.TRUSTED_DASHBOARD.encode('utf-8'), resp.data)

    def test_issue_unscoped_token_with_remote_from_protocol(self):
        self.config_fixture.config(
            group='federation', remote_id_attribute=None
        )
        self.config_fixture.config(
            group=self.PROTOCOL, remote_id_attribute=None
        )
        protocol = PROVIDERS.federation_api.get_protocol(
            self.IDP_WITH_REMOTE, self.PROTOCOL
        )
        protocol['remote_id_attribute'] = self.PROTOCOL_REMOTE_ID_ATTR
        PROVIDERS.federation_api.update_protocol(
            self.IDP_WITH_REMOTE, protocol['id'], protocol
        )
        environment = {self.PROTOCOL_REMOTE_ID_ATTR: self.REMOTE_IDS[0],
                       'QUERY_STRING': 'origin=%s' % self.ORIGIN}
        environment.update(mapping_fixtures.EMPLOYEE_ASSERTION)
        with self.make_request(environ=environment):
            resp = auth_api.AuthFederationWebSSOResource._perform_auth(
                self.PROTOCOL)
        self.assertIn(self.TRUSTED_DASHBOARD.encode('utf-8'), resp.data)


class K2KServiceCatalogTests(test_v3.RestfulTestCase):
    SP1 = 'SP1'
    SP2 = 'SP2'
    SP3 = 'SP3'

    def setUp(self):
        super(K2KServiceCatalogTests, self).setUp()

        sp = core.new_service_provider_ref()
        PROVIDERS.federation_api.create_sp(self.SP1, sp)
        self.sp_alpha = {self.SP1: sp}

        sp = core.new_service_provider_ref()
        PROVIDERS.federation_api.create_sp(self.SP2, sp)
        self.sp_beta = {self.SP2: sp}

        sp = core.new_service_provider_ref()
        PROVIDERS.federation_api.create_sp(self.SP3, sp)
        self.sp_gamma = {self.SP3: sp}

    def sp_response(self, id, ref):
        ref.pop('enabled')
        ref.pop('description')
        ref.pop('relay_state_prefix')
        ref['id'] = id
        return ref

    def _validate_service_providers(self, token, ref):
        token_data = token['token']
        self.assertIn('service_providers', token_data)
        self.assertIsNotNone(token_data['service_providers'])
        service_providers = token_data.get('service_providers')

        self.assertEqual(len(ref), len(service_providers))
        for entity in service_providers:
            id = entity.get('id')
            ref_entity = self.sp_response(id, ref.get(id))
            self.assertDictEqual(entity, ref_entity)

    def test_service_providers_in_token(self):
        """Check if service providers are listed in service catalog."""
        model = token_model.TokenModel()
        model.user_id = self.user_id
        model.methods = ['password']
        token = render_token.render_token_response_from_model(model)
        ref = {}
        for r in (self.sp_alpha, self.sp_beta, self.sp_gamma):
            ref.update(r)
        self._validate_service_providers(token, ref)

    def test_service_provides_in_token_disabled_sp(self):
        """Test behaviour with disabled service providers.

        Disabled service providers should not be listed in the service
        catalog.

        """
        # disable service provider ALPHA
        sp_ref = {'enabled': False}
        PROVIDERS.federation_api.update_sp(self.SP1, sp_ref)

        model = token_model.TokenModel()
        model.user_id = self.user_id
        model.methods = ['password']
        token = render_token.render_token_response_from_model(model)
        ref = {}
        for r in (self.sp_beta, self.sp_gamma):
            ref.update(r)
        self._validate_service_providers(token, ref)

    def test_no_service_providers_in_token(self):
        """Test service catalog with disabled service providers.

        There should be no entry ``service_providers`` in the catalog.
        Test passes providing no attribute was raised.

        """
        sp_ref = {'enabled': False}
        for sp in (self.SP1, self.SP2, self.SP3):
            PROVIDERS.federation_api.update_sp(sp, sp_ref)

        model = token_model.TokenModel()
        model.user_id = self.user_id
        model.methods = ['password']
        token = render_token.render_token_response_from_model(model)
        self.assertNotIn('service_providers', token['token'],
                         message=('Expected Service Catalog not to have '
                                  'service_providers'))
