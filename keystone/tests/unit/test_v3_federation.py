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

import os
import random
from testtools import matchers
import uuid

import fixtures
from lxml import etree
import mock
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslotest import mockpatch
import saml2
from saml2 import saml
from saml2 import sigver
from six.moves import http_client
from six.moves import range, urllib, zip
xmldsig = importutils.try_import("saml2.xmldsig")
if not xmldsig:
    xmldsig = importutils.try_import("xmldsig")

from keystone.auth import controllers as auth_controllers
from keystone.common import environment
from keystone.contrib.federation import controllers as federation_controllers
from keystone.contrib.federation import idp as keystone_idp
from keystone import exception
from keystone import notifications
from keystone.tests.unit import core
from keystone.tests.unit import federation_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import mapping_fixtures
from keystone.tests.unit import test_v3
from keystone.token.providers import common as token_common


subprocess = environment.subprocess

CONF = cfg.CONF
LOG = log.getLogger(__name__)
ROOTDIR = os.path.dirname(os.path.abspath(__file__))
XMLDIR = os.path.join(ROOTDIR, 'saml2/')


def dummy_validator(*args, **kwargs):
    pass


class FederationTests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'federation'
    EXTENSION_TO_ADD = 'federation_extension'


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
        self.assertEqual('Federated', token['user']['domain']['id'])
        self.assertEqual('Federated', token['user']['domain']['name'])

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

        # Make sure user_id is url safe
        self.assertEqual(urllib.parse.quote(user['name']), user['id'])

    def _issue_unscoped_token(self,
                              idp=None,
                              assertion='EMPLOYEE_ASSERTION',
                              environment=None):
        api = federation_controllers.Auth()
        context = {'environment': environment or {}}
        self._inject_assertion(context, assertion)
        if idp is None:
            idp = self.IDP
        r = api.federated_authentication(context, idp, self.PROTOCOL)
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
                        self.AUTH_METHOD
                    ],
                    self.AUTH_METHOD: {
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

    def _inject_assertion(self, context, variant, query_string=None):
        assertion = getattr(mapping_fixtures, variant)
        context['environment'].update(assertion)
        context['query_string'] = query_string or []

    def load_federation_sample_data(self):
        """Inject additional data."""

        # Create and add domains
        self.domainA = self.new_domain_ref()
        self.resource_api.create_domain(self.domainA['id'],
                                        self.domainA)

        self.domainB = self.new_domain_ref()
        self.resource_api.create_domain(self.domainB['id'],
                                        self.domainB)

        self.domainC = self.new_domain_ref()
        self.resource_api.create_domain(self.domainC['id'],
                                        self.domainC)

        self.domainD = self.new_domain_ref()
        self.resource_api.create_domain(self.domainD['id'],
                                        self.domainD)

        # Create and add projects
        self.proj_employees = self.new_project_ref(
            domain_id=self.domainA['id'])
        self.resource_api.create_project(self.proj_employees['id'],
                                         self.proj_employees)
        self.proj_customers = self.new_project_ref(
            domain_id=self.domainA['id'])
        self.resource_api.create_project(self.proj_customers['id'],
                                         self.proj_customers)

        self.project_all = self.new_project_ref(
            domain_id=self.domainA['id'])
        self.resource_api.create_project(self.project_all['id'],
                                         self.project_all)

        self.project_inherited = self.new_project_ref(
            domain_id=self.domainD['id'])
        self.resource_api.create_project(self.project_inherited['id'],
                                         self.project_inherited)

        # Create and add groups
        self.group_employees = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.group_employees = (
            self.identity_api.create_group(self.group_employees))

        self.group_customers = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.group_customers = (
            self.identity_api.create_group(self.group_customers))

        self.group_admins = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.group_admins = self.identity_api.create_group(self.group_admins)

        # Create and add roles
        self.role_employee = self.new_role_ref()
        self.role_api.create_role(self.role_employee['id'], self.role_employee)
        self.role_customer = self.new_role_ref()
        self.role_api.create_role(self.role_customer['id'], self.role_customer)

        self.role_admin = self.new_role_ref()
        self.role_api.create_role(self.role_admin['id'], self.role_admin)

        # Employees can access
        # * proj_employees
        # * project_all
        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         project_id=self.proj_employees['id'])
        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         project_id=self.project_all['id'])
        # Customers can access
        # * proj_customers
        self.assignment_api.create_grant(self.role_customer['id'],
                                         group_id=self.group_customers['id'],
                                         project_id=self.proj_customers['id'])

        # Admins can access:
        # * proj_customers
        # * proj_employees
        # * project_all
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         project_id=self.proj_customers['id'])
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         project_id=self.proj_employees['id'])
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         project_id=self.project_all['id'])

        self.assignment_api.create_grant(self.role_customer['id'],
                                         group_id=self.group_customers['id'],
                                         domain_id=self.domainA['id'])

        # Customers can access:
        # * domain A
        self.assignment_api.create_grant(self.role_customer['id'],
                                         group_id=self.group_customers['id'],
                                         domain_id=self.domainA['id'])

        # Customers can access projects via inheritance:
        # * domain D
        self.assignment_api.create_grant(self.role_customer['id'],
                                         group_id=self.group_customers['id'],
                                         domain_id=self.domainD['id'],
                                         inherited_to_projects=True)

        # Employees can access:
        # * domain A
        # * domain B

        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         domain_id=self.domainB['id'])

        # Admins can access:
        # * domain A
        # * domain B
        # * domain C
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         domain_id=self.domainB['id'])

        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         domain_id=self.domainC['id'])
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
                }
            ]
        }

        # Add IDP
        self.idp = self.idp_ref(id=self.IDP)
        self.federation_api.create_idp(self.idp['id'],
                                       self.idp)
        # Add IDP with remote
        self.idp_with_remote = self.idp_ref(id=self.IDP_WITH_REMOTE)
        self.idp_with_remote['remote_ids'] = self.REMOTE_IDS
        self.federation_api.create_idp(self.idp_with_remote['id'],
                                       self.idp_with_remote)
        # Add a mapping
        self.mapping = self.mapping_ref()
        self.federation_api.create_mapping(self.mapping['id'],
                                           self.mapping)
        # Add protocols
        self.proto_saml = self.proto_ref(mapping_id=self.mapping['id'])
        self.proto_saml['id'] = self.PROTOCOL
        self.federation_api.create_protocol(self.idp['id'],
                                            self.proto_saml['id'],
                                            self.proto_saml)
        # Add protocols IDP with remote
        self.federation_api.create_protocol(self.idp_with_remote['id'],
                                            self.proto_saml['id'],
                                            self.proto_saml)
        # Generate fake tokens
        context = {'environment': {}}

        self.tokens = {}
        VARIANTS = ('EMPLOYEE_ASSERTION', 'CUSTOMER_ASSERTION',
                    'ADMIN_ASSERTION')
        api = auth_controllers.Auth()
        for variant in VARIANTS:
            self._inject_assertion(context, variant)
            r = api.authenticate_for_token(context, self.UNSCOPED_V3_SAML2_REQ)
            self.tokens[variant] = r.headers.get('X-Subject-Token')

        self.TOKEN_SCOPE_PROJECT_FROM_NONEXISTENT_TOKEN = self._scope_request(
            uuid.uuid4().hex, 'project', self.proj_customers['id'])

        self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE = self._scope_request(
            self.tokens['EMPLOYEE_ASSERTION'], 'project',
            self.proj_employees['id'])

        self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'project',
            self.proj_employees['id'])

        self.TOKEN_SCOPE_PROJECT_CUSTOMER_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'project',
            self.proj_customers['id'])

        self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'project',
            self.proj_employees['id'])

        self.TOKEN_SCOPE_PROJECT_INHERITED_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'project',
            self.project_inherited['id'])

        self.TOKEN_SCOPE_DOMAIN_A_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'domain', self.domainA['id'])

        self.TOKEN_SCOPE_DOMAIN_B_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'domain',
            self.domainB['id'])

        self.TOKEN_SCOPE_DOMAIN_D_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'domain', self.domainD['id'])

        self.TOKEN_SCOPE_DOMAIN_A_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'domain', self.domainA['id'])

        self.TOKEN_SCOPE_DOMAIN_B_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'domain', self.domainB['id'])

        self.TOKEN_SCOPE_DOMAIN_C_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'domain',
            self.domainC['id'])


class FederatedIdentityProviderTests(FederationTests):
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

    def _create_default_idp(self, body=None):
        """Create default IdP."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        if body is None:
            body = self._http_idp_input()
        resp = self.put(url, body={'identity_provider': body},
                        expected_status=201)
        return resp

    def _http_idp_input(self, **kwargs):
        """Create default input for IdP data."""
        body = None
        if 'body' not in kwargs:
            body = self.default_body.copy()
            body['description'] = uuid.uuid4().hex
        else:
            body = kwargs['body']
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
        url = "%s/protocols/%s" % (idp_id, protocol_id)
        url = self.base_url(suffix=url)
        r = self.get(url)
        return r

    def test_create_idp(self):
        """Creates the IdentityProvider entity associated to remote_ids."""

        keys_to_check = list(self.idp_keys)
        body = self.default_body.copy()
        body['description'] = uuid.uuid4().hex
        resp = self._create_default_idp(body=body)
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)

    def test_create_idp_remote(self):
        """Creates the IdentityProvider entity associated to remote_ids."""

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

    def test_create_idp_remote_repeated(self):
        """Creates two IdentityProvider entities with some remote_ids

        A remote_id is the same for both so the second IdP is not
        created because of the uniqueness of the remote_ids

        Expect HTTP 409 code for the latter call.

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
        self.put(url, body={'identity_provider': body},
                 expected_status=http_client.CONFLICT)

    def test_create_idp_remote_empty(self):
        """Creates an IdP with empty remote_ids."""

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
        """Creates an IdP with a None remote_ids."""

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

    def test_list_idps(self, iterations=5):
        """Lists all available IdentityProviders.

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

    def test_check_idp_uniqueness(self):
        """Add same IdP twice.

        Expect HTTP 409 code for the latter call.

        """
        url = self.base_url(suffix=uuid.uuid4().hex)
        body = self._http_idp_input()
        self.put(url, body={'identity_provider': body},
                 expected_status=201)
        self.put(url, body={'identity_provider': body},
                 expected_status=http_client.CONFLICT)

    def test_get_idp(self):
        """Create and later fetch IdP."""
        body = self._http_idp_input()
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        resp = self.get(url)
        self.assertValidResponse(resp, 'identity_provider',
                                 dummy_validator, keys_to_check=body.keys(),
                                 ref=body)

    def test_get_nonexisting_idp(self):
        """Fetch nonexisting IdP entity.

        Expected HTTP 404 status code.

        """
        idp_id = uuid.uuid4().hex
        self.assertIsNotNone(idp_id)

        url = self.base_url(suffix=idp_id)
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_delete_existing_idp(self):
        """Create and later delete IdP.

        Expect HTTP 404 for the GET IdP call.
        """
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        self.assertIsNotNone(idp_id)
        url = self.base_url(suffix=idp_id)
        self.delete(url)
        self.get(url, expected_status=http_client.NOT_FOUND)

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
        kwargs = {'expected_status': 201}
        resp, idp_id, proto = self._assign_protocol_to_idp(
            url=url,
            idp_id=idp_id,
            proto=protocol_id,
            **kwargs)

        # removing IdP will remove the assigned protocol as well
        self.assertEqual(1, len(self.federation_api.list_protocols(idp_id)))
        self.delete(idp_url)
        self.get(idp_url, expected_status=http_client.NOT_FOUND)
        self.assertEqual(0, len(self.federation_api.list_protocols(idp_id)))

    def test_delete_nonexisting_idp(self):
        """Delete nonexisting IdP.

        Expect HTTP 404 for the GET IdP call.
        """
        idp_id = uuid.uuid4().hex
        url = self.base_url(suffix=idp_id)
        self.delete(url, expected_status=http_client.NOT_FOUND)

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

        Expect HTTP FORBIDDEN.

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
                   expected_status=http_client.FORBIDDEN)

    def test_update_nonexistent_idp(self):
        """Update nonexistent IdP

        Expect HTTP 404 code.

        """
        idp_id = uuid.uuid4().hex
        url = self.base_url(suffix=idp_id)
        body = self._http_idp_input()
        body['enabled'] = False
        body = {'identity_provider': body}

        self.patch(url, body=body, expected_status=http_client.NOT_FOUND)

    def test_assign_protocol_to_idp(self):
        """Assign a protocol to existing IdP."""

        self._assign_protocol_to_idp(expected_status=201)

    def test_protocol_composite_pk(self):
        """Test whether Keystone let's add two entities with identical
        names, however attached to different IdPs.

        1. Add IdP and assign it protocol with predefined name
        2. Add another IdP and assign it a protocol with same name.

        Expect HTTP 201 code

        """
        url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')

        kwargs = {'expected_status': 201}
        self._assign_protocol_to_idp(proto='saml2',
                                     url=url, **kwargs)

        self._assign_protocol_to_idp(proto='saml2',
                                     url=url, **kwargs)

    def test_protocol_idp_pk_uniqueness(self):
        """Test whether Keystone checks for unique idp/protocol values.

        Add same protocol twice, expect Keystone to reject a latter call and
        return HTTP 409 code.

        """
        url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')

        kwargs = {'expected_status': 201}
        resp, idp_id, proto = self._assign_protocol_to_idp(proto='saml2',
                                                           url=url, **kwargs)
        kwargs = {'expected_status': http_client.CONFLICT}
        resp, idp_id, proto = self._assign_protocol_to_idp(idp_id=idp_id,
                                                           proto='saml2',
                                                           validate=False,
                                                           url=url, **kwargs)

    def test_assign_protocol_to_nonexistent_idp(self):
        """Assign protocol to IdP that doesn't exist.

        Expect HTTP 404 code.

        """

        idp_id = uuid.uuid4().hex
        kwargs = {'expected_status': http_client.NOT_FOUND}
        self._assign_protocol_to_idp(proto='saml2',
                                     idp_id=idp_id,
                                     validate=False,
                                     **kwargs)

    def test_get_protocol(self):
        """Create and later fetch protocol tied to IdP."""

        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        proto_id = self._fetch_attribute_from_response(resp, 'protocol')['id']
        url = "%s/protocols/%s" % (idp_id, proto_id)
        url = self.base_url(suffix=url)

        resp = self.get(url)

        reference = {'id': proto_id}
        self.assertValidResponse(resp, 'protocol',
                                 dummy_validator,
                                 keys_to_check=reference.keys(),
                                 ref=reference)

    def test_list_protocols(self):
        """Create set of protocols and later list them.

        Compare input and output id sets.

        """
        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        iterations = random.randint(0, 16)
        protocol_ids = []
        for _ in range(iterations):
            resp, _, proto = self._assign_protocol_to_idp(idp_id=idp_id,
                                                          expected_status=201)
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

    def test_update_protocols_attribute(self):
        """Update protocol's attribute."""

        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        new_mapping_id = uuid.uuid4().hex

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

        Expect HTTP 404 code for the GET call after the protocol is deleted.

        """
        url = self.base_url(suffix='/%(idp_id)s/'
                                   'protocols/%(protocol_id)s')
        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        url = url % {'idp_id': idp_id,
                     'protocol_id': proto}
        self.delete(url)
        self.get(url, expected_status=http_client.NOT_FOUND)


class MappingCRUDTests(FederationTests):
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
                        expected_status=201)
        return resp

    def _get_id_from_response(self, resp):
        r = resp.result.get('mapping')
        return r.get('id')

    def test_mapping_create(self):
        resp = self._create_default_mapping_entry()
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_LARGE)

    def test_mapping_list(self):
        url = self.MAPPING_URL
        self._create_default_mapping_entry()
        resp = self.get(url)
        entities = resp.result.get('mappings')
        self.assertIsNotNone(entities)
        self.assertResponseStatus(resp, 200)
        self.assertValidListLinks(resp.result.get('links'))
        self.assertEqual(1, len(entities))

    def test_mapping_delete(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': str(mapping_id)}
        resp = self.delete(url)
        self.assertResponseStatus(resp, 204)
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_mapping_get(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': mapping_id}
        resp = self.get(url)
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_LARGE)

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
        self.delete(url, expected_status=http_client.NOT_FOUND)

    def test_get_mapping_dne(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_create_mapping_bad_requirements(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_BAD_REQ})

    def test_create_mapping_no_rules(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_NO_RULES})

    def test_create_mapping_no_remote_objects(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_NO_REMOTE})

    def test_create_mapping_bad_value(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_BAD_VALUE})

    def test_create_mapping_missing_local(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_MISSING_LOCAL})

    def test_create_mapping_missing_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_MISSING_TYPE})

    def test_create_mapping_wrong_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_WRONG_TYPE})

    def test_create_mapping_extra_remote_properties_not_any_of(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_NOT_ANY_OF
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping})

    def test_create_mapping_extra_remote_properties_any_one_of(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_ANY_ONE_OF
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping})

    def test_create_mapping_extra_remote_properties_just_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_JUST_TYPE
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping})

    def test_create_mapping_empty_map(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': {}})

    def test_create_mapping_extra_rules_properties(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping_fixtures.MAPPING_EXTRA_RULES_PROPS})

    def test_create_mapping_with_blacklist_and_whitelist(self):
        """Test for adding whitelist and blacklist in the rule

        Server should respond with HTTP 400 error upon discovering both
        ``whitelist`` and ``blacklist`` keywords in the same rule.

        """
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_AND_BLACKLIST
        self.put(url, expected_status=http_client.BAD_REQUEST,
                 body={'mapping': mapping})


class FederatedTokenTests(FederationTests, FederatedSetupMixin):

    def auth_plugin_config_override(self):
        methods = ['saml2']
        super(FederatedTokenTests, self).auth_plugin_config_override(methods)

    def setUp(self):
        super(FederatedTokenTests, self).setUp()
        self._notifications = []

        def fake_saml_notify(action, context, user_id, group_ids,
                             identity_provider, protocol, token_id, outcome):
            note = {
                'action': action,
                'user_id': user_id,
                'identity_provider': identity_provider,
                'protocol': protocol,
                'send_notification_called': True}
            self._notifications.append(note)

        self.useFixture(mockpatch.PatchObject(
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
        super(FederationTests, self).load_fixtures(fixtures)
        self.load_federation_sample_data()

    def test_issue_unscoped_token_notify(self):
        self._issue_unscoped_token()
        self._assert_last_notify(self.ACTION, self.IDP, self.PROTOCOL)

    def test_issue_unscoped_token(self):
        r = self._issue_unscoped_token()
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))
        self.assertValidMappedUser(r.json['token'])

    def test_issue_unscoped_token_disabled_idp(self):
        """Checks if authentication works with disabled identity providers.

        Test plan:
        1) Disable default IdP
        2) Try issuing unscoped token for that IdP
        3) Expect server to forbid authentication

        """
        enabled_false = {'enabled': False}
        self.federation_api.update_idp(self.IDP, enabled_false)
        self.assertRaises(exception.Forbidden,
                          self._issue_unscoped_token)

    def test_issue_unscoped_token_group_names_in_mapping(self):
        r = self._issue_unscoped_token(assertion='ANOTHER_CUSTOMER_ASSERTION')
        ref_groups = set([self.group_customers['id'], self.group_admins['id']])
        token_resp = r.json_body
        token_groups = token_resp['token']['user']['OS-FEDERATION']['groups']
        token_groups = set([group['id'] for group in token_groups])
        self.assertEqual(ref_groups, token_groups)

    def test_issue_unscoped_tokens_nonexisting_group(self):
        self.assertRaises(exception.MissingGroups,
                          self._issue_unscoped_token,
                          assertion='ANOTHER_TESTER_ASSERTION')

    def test_issue_unscoped_token_with_remote_no_attribute(self):
        r = self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                       environment={
                                           self.REMOTE_ID_ATTR:
                                               self.REMOTE_IDS[0]
                                       })
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_issue_unscoped_token_with_remote(self):
        self.config_fixture.config(group='federation',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        r = self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                       environment={
                                           self.REMOTE_ID_ATTR:
                                               self.REMOTE_IDS[0]
                                       })
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_issue_unscoped_token_with_saml2_remote(self):
        self.config_fixture.config(group='saml2',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        r = self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                       environment={
                                           self.REMOTE_ID_ATTR:
                                               self.REMOTE_IDS[0]
                                       })
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

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
        r = self._issue_unscoped_token(idp=self.IDP_WITH_REMOTE,
                                       environment={
                                           self.REMOTE_ID_ATTR:
                                               self.REMOTE_IDS[0]
                                       })
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_issue_unscoped_token_with_remote_unavailable(self):
        self.config_fixture.config(group='federation',
                                   remote_id_attribute=self.REMOTE_ID_ATTR)
        self.assertRaises(exception.ValidationError,
                          self._issue_unscoped_token,
                          idp=self.IDP_WITH_REMOTE,
                          environment={
                              uuid.uuid4().hex: uuid.uuid4().hex
                          })

    def test_issue_unscoped_token_with_remote_user_as_empty_string(self):
        # make sure that REMOTE_USER set as the empty string won't interfere
        r = self._issue_unscoped_token(environment={'REMOTE_USER': ''})
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_issue_unscoped_token_no_groups(self):
        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token,
                          assertion='BAD_TESTER_ASSERTION')

    def test_issue_unscoped_token_malformed_environment(self):
        """Test whether non string objects are filtered out.

        Put non string objects into the environment, inject
        correct assertion and try to get an unscoped token.
        Expect server not to fail on using split() method on
        non string objects and return token id in the HTTP header.

        """
        api = auth_controllers.Auth()
        context = {
            'environment': {
                'malformed_object': object(),
                'another_bad_idea': tuple(range(10)),
                'yet_another_bad_param': dict(zip(uuid.uuid4().hex,
                                                  range(32)))
            }
        }
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION')
        r = api.authenticate_for_token(context, self.UNSCOPED_V3_SAML2_REQ)
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_scope_to_project_once_notify(self):
        r = self.v3_authenticate_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE)
        user_id = r.json['token']['user']['id']
        self._assert_last_notify(self.ACTION, self.IDP, self.PROTOCOL, user_id)

    def test_scope_to_project_once(self):
        r = self.v3_authenticate_token(
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
        self.federation_api.update_idp(self.IDP, enabled_false)
        self.v3_authenticate_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER,
            expected_status=http_client.FORBIDDEN)

    def test_scope_to_bad_project(self):
        """Scope unscoped token with a project we don't have access to."""

        self.v3_authenticate_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER,
            expected_status=http_client.UNAUTHORIZED)

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
            r = self.v3_authenticate_token(body)
            token_resp = r.result['token']
            self._check_project_scoped_token_attributes(token_resp,
                                                        project_id_ref)

    def test_scope_to_project_with_only_inherited_roles(self):
        """Try to scope token whose only roles are inherited."""
        self.config_fixture.config(group='os_inherit', enabled=True)
        r = self.v3_authenticate_token(
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
        self.v3_authenticate_token(
            self.TOKEN_SCOPE_PROJECT_FROM_NONEXISTENT_TOKEN,
            expected_status=http_client.NOT_FOUND)

    def test_issue_token_from_rules_without_user(self):
        api = auth_controllers.Auth()
        context = {'environment': {}}
        self._inject_assertion(context, 'BAD_TESTER_ASSERTION')
        self.assertRaises(exception.Unauthorized,
                          api.authenticate_for_token,
                          context, self.UNSCOPED_V3_SAML2_REQ)

    def test_issue_token_with_nonexistent_group(self):
        """Inject assertion that matches rule issuing bad group id.

        Expect server to find out that some groups are missing in the
        backend and raise exception.MappedGroupNotFound exception.

        """
        self.assertRaises(exception.MappedGroupNotFound,
                          self._issue_unscoped_token,
                          assertion='CONTRACTOR_ASSERTION')

    def test_scope_to_domain_once(self):
        r = self.v3_authenticate_token(self.TOKEN_SCOPE_DOMAIN_A_FROM_CUSTOMER)
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
            r = self.v3_authenticate_token(body)
            token_resp = r.result['token']
            self._check_domain_scoped_token_attributes(token_resp,
                                                       domain_id_ref)

    def test_scope_to_domain_with_only_inherited_roles_fails(self):
        """Try to scope to a domain that has no direct roles."""
        self.v3_authenticate_token(
            self.TOKEN_SCOPE_DOMAIN_D_FROM_CUSTOMER,
            expected_status=http_client.UNAUTHORIZED)

    def test_list_projects(self):
        urls = ('/OS-FEDERATION/projects', '/auth/projects')

        token = (self.tokens['CUSTOMER_ASSERTION'],
                 self.tokens['EMPLOYEE_ASSERTION'],
                 self.tokens['ADMIN_ASSERTION'])

        self.config_fixture.config(group='os_inherit', enabled=True)
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
    # have tests specific to this fuctionality grouped, easing readability and
    # maintenability.
    def test_list_projects_for_inherited_project_assignment(self):
        # Enable os_inherit extension
        self.config_fixture.config(group='os_inherit', enabled=True)

        # Create a subproject
        subproject_inherited = self.new_project_ref(
            domain_id=self.domainD['id'],
            parent_id=self.project_inherited['id'])
        self.resource_api.create_project(subproject_inherited['id'],
                                         subproject_inherited)

        # Create an inherited role assignment
        self.assignment_api.create_grant(
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
        token_resp = r.json_body['token']
        self.assertValidMappedUser(token_resp)
        employee_unscoped_token_id = r.headers.get('X-Subject-Token')
        r = self.get('/auth/projects', token=employee_unscoped_token_id)
        projects = r.result['projects']
        random_project = random.randint(0, len(projects)) - 1
        project = projects[random_project]

        v3_scope_request = self._scope_request(employee_unscoped_token_id,
                                               'project', project['id'])

        r = self.v3_authenticate_token(v3_scope_request)
        token_resp = r.result['token']
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
        group = self.new_group_ref(
            domain_id=self.domainA['id'])
        group = self.identity_api.create_group(group)
        role = self.new_role_ref()
        self.role_api.create_role(role['id'], role)

        # assign role to group and project_admins
        self.assignment_api.create_grant(role['id'],
                                         group_id=group['id'],
                                         project_id=self.project_all['id'])

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

        self.federation_api.update_mapping(self.mapping['id'], rules)

        r = self._issue_unscoped_token(assertion='TESTER_ASSERTION')
        token_id = r.headers.get('X-Subject-Token')

        # delete group
        self.identity_api.delete_group(group['id'])

        # scope token to project_all, expect HTTP 500
        scoped_token = self._scope_request(
            token_id, 'project',
            self.project_all['id'])

        self.v3_authenticate_token(scoped_token, expected_status=500)

    def test_lists_with_missing_group_in_backend(self):
        """Test a mapping that points to a group that does not exist

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
        group = self.new_group_ref(domain_id=domain_id)
        group['name'] = 'EXISTS'
        group = self.identity_api.create_group(group)
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
        self.federation_api.update_mapping(self.mapping['id'], rules)

    def test_empty_blacklist_passess_all_values(self):
        """Test a mapping with empty blacklist specified

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
        group_exists = self.new_group_ref(domain_id=domain_id)
        group_exists['name'] = 'EXISTS'
        group_exists = self.identity_api.create_group(group_exists)

        # Add a group "NO_EXISTS"
        group_no_exists = self.new_group_ref(domain_id=domain_id)
        group_no_exists['name'] = 'NO_EXISTS'
        group_no_exists = self.identity_api.create_group(group_no_exists)

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
        self.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_group_ids = r.json['token']['user']['OS-FEDERATION']['groups']
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
        group_exists = self.new_group_ref(domain_id=domain_id)
        group_exists['name'] = 'EXISTS'
        group_exists = self.identity_api.create_group(group_exists)

        # Add a group "NO_EXISTS"
        group_no_exists = self.new_group_ref(domain_id=domain_id)
        group_no_exists['name'] = 'NO_EXISTS'
        group_no_exists = self.identity_api.create_group(group_no_exists)

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
        self.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_group_ids = r.json['token']['user']['OS-FEDERATION']['groups']
        self.assertEqual(len(group_ids), len(assigned_group_ids))
        for group in assigned_group_ids:
            self.assertIn(group['id'], group_ids)

    def test_empty_whitelist_discards_all_values(self):
        """Test that empty whitelist blocks all the values

        Not adding a ``whitelist`` keyword to the mapping value is different
        than adding empty whitelist.  The former case will simply pass all the
        values, whereas the latter would discard all the values.

        This test checks scenario where an empty whitelist was specified.
        The expected result is that no groups are matched.

        The test scenario is as follows:
         - Create group ``EXISTS``
         - Set mapping rules for existing IdP with an empty whitelist
           that whould discard any values from the assertion
         - Try issuing unscoped token, expect server to raise
           ``exception.MissingGroups`` as no groups were matched and ephemeral
           user does not have any group assigned.

        """
        domain_id = self.domainA['id']
        domain_name = self.domainA['name']
        group = self.new_group_ref(domain_id=domain_id)
        group['name'] = 'EXISTS'
        group = self.identity_api.create_group(group)
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
        self.federation_api.update_mapping(self.mapping['id'], rules)

        self.assertRaises(exception.MissingGroups,
                          self._issue_unscoped_token,
                          assertion='UNMATCHED_GROUP_ASSERTION')

    def test_not_setting_whitelist_accepts_all_values(self):
        """Test that not setting whitelist passes

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
        group_exists = self.new_group_ref(domain_id=domain_id)
        group_exists['name'] = 'EXISTS'
        group_exists = self.identity_api.create_group(group_exists)

        # Add a group "NO_EXISTS"
        group_no_exists = self.new_group_ref(domain_id=domain_id)
        group_no_exists['name'] = 'NO_EXISTS'
        group_no_exists = self.identity_api.create_group(group_no_exists)

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
        self.federation_api.update_mapping(self.mapping['id'], rules)
        r = self._issue_unscoped_token(assertion='UNMATCHED_GROUP_ASSERTION')
        assigned_group_ids = r.json['token']['user']['OS-FEDERATION']['groups']
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
        r = self._issue_unscoped_token(assertion='EMPLOYEE_ASSERTION_PREFIXED')
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_assertion_prefix_parameter_expect_fail(self):
        """Test parameters filtering based on the prefix.

        With ``assertion_prefix`` default value set to empty string
        issue an unscoped token from assertion EMPLOYEE_ASSERTION.
        Next, configure ``assertion_prefix`` to value ``UserName``.
        Try issuing unscoped token with EMPLOYEE_ASSERTION.
        Expect server to raise exception.Unathorized exception.

        """
        r = self._issue_unscoped_token()
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))
        self.config_fixture.config(group='federation',
                                   assertion_prefix='UserName')

        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token)

    def test_v2_auth_with_federation_token_fails(self):
        """Test that using a federation token with v2 auth fails.

        If an admin sets up a federated Keystone environment, and a user
        incorrectly configures a service (like Nova) to only use v2 auth, the
        returned message should be informative.

        """
        r = self._issue_unscoped_token()
        token_id = r.headers.get('X-Subject-Token')
        self.assertRaises(exception.Unauthorized,
                          self.token_provider_api.validate_v2_token,
                          token_id=token_id)

    def test_unscoped_token_has_user_domain(self):
        r = self._issue_unscoped_token()
        self._check_domains_are_valid(r.json_body['token'])

    def test_scoped_token_has_user_domain(self):
        r = self.v3_authenticate_token(
            self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE)
        self._check_domains_are_valid(r.result['token'])

    def test_issue_unscoped_token_for_local_user(self):
        r = self._issue_unscoped_token(assertion='LOCAL_USER_ASSERTION')
        token_resp = r.json_body['token']
        self.assertListEqual(['saml2'], token_resp['methods'])
        self.assertEqual(self.user['id'], token_resp['user']['id'])
        self.assertEqual(self.user['name'], token_resp['user']['name'])
        self.assertEqual(self.domain['id'], token_resp['user']['domain']['id'])
        # Make sure the token is not scoped
        self.assertNotIn('project', token_resp)
        self.assertNotIn('domain', token_resp)

    def test_issue_token_for_local_user_user_not_found(self):
        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token,
                          assertion='ANOTHER_LOCAL_USER_ASSERTION')


class FernetFederatedTokenTests(FederationTests, FederatedSetupMixin):
    AUTH_METHOD = 'token'

    def load_fixtures(self, fixtures):
        super(FernetFederatedTokenTests, self).load_fixtures(fixtures)
        self.load_federation_sample_data()

    def config_overrides(self):
        super(FernetFederatedTokenTests, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))

    def auth_plugin_config_override(self):
        methods = ['saml2', 'token', 'password']
        super(FernetFederatedTokenTests,
              self).auth_plugin_config_override(methods)

    def test_federated_unscoped_token(self):
        resp = self._issue_unscoped_token()
        self.assertEqual(204, len(resp.headers['X-Subject-Token']))
        self.assertValidMappedUser(resp.json_body['token'])

    def test_federated_unscoped_token_with_multiple_groups(self):
        assertion = 'ANOTHER_CUSTOMER_ASSERTION'
        resp = self._issue_unscoped_token(assertion=assertion)
        self.assertEqual(226, len(resp.headers['X-Subject-Token']))
        self.assertValidMappedUser(resp.json_body['token'])

    def test_validate_federated_unscoped_token(self):
        resp = self._issue_unscoped_token()
        unscoped_token = resp.headers.get('X-Subject-Token')
        # assert that the token we received is valid
        self.get('/auth/tokens/', headers={'X-Subject-Token': unscoped_token})

    def test_fernet_full_workflow(self):
        """Test 'standard' workflow for granting Fernet access tokens.

        * Issue unscoped token
        * List available projects based on groups
        * Scope token to one of available projects

        """
        resp = self._issue_unscoped_token()
        self.assertValidMappedUser(resp.json_body['token'])
        unscoped_token = resp.headers.get('X-Subject-Token')
        resp = self.get('/auth/projects', token=unscoped_token)
        projects = resp.result['projects']
        random_project = random.randint(0, len(projects)) - 1
        project = projects[random_project]

        v3_scope_request = self._scope_request(unscoped_token,
                                               'project', project['id'])

        resp = self.v3_authenticate_token(v3_scope_request)
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


class JsonHomeTests(FederationTests, test_v3.JsonHomeTestMixin):
    JSON_HOME_DATA = {
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/'
        '1.0/rel/identity_provider': {
            'href-template': '/OS-FEDERATION/identity_providers/{idp_id}',
            'href-vars': {
                'idp_id': 'http://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-FEDERATION/1.0/param/idp_id'
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


class SAMLGenerationTests(FederationTests):

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
    SAML_GENERATION_ROUTE = '/auth/OS-FEDERATION/saml2'
    ECP_GENERATION_ROUTE = '/auth/OS-FEDERATION/saml2/ecp'
    ASSERTION_VERSION = "2.0"
    SERVICE_PROVDIER_ID = 'ACME'

    def sp_ref(self):
        ref = {
            'auth_url': self.SP_AUTH_URL,
            'enabled': True,
            'description': uuid.uuid4().hex,
            'sp_url': self.RECIPIENT,
            'relay_state_prefix': CONF.saml.relay_state_prefix,

        }
        return ref

    def setUp(self):
        super(SAMLGenerationTests, self).setUp()
        self.signed_assertion = saml2.create_class_from_xml_string(
            saml.Assertion, _load_xml(self.ASSERTION_FILE))
        self.sp = self.sp_ref()
        url = '/OS-FEDERATION/service_providers/' + self.SERVICE_PROVDIER_ID
        self.put(url, body={'service_provider': self.sp},
                 expected_status=201)

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
                                               self.PROJECT_DOMAIN)

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
                                               self.PROJECT_DOMAIN)
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
                                               self.PROJECT_DOMAIN)

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

    def test_assertion_using_explicit_namespace_prefixes(self):
        def mocked_subprocess_check_output(*popenargs, **kwargs):
            # the last option is the assertion file to be signed
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
                                               self.PROJECT_DOMAIN)
            assertion_xml = response.assertion.to_string()
            # make sure we have the proper tag and prefix for the assertion
            # namespace
            self.assertIn('<saml:Assertion', assertion_xml)
            self.assertIn('xmlns:saml="' + saml2.NAMESPACE + '"',
                          assertion_xml)
            self.assertIn('xmlns:xmldsig="' + xmldsig.NAMESPACE + '"',
                          assertion_xml)

    def test_saml_signing(self):
        """Test that the SAML generator produces a SAML object.

        Test the SAML generator directly by passing known arguments, the result
        should be a SAML object that consistently includes attributes based on
        the known arguments that were passed in.

        """
        if not _is_xmlsec1_installed():
            self.skip('xmlsec1 is not installed')

        generator = keystone_idp.SAMLGenerator()
        response = generator.samlize_token(self.ISSUER, self.RECIPIENT,
                                           self.SUBJECT, self.SUBJECT_DOMAIN,
                                           self.ROLES, self.PROJECT,
                                           self.PROJECT_DOMAIN)

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
        resp = self.v3_authenticate_token(auth_data)
        token_id = resp.headers.get('X-Subject-Token')
        return token_id

    def _fetch_domain_scoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            user_domain_id=self.domain['id'])
        resp = self.v3_authenticate_token(auth_data)
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
                      expected_status=http_client.FORBIDDEN)

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
                                      expected_status=200)

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

    def test_invalid_scope_body(self):
        """Test that missing the scope in request body raises an exception.

        Raises exception.SchemaValidationError() - error code 400

        """

        token_id = uuid.uuid4().hex
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        del body['auth']['scope']

        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http_client.BAD_REQUEST)

    def test_invalid_token_body(self):
        """Test that missing the token in request body raises an exception.

        Raises exception.SchemaValidationError() - error code 400

        """

        token_id = uuid.uuid4().hex
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        del body['auth']['identity']['token']

        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http_client.BAD_REQUEST)

    def test_sp_not_found(self):
        """Test SAML generation with an invalid service provider ID.

        Raises exception.ServiceProviderNotFound() - error code 404

        """
        sp_id = uuid.uuid4().hex
        token_id = self._fetch_valid_token()
        body = self._create_generate_saml_request(token_id, sp_id)
        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http_client.NOT_FOUND)

    def test_sp_disabled(self):
        """Try generating assertion for disabled Service Provider."""

        # Disable Service Provider
        sp_ref = {'enabled': False}
        self.federation_api.update_sp(self.SERVICE_PROVDIER_ID, sp_ref)

        token_id = self._fetch_valid_token()
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http_client.FORBIDDEN)

    def test_token_not_found(self):
        """Test that an invalid token in the request body raises an exception.

        Raises exception.TokenNotFound() - error code 404

        """

        token_id = uuid.uuid4().hex
        body = self._create_generate_saml_request(token_id,
                                                  self.SERVICE_PROVDIER_ID)
        self.post(self.SAML_GENERATION_ROUTE, body=body,
                  expected_status=http_client.NOT_FOUND)

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
                                      expected_status=200)

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

    @mock.patch('saml2.create_class_from_xml_string')
    @mock.patch('oslo_utils.fileutils.write_to_tempfile')
    @mock.patch.object(subprocess, 'check_output')
    def test__sign_assertion(self, check_output_mock,
                             write_to_tempfile_mock, create_class_mock):
        write_to_tempfile_mock.return_value = 'tmp_path'
        check_output_mock.return_value = 'fakeoutput'

        keystone_idp._sign_assertion(self.signed_assertion)

        create_class_mock.assert_called_with(saml.Assertion, 'fakeoutput')

    @mock.patch('oslo_utils.fileutils.write_to_tempfile')
    @mock.patch.object(subprocess, 'check_output')
    def test__sign_assertion_exc(self, check_output_mock,
                                 write_to_tempfile_mock):
        # If the command fails the command output is logged.

        write_to_tempfile_mock.return_value = 'tmp_path'

        sample_returncode = 1
        sample_output = self.getUniqueString()
        check_output_mock.side_effect = subprocess.CalledProcessError(
            returncode=sample_returncode, cmd=CONF.saml.xmlsec1_binary,
            output=sample_output)

        logger_fixture = self.useFixture(fixtures.LoggerFixture())
        self.assertRaises(exception.SAMLSigningError,
                          keystone_idp._sign_assertion,
                          self.signed_assertion)
        expected_log = (
            "Error when signing assertion, reason: Command '%s' returned "
            "non-zero exit status %s %s\n" %
            (CONF.saml.xmlsec1_binary, sample_returncode, sample_output))
        self.assertEqual(expected_log, logger_fixture.output)

    @mock.patch('oslo_utils.fileutils.write_to_tempfile')
    def test__sign_assertion_fileutils_exc(self, write_to_tempfile_mock):
        exception_msg = 'fake'
        write_to_tempfile_mock.side_effect = Exception(exception_msg)

        logger_fixture = self.useFixture(fixtures.LoggerFixture())
        self.assertRaises(exception.SAMLSigningError,
                          keystone_idp._sign_assertion,
                          self.signed_assertion)
        expected_log = (
            'Error when signing assertion, reason: %s\n' % exception_msg)
        self.assertEqual(expected_log, logger_fixture.output)


class IdPMetadataGenerationTests(FederationTests):
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

    def test_metadata_invalid_contact_type(self):
        self.config_fixture.config(
            group='saml',
            idp_contact_type="invalid")
        self.assertRaises(exception.ValidationError,
                          self.generator.generate_metadata)

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
        self.get(self.METADATA_URL, expected_status=500)

    def test_get_metadata(self):
        self.config_fixture.config(
            group='saml', idp_metadata_path=XMLDIR + '/idp_saml2_metadata.xml')
        r = self.get(self.METADATA_URL, response_content_type='text/xml',
                     expected_status=200)
        self.assertEqual('text/xml', r.headers.get('Content-Type'))

        reference_file = _load_xml('idp_saml2_metadata.xml')
        self.assertEqual(reference_file, r.result)


class ServiceProviderTests(FederationTests):
    """A test class for Service Providers."""

    MEMBER_NAME = 'service_provider'
    COLLECTION_NAME = 'service_providers'
    SERVICE_PROVIDER_ID = 'ACME'
    SP_KEYS = ['auth_url', 'id', 'enabled', 'description',
               'relay_state_prefix', 'sp_url']

    def setUp(self):
        super(FederationTests, self).setUp()
        # Add a Service Provider
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.SP_REF = self.sp_ref()
        self.SERVICE_PROVIDER = self.put(
            url, body={'service_provider': self.SP_REF},
            expected_status=201).result

    def sp_ref(self):
        ref = {
            'auth_url': 'https://' + uuid.uuid4().hex + '.com',
            'enabled': True,
            'description': uuid.uuid4().hex,
            'sp_url': 'https://' + uuid.uuid4().hex + '.com',
            'relay_state_prefix': CONF.saml.relay_state_prefix
        }
        return ref

    def base_url(self, suffix=None):
        if suffix is not None:
            return '/OS-FEDERATION/service_providers/' + str(suffix)
        return '/OS-FEDERATION/service_providers'

    def test_get_service_provider(self):
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        resp = self.get(url, expected_status=200)
        self.assertValidEntity(resp.result['service_provider'],
                               keys_to_check=self.SP_KEYS)

    def test_get_service_provider_fail(self):
        url = self.base_url(suffix=uuid.uuid4().hex)
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_create_service_provider(self):
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = self.sp_ref()
        resp = self.put(url, body={'service_provider': sp},
                        expected_status=201)
        self.assertValidEntity(resp.result['service_provider'],
                               keys_to_check=self.SP_KEYS)

    def test_create_sp_relay_state_default(self):
        """Create an SP without relay state, should default to `ss:mem`."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = self.sp_ref()
        del sp['relay_state_prefix']
        resp = self.put(url, body={'service_provider': sp},
                        expected_status=201)
        sp_result = resp.result['service_provider']
        self.assertEqual(CONF.saml.relay_state_prefix,
                         sp_result['relay_state_prefix'])

    def test_create_sp_relay_state_non_default(self):
        """Create an SP with custom relay state."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = self.sp_ref()
        non_default_prefix = uuid.uuid4().hex
        sp['relay_state_prefix'] = non_default_prefix
        resp = self.put(url, body={'service_provider': sp},
                        expected_status=201)
        sp_result = resp.result['service_provider']
        self.assertEqual(non_default_prefix,
                         sp_result['relay_state_prefix'])

    def test_create_service_provider_fail(self):
        """Try adding SP object with unallowed attribute."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        sp = self.sp_ref()
        sp[uuid.uuid4().hex] = uuid.uuid4().hex
        self.put(url, body={'service_provider': sp},
                 expected_status=http_client.BAD_REQUEST)

    def test_list_service_providers(self):
        """Test listing of service provider objects.

        Add two new service providers. List all available service providers.
        Expect to get list of three service providers (one created by setUp())
        Test if attributes match.

        """
        ref_service_providers = {
            uuid.uuid4().hex: self.sp_ref(),
            uuid.uuid4().hex: self.sp_ref(),
        }
        for id, sp in ref_service_providers.items():
            url = self.base_url(suffix=id)
            self.put(url, body={'service_provider': sp}, expected_status=201)

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

    def test_update_service_provider(self):
        """Update existing service provider.

        Update default existing service provider and make sure it has been
        properly changed.

        """
        new_sp_ref = self.sp_ref()
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        resp = self.patch(url, body={'service_provider': new_sp_ref},
                          expected_status=200)
        patch_result = resp.result
        new_sp_ref['id'] = self.SERVICE_PROVIDER_ID
        self.assertValidEntity(patch_result['service_provider'],
                               ref=new_sp_ref,
                               keys_to_check=self.SP_KEYS)

        resp = self.get(url, expected_status=200)
        get_result = resp.result

        self.assertDictEqual(patch_result['service_provider'],
                             get_result['service_provider'])

    def test_update_service_provider_immutable_parameters(self):
        """Update immutable attributes in service provider.

        In this particular case the test will try to change ``id`` attribute.
        The server should return an HTTP 403 error code.

        """
        new_sp_ref = {'id': uuid.uuid4().hex}
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.patch(url, body={'service_provider': new_sp_ref},
                   expected_status=http_client.BAD_REQUEST)

    def test_update_service_provider_unknown_parameter(self):
        new_sp_ref = self.sp_ref()
        new_sp_ref[uuid.uuid4().hex] = uuid.uuid4().hex
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.patch(url, body={'service_provider': new_sp_ref},
                   expected_status=http_client.BAD_REQUEST)

    def test_update_service_provider_404(self):
        new_sp_ref = self.sp_ref()
        new_sp_ref['description'] = uuid.uuid4().hex
        url = self.base_url(suffix=uuid.uuid4().hex)
        self.patch(url, body={'service_provider': new_sp_ref},
                   expected_status=http_client.NOT_FOUND)

    def test_update_sp_relay_state(self):
        """Update an SP with custome relay state."""
        new_sp_ref = self.sp_ref()
        non_default_prefix = uuid.uuid4().hex
        new_sp_ref['relay_state_prefix'] = non_default_prefix
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        resp = self.patch(url, body={'service_provider': new_sp_ref},
                          expected_status=200)
        sp_result = resp.result['service_provider']
        self.assertEqual(non_default_prefix,
                         sp_result['relay_state_prefix'])

    def test_delete_service_provider(self):
        url = self.base_url(suffix=self.SERVICE_PROVIDER_ID)
        self.delete(url, expected_status=204)

    def test_delete_service_provider_404(self):
        url = self.base_url(suffix=uuid.uuid4().hex)
        self.delete(url, expected_status=http_client.NOT_FOUND)


class WebSSOTests(FederatedTokenTests):
    """A class for testing Web SSO."""

    SSO_URL = '/auth/OS-FEDERATION/websso/'
    SSO_TEMPLATE_NAME = 'sso_callback_template.html'
    SSO_TEMPLATE_PATH = os.path.join(core.dirs.etc(), SSO_TEMPLATE_NAME)
    TRUSTED_DASHBOARD = 'http://horizon.com'
    ORIGIN = urllib.parse.quote_plus(TRUSTED_DASHBOARD)
    PROTOCOL_REMOTE_ID_ATTR = uuid.uuid4().hex

    def setUp(self):
        super(WebSSOTests, self).setUp()
        self.api = federation_controllers.Auth()

    def config_overrides(self):
        super(WebSSOTests, self).config_overrides()
        self.config_fixture.config(
            group='federation',
            trusted_dashboard=[self.TRUSTED_DASHBOARD],
            sso_callback_template=self.SSO_TEMPLATE_PATH,
            remote_id_attribute=self.REMOTE_ID_ATTR)

    def test_render_callback_template(self):
        token_id = uuid.uuid4().hex
        resp = self.api.render_html_response(self.TRUSTED_DASHBOARD, token_id)
        self.assertIn(token_id, resp.body)
        self.assertIn(self.TRUSTED_DASHBOARD, resp.body)

    def test_federated_sso_auth(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0]}
        context = {'environment': environment}
        query_string = {'origin': self.ORIGIN}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION', query_string)
        resp = self.api.federated_sso_auth(context, self.PROTOCOL)
        self.assertIn(self.TRUSTED_DASHBOARD, resp.body)

    def test_federated_sso_auth_with_protocol_specific_remote_id(self):
        self.config_fixture.config(
            group=self.PROTOCOL,
            remote_id_attribute=self.PROTOCOL_REMOTE_ID_ATTR)

        environment = {self.PROTOCOL_REMOTE_ID_ATTR: self.REMOTE_IDS[0]}
        context = {'environment': environment}
        query_string = {'origin': self.ORIGIN}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION', query_string)
        resp = self.api.federated_sso_auth(context, self.PROTOCOL)
        self.assertIn(self.TRUSTED_DASHBOARD, resp.body)

    def test_federated_sso_auth_bad_remote_id(self):
        environment = {self.REMOTE_ID_ATTR: self.IDP}
        context = {'environment': environment}
        query_string = {'origin': self.ORIGIN}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION', query_string)
        self.assertRaises(exception.IdentityProviderNotFound,
                          self.api.federated_sso_auth,
                          context, self.PROTOCOL)

    def test_federated_sso_missing_query(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0]}
        context = {'environment': environment}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION')
        self.assertRaises(exception.ValidationError,
                          self.api.federated_sso_auth,
                          context, self.PROTOCOL)

    def test_federated_sso_missing_query_bad_remote_id(self):
        environment = {self.REMOTE_ID_ATTR: self.IDP}
        context = {'environment': environment}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION')
        self.assertRaises(exception.ValidationError,
                          self.api.federated_sso_auth,
                          context, self.PROTOCOL)

    def test_federated_sso_untrusted_dashboard(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0]}
        context = {'environment': environment}
        query_string = {'origin': uuid.uuid4().hex}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION', query_string)
        self.assertRaises(exception.Unauthorized,
                          self.api.federated_sso_auth,
                          context, self.PROTOCOL)

    def test_federated_sso_untrusted_dashboard_bad_remote_id(self):
        environment = {self.REMOTE_ID_ATTR: self.IDP}
        context = {'environment': environment}
        query_string = {'origin': uuid.uuid4().hex}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION', query_string)
        self.assertRaises(exception.Unauthorized,
                          self.api.federated_sso_auth,
                          context, self.PROTOCOL)

    def test_federated_sso_missing_remote_id(self):
        context = {'environment': {}}
        query_string = {'origin': self.ORIGIN}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION', query_string)
        self.assertRaises(exception.Unauthorized,
                          self.api.federated_sso_auth,
                          context, self.PROTOCOL)

    def test_identity_provider_specific_federated_authentication(self):
        environment = {self.REMOTE_ID_ATTR: self.REMOTE_IDS[0]}
        context = {'environment': environment}
        query_string = {'origin': self.ORIGIN}
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION', query_string)
        resp = self.api.federated_idp_specific_sso_auth(context,
                                                        self.idp['id'],
                                                        self.PROTOCOL)
        self.assertIn(self.TRUSTED_DASHBOARD, resp.body)


class K2KServiceCatalogTests(FederationTests):
    SP1 = 'SP1'
    SP2 = 'SP2'
    SP3 = 'SP3'

    def setUp(self):
        super(K2KServiceCatalogTests, self).setUp()

        sp = self.sp_ref()
        self.federation_api.create_sp(self.SP1, sp)
        self.sp_alpha = {self.SP1: sp}

        sp = self.sp_ref()
        self.federation_api.create_sp(self.SP2, sp)
        self.sp_beta = {self.SP2: sp}

        sp = self.sp_ref()
        self.federation_api.create_sp(self.SP3, sp)
        self.sp_gamma = {self.SP3: sp}

        self.token_v3_helper = token_common.V3TokenDataHelper()

    def sp_response(self, id, ref):
        ref.pop('enabled')
        ref.pop('description')
        ref.pop('relay_state_prefix')
        ref['id'] = id
        return ref

    def sp_ref(self):
        ref = {
            'auth_url': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex,
            'sp_url': uuid.uuid4().hex,
            'relay_state_prefix': CONF.saml.relay_state_prefix,
        }
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
            self.assertDictEqual(ref_entity, entity)

    def test_service_providers_in_token(self):
        """Check if service providers are listed in service catalog."""

        token = self.token_v3_helper.get_token_data(self.user_id, ['password'])
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
        self.federation_api.update_sp(self.SP1, sp_ref)

        token = self.token_v3_helper.get_token_data(self.user_id, ['password'])
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
            self.federation_api.update_sp(sp, sp_ref)

        token = self.token_v3_helper.get_token_data(self.user_id, ['password'])
        self.assertNotIn('service_providers', token['token'],
                         message=('Expected Service Catalog not to have '
                                  'service_providers'))
