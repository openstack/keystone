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
import datetime
import uuid

from oslo_utils import timeutils
from six.moves import range

from keystone.common import provider_api
from keystone.common import utils as ks_utils
import keystone.conf
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.models import token_model
from keystone.tests.unit import base_classes
from keystone.tests.unit import core
from keystone.tests.unit import test_token_provider
from keystone.token import provider

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TestKeystoneTokenModel(core.TestCase):
    def setUp(self):
        super(TestKeystoneTokenModel, self).setUp()
        self.v3_sample_token = copy.deepcopy(
            test_token_provider.SAMPLE_V3_TOKEN)

    def test_token_model_v3(self):
        token_data = token_model.KeystoneToken(uuid.uuid4().hex,
                                               self.v3_sample_token)
        expires = timeutils.normalize_time(timeutils.parse_isotime(
            self.v3_sample_token['token']['expires_at']))
        issued = timeutils.normalize_time(timeutils.parse_isotime(
            self.v3_sample_token['token']['issued_at']))
        self.assertEqual(expires, token_data.expires)
        self.assertEqual(issued, token_data.issued)
        self.assertEqual(self.v3_sample_token['token']['user']['id'],
                         token_data.user_id)
        self.assertEqual(self.v3_sample_token['token']['user']['name'],
                         token_data.user_name)
        self.assertEqual(
            self.v3_sample_token['token']['user']['password_expires_at'],
            token_data.user_password_expires_at)
        self.assertEqual(self.v3_sample_token['token']['user']['domain']['id'],
                         token_data.user_domain_id)
        self.assertEqual(
            self.v3_sample_token['token']['user']['domain']['name'],
            token_data.user_domain_name)
        self.assertEqual(
            self.v3_sample_token['token']['project']['domain']['id'],
            token_data.project_domain_id)
        self.assertEqual(
            self.v3_sample_token['token']['project']['domain']['name'],
            token_data.project_domain_name)
        self.assertEqual(
            self.v3_sample_token['token']['is_domain'], token_data.is_domain)
        self.assertEqual(self.v3_sample_token['token']['OS-TRUST:trust']['id'],
                         token_data.trust_id)
        self.assertEqual(
            self.v3_sample_token['token']['OS-TRUST:trust']['trustor_user_id'],
            token_data.trustor_user_id)
        self.assertEqual(
            self.v3_sample_token['token']['OS-TRUST:trust']['trustee_user_id'],
            token_data.trustee_user_id)

        # Project Scoped Token
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'domain_id')
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'domain_name')
        self.assertFalse(token_data.domain_scoped)
        self.assertEqual(self.v3_sample_token['token']['project']['id'],
                         token_data.project_id)
        self.assertEqual(self.v3_sample_token['token']['project']['name'],
                         token_data.project_name)
        self.assertTrue(token_data.project_scoped)
        self.assertTrue(token_data.scoped)
        self.assertTrue(token_data.trust_scoped)

        # by default admin project is True for project scoped tokens
        self.assertTrue(token_data.is_admin_project)

        self.assertEqual(
            [r['id'] for r in self.v3_sample_token['token']['roles']],
            token_data.role_ids)
        self.assertEqual(
            [r['name'] for r in self.v3_sample_token['token']['roles']],
            token_data.role_names)

        # Domain Scoped Token
        token_data.pop('project')
        self.assertFalse(token_data.project_scoped)
        self.assertFalse(token_data.scoped)
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'project_id')
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'project_name')
        self.assertFalse(token_data.project_scoped)
        domain_id = uuid.uuid4().hex
        domain_name = uuid.uuid4().hex
        token_data['domain'] = {'id': domain_id,
                                'name': domain_name}
        self.assertEqual(domain_id, token_data.domain_id)
        self.assertEqual(domain_name, token_data.domain_name)
        self.assertTrue(token_data.domain_scoped)

        token_data['audit_ids'] = [uuid.uuid4().hex]
        self.assertEqual(token_data.audit_id,
                         token_data['audit_ids'][0])
        self.assertEqual(token_data.audit_chain_id,
                         token_data['audit_ids'][0])
        token_data['audit_ids'].append(uuid.uuid4().hex)
        self.assertEqual(token_data.audit_chain_id,
                         token_data['audit_ids'][1])
        del token_data['audit_ids']
        self.assertIsNone(token_data.audit_id)
        self.assertIsNone(token_data.audit_chain_id)

        # by default admin project is False for domain scoped tokens
        self.assertFalse(token_data.is_admin_project)

    def test_token_model_v3_federated_user(self):
        token_data = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                               token_data=self.v3_sample_token)
        federation_data = {'identity_provider': {'id': uuid.uuid4().hex},
                           'protocol': {'id': 'saml2'},
                           'groups': [{'id': uuid.uuid4().hex}
                                      for x in range(1, 5)]}

        self.assertFalse(token_data.is_federated_user)
        self.assertEqual([], token_data.federation_group_ids)
        self.assertIsNone(token_data.federation_protocol_id)
        self.assertIsNone(token_data.federation_idp_id)

        token_data['user'][federation_constants.FEDERATION] = federation_data

        self.assertTrue(token_data.is_federated_user)
        self.assertEqual([x['id'] for x in federation_data['groups']],
                         token_data.federation_group_ids)
        self.assertEqual(federation_data['protocol']['id'],
                         token_data.federation_protocol_id)
        self.assertEqual(federation_data['identity_provider']['id'],
                         token_data.federation_idp_id)

    def test_token_model_unknown(self):
        self.assertRaises(exception.UnsupportedTokenVersionException,
                          token_model.KeystoneToken,
                          token_id=uuid.uuid4().hex,
                          token_data={'bogus_data': uuid.uuid4().hex})

    def test_token_model_dual_scoped_token(self):
        domain = {'id': uuid.uuid4().hex,
                  'name': uuid.uuid4().hex}
        self.v3_sample_token['token']['domain'] = domain

        self.assertRaises(exception.UnexpectedError,
                          token_model.KeystoneToken,
                          token_id=uuid.uuid4().hex,
                          token_data=self.v3_sample_token)

    def test_token_model_is_admin_project(self):
        token_data = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                               token_data=self.v3_sample_token)

        token_data['is_admin_project'] = False
        self.assertFalse(token_data.is_admin_project)


class TokenModelTests(base_classes.TestCaseWithBootstrap):

    def setUp(self):
        super(TokenModelTests, self).setUp()
        self.admin_user_id = self.bootstrapper.admin_user_id
        self.admin_username = self.bootstrapper.admin_username
        self.admin_password = self.bootstrapper.admin_password
        self.project_id = self.bootstrapper.project_id
        self.project_name = self.bootstrapper.project_name
        self.admin_role_id = self.bootstrapper.admin_role_id
        self.member_role_id = self.bootstrapper.member_role_id
        self.reader_role_id = self.bootstrapper.reader_role_id

        self.token_id = uuid.uuid4().hex
        issued_at = datetime.datetime.utcnow()
        self.issued_at = ks_utils.isotime(at=issued_at, subsecond=True)

    def assertTokenContainsRole(self, token, role):
        """Ensure a role reference exists in a token's roles.

        :param token: instance of ``keystone.models.token_model.TokenModel``
        :param role: a dictionary reference of the expected role
        """
        self.assertIn(role, token.roles)

    def test_audit_id_attributes(self):
        token = token_model.TokenModel()
        audit_id = provider.random_urlsafe_str()
        token.audit_id = audit_id

        self.assertTrue(len(token.audit_ids) == 1)

        parent_audit_id = provider.random_urlsafe_str()
        token.parent_audit_id = parent_audit_id

        self.assertTrue(len(token.audit_ids) == 2)

        self.assertEqual(audit_id, token.audit_ids[0])
        self.assertEqual(parent_audit_id, token.audit_ids[-1])

    def test_token_model_user_attributes(self):
        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.user_domain_id = token.user['domain_id']

        self.assertEqual(self.admin_user_id, token.user_id)
        self.assertIsNotNone(token.user)
        self.assertIsNotNone(token.user_domain)
        self.assertEqual(self.admin_username, token.user['name'])
        self.assertEqual(CONF.identity.default_domain_id, token.user_domain_id)
        self.assertEqual(
            CONF.identity.default_domain_id, token.user_domain['id']
        )

    def test_mint_unscoped_token(self):
        token = token_model.TokenModel()
        token.user_id = self.admin_user_id

        token.mint(self.token_id, self.issued_at)

        self.assertTrue(token.unscoped)
        self.assertTrue(len(token.roles) == 0)

    def test_mint_system_scoped_token(self):
        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.system = {'all': True}

        token.mint(self.token_id, self.issued_at)

        self.assertTrue(token.system_scoped)
        self.assertFalse(token.domain_scoped)
        self.assertFalse(token.project_scoped)
        self.assertFalse(token.trust_scoped)
        self.assertFalse(token.unscoped)

        self.assertIsNotNone(token.system)
        self.assertTrue(len(token.roles) == 1)
        admin_role = {'id': self.admin_role_id, 'name': 'admin'}
        self.assertTokenContainsRole(token, admin_role)

    def test_mint_system_scoped_token_with_multiple_roles(self):
        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.system = {'all': True}

        self.assertTrue(token.system_scoped)
        self.assertFalse(token.domain_scoped)
        self.assertFalse(token.project_scoped)
        self.assertFalse(token.trust_scoped)
        self.assertFalse(token.unscoped)

        role = core.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        role.pop('domain_id')
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.admin_user_id, role['id']
        )

        self.assertIsNotNone(token.system)
        self.assertTrue(len(token.roles) == 2)
        admin_role = {'id': self.admin_role_id, 'name': 'admin'}
        self.assertTokenContainsRole(token, admin_role)
        self.assertTokenContainsRole(token, role)

    def test_mint_system_scoped_token_without_roles_fails(self):
        user = core.new_user_ref(CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)

        token = token_model.TokenModel()
        token.user_id = user['id']
        token.system = 'all'
        token.audit_id = provider.random_urlsafe_str()

        self.assertRaises(
            exception.Unauthorized, token.mint, self.token_id, self.issued_at
        )

    def test_mint_system_token_with_effective_role_assignment(self):
        user = core.new_user_ref(CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)

        group = core.new_group_ref(CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.admin_role_id
        )

        token = token_model.TokenModel()
        token.user_id = user['id']
        token.system = 'all'

        token.mint(self.token_id, self.issued_at)

        exp_role = {'id': self.admin_role_id, 'name': 'admin'}
        self.assertTokenContainsRole(token, exp_role)

    def test_mint_domain_scoped_token(self):
        PROVIDERS.assignment_api.create_grant(
            self.admin_role_id, user_id=self.admin_user_id,
            domain_id=CONF.identity.default_domain_id
        )

        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.domain_id = CONF.identity.default_domain_id

        token.mint(self.token_id, self.issued_at)

        self.assertTrue(token.domain_scoped)
        self.assertFalse(token.system_scoped)
        self.assertFalse(token.project_scoped)
        self.assertFalse(token.trust_scoped)
        self.assertFalse(token.unscoped)

        self.assertIsNotNone(token.domain)
        exp_domain = PROVIDERS.resource_api.get_domain(
            CONF.identity.default_domain_id
        )
        self.assertEqual(exp_domain['id'], token.domain_id)
        self.assertEqual(exp_domain['name'], token.domain['name'])

        self.assertTrue(len(token.roles) == 3)
        exp_roles = [
            {'id': self.admin_role_id, 'name': 'admin'},
            {'id': self.member_role_id, 'name': 'member'},
            {'id': self.reader_role_id, 'name': 'reader'}
        ]
        for role in exp_roles:
            self.assertTokenContainsRole(token, role)

    def test_mint_domain_scoped_token_fails_without_roles(self):
        user = core.new_user_ref(CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)

        token = token_model.TokenModel()
        token.user_id = user['id']
        token.domain_id = CONF.identity.default_domain_id
        token.audit_id = provider.random_urlsafe_str()

        self.assertRaises(
            exception.Unauthorized, token.mint, self.token_id, self.issued_at
        )

    def test_mint_project_scoped_token(self):
        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.project_id = self.project_id

        token.mint(self.token_id, self.issued_at)

        self.assertTrue(token.project_scoped)
        self.assertFalse(token.system_scoped)
        self.assertFalse(token.domain_scoped)
        self.assertFalse(token.trust_scoped)
        self.assertFalse(token.unscoped)

        self.assertIsNotNone(token.project)
        self.assertEqual(self.project_name, token.project['name'])

        self.assertTrue(len(token.roles) == 3)
        exp_roles = [
            {'id': self.admin_role_id, 'name': 'admin'},
            {'id': self.member_role_id, 'name': 'member'},
            {'id': self.reader_role_id, 'name': 'reader'}
        ]
        for role in exp_roles:
            self.assertTokenContainsRole(token, role)

    def test_mint_project_scoped_token_fails_without_roles(self):
        user = core.new_user_ref(CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)

        token = token_model.TokenModel()
        token.user_id = user['id']
        token.project_id = self.project_id
        token.audit_id = provider.random_urlsafe_str()

        self.assertRaises(
            exception.Unauthorized, token.mint, self.token_id, self.issued_at
        )

    def test_mint_project_scoped_token_fails_when_project_is_disabled(self):
        PROVIDERS.resource_api.update_project(
            self.project_id, {'enabled': False}
        )

        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.project_id = self.project_id
        token.audit_id = provider.random_urlsafe_str()

        self.assertRaises(
            exception.ProjectNotFound, token.mint, self.token_id,
            self.issued_at
        )

    def test_mint_project_scoped_token_fails_when_domain_is_disabled(self):
        project = PROVIDERS.resource_api.get_project(self.project_id)
        PROVIDERS.resource_api.update_domain(
            project['domain_id'], {'enabled': False}
        )

        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.project_id = self.project_id
        token.audit_id = provider.random_urlsafe_str()

        self.assertRaises(
            exception.DomainNotFound, token.mint, self.token_id, self.issued_at
        )

    def test_mint_application_credential_token(self):
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': 'monitoring-application',
            'user_id': self.admin_user_id,
            'roles': [{'id': self.admin_role_id}],
            'project_id': self.project_id,
            'secret': uuid.uuid4().hex
        }

        PROVIDERS.application_credential_api.create_application_credential(
            app_cred
        )

        token = token_model.TokenModel()
        token.user_id = self.admin_user_id
        token.application_credential_id = app_cred['id']
        token.project_id = self.project_id

        token.mint(self.token_id, self.issued_at)
        self.assertIsNotNone(token.application_credential_id)
        self.assertIsNotNone(token.application_credential)
        exp_role = {'id': self.admin_role_id, 'name': 'admin'}
        self.assertTokenContainsRole(token, exp_role)


class TrustScopedTokenModelTests(TokenModelTests):

    def setUp(self):
        super(TrustScopedTokenModelTests, self).setUp()

        trustor_domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, core.new_domain_ref()
        )
        trustee_domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, core.new_domain_ref()
        )

        self.trustor = PROVIDERS.identity_api.create_user(
            core.new_user_ref(trustor_domain['id'])
        )
        self.trustee = PROVIDERS.identity_api.create_user(
            core.new_user_ref(trustee_domain['id'])
        )

        PROVIDERS.assignment_api.create_grant(
            self.admin_role_id, user_id=self.trustor['id'],
            project_id=self.project_id
        )

    def test_mint_trust_scoped_token(self):
        roles = [{'id': self.admin_role_id}]
        trust = core.new_trust_ref(
            self.trustor['id'], self.trustee['id'], project_id=self.project_id
        )
        trust = PROVIDERS.trust_api.create_trust(trust['id'], trust, roles)

        token = token_model.TokenModel()
        token.trust_id = trust['id']
        token.user_id = self.trustee['id']

        token.mint(self.token_id, self.issued_at)

        self.assertEqual(self.trustee['id'], token.user_id)
        self.assertEqual(self.trustee['id'], token.trustee['id'])
        self.assertEqual(self.trustor['id'], token.trustor['id'])
        self.assertEqual(self.project_id, token.trust_project['id'])
        self.assertEqual(
            CONF.identity.default_domain_id, token.trust_project_domain['id']
        )
        # NOTE(lbragstad): The domain key here should be removed once
        # https://bugs.launchpad.net/keystone/+bug/1763510 is fixed.
        exp_role = {
            'id': self.admin_role_id, 'name': 'admin', 'domain_id': None
        }
        self.assertTokenContainsRole(token, exp_role)

    def test_mint_trust_scoped_token_fails_when_trustee_domain_disabled(self):
        roles = [{'id': self.admin_role_id}]
        trust = core.new_trust_ref(
            self.trustor['id'], self.trustee['id'], project_id=self.project_id
        )
        trust = PROVIDERS.trust_api.create_trust(trust['id'], trust, roles)

        PROVIDERS.resource_api.update_domain(
            self.trustee['domain_id'], {'enabled': False}
        )

        token = token_model.TokenModel()
        token.trust_id = trust['id']
        token.user_id = self.trustee['id']

        self.assertRaises(
            exception.TokenNotFound, token.mint, self.token_id, self.issued_at
        )

    def test_mint_trust_scoped_token_fails_when_trustor_domain_disabled(self):
        roles = [{'id': self.admin_role_id}]
        trust = core.new_trust_ref(
            self.trustor['id'], self.trustee['id'], project_id=self.project_id
        )
        trust = PROVIDERS.trust_api.create_trust(trust['id'], trust, roles)

        PROVIDERS.resource_api.update_domain(
            self.trustor['domain_id'], {'enabled': False}
        )

        token = token_model.TokenModel()
        token.trust_id = trust['id']
        token.user_id = self.trustee['id']

        self.assertRaises(
            exception.TokenNotFound, token.mint, self.token_id, self.issued_at
        )

    def test_mint_trust_scoped_token_fails_when_trustor_is_disabled(self):
        roles = [{'id': self.admin_role_id}]
        trust = core.new_trust_ref(
            self.trustor['id'], self.trustee['id'], project_id=self.project_id
        )
        trust = PROVIDERS.trust_api.create_trust(trust['id'], trust, roles)

        PROVIDERS.identity_api.update_user(
            self.trustor['id'], {'enabled': False}
        )

        token = token_model.TokenModel()
        token.trust_id = trust['id']
        token.user_id = self.trustee['id']

        self.assertRaises(
            exception.Forbidden, token.mint, self.token_id, self.issued_at
        )

    def test_mint_trust_scoped_token_with_mismatching_users_fails(self):
        user = core.new_user_ref(CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)

        roles = [{'id': self.admin_role_id}]
        trust = core.new_trust_ref(
            self.trustor['id'], self.trustee['id'], project_id=self.project_id
        )
        trust = PROVIDERS.trust_api.create_trust(trust['id'], trust, roles)

        token = token_model.TokenModel()
        token.trust_id = trust['id']
        token.user_id = user['id']

        self.assertRaises(
            exception.Forbidden, token.mint, self.token_id, self.issued_at
        )
