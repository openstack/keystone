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
import uuid

from oslo_config import cfg
from oslo_utils import timeutils
from six.moves import range

from keystone.contrib.federation import constants as federation_constants
from keystone import exception
from keystone.models import token_model
from keystone.tests.unit import core
from keystone.tests.unit import test_token_provider


CONF = cfg.CONF


class TestKeystoneTokenModel(core.TestCase):
    def setUp(self):
        super(TestKeystoneTokenModel, self).setUp()
        self.v2_sample_token = copy.deepcopy(
            test_token_provider.SAMPLE_V2_TOKEN)
        self.v3_sample_token = copy.deepcopy(
            test_token_provider.SAMPLE_V3_TOKEN)

    def test_token_model_v3(self):
        token_data = token_model.KeystoneToken(uuid.uuid4().hex,
                                               self.v3_sample_token)
        self.assertIs(token_model.V3, token_data.version)
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
        self.assertEqual(
            [r['id'] for r in self.v3_sample_token['token']['roles']],
            token_data.role_ids)
        self.assertEqual(
            [r['name'] for r in self.v3_sample_token['token']['roles']],
            token_data.role_names)
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

    def test_token_model_v2_federated_user(self):
        token_data = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                               token_data=self.v2_sample_token)
        federation_data = {'identity_provider': {'id': uuid.uuid4().hex},
                           'protocol': {'id': 'saml2'},
                           'groups': [{'id': uuid.uuid4().hex}
                                      for x in range(1, 5)]}
        self.assertFalse(token_data.is_federated_user)
        self.assertEqual([], token_data.federation_group_ids)
        self.assertIsNone(token_data.federation_protocol_id)
        self.assertIsNone(token_data.federation_idp_id)

        token_data['user'][federation_constants.FEDERATION] = federation_data

        # Federated users should not exist in V2, the data should remain empty
        self.assertFalse(token_data.is_federated_user)
        self.assertEqual([], token_data.federation_group_ids)
        self.assertIsNone(token_data.federation_protocol_id)
        self.assertIsNone(token_data.federation_idp_id)

    def test_token_model_v2(self):
        token_data = token_model.KeystoneToken(uuid.uuid4().hex,
                                               self.v2_sample_token)
        self.assertIs(token_model.V2, token_data.version)
        expires = timeutils.normalize_time(timeutils.parse_isotime(
            self.v2_sample_token['access']['token']['expires']))
        issued = timeutils.normalize_time(timeutils.parse_isotime(
            self.v2_sample_token['access']['token']['issued_at']))
        self.assertEqual(expires, token_data.expires)
        self.assertEqual(issued, token_data.issued)
        self.assertEqual(self.v2_sample_token['access']['user']['id'],
                         token_data.user_id)
        self.assertEqual(self.v2_sample_token['access']['user']['name'],
                         token_data.user_name)
        self.assertEqual(CONF.identity.default_domain_id,
                         token_data.user_domain_id)
        self.assertEqual('Default', token_data.user_domain_name)
        self.assertEqual(CONF.identity.default_domain_id,
                         token_data.project_domain_id)
        self.assertEqual('Default',
                         token_data.project_domain_name)
        self.assertEqual(self.v2_sample_token['access']['trust']['id'],
                         token_data.trust_id)
        self.assertEqual(
            self.v2_sample_token['access']['trust']['trustor_user_id'],
            token_data.trustor_user_id)
        self.assertEqual(
            self.v2_sample_token['access']['trust']['impersonation'],
            token_data.trust_impersonation)
        self.assertEqual(
            self.v2_sample_token['access']['trust']['trustee_user_id'],
            token_data.trustee_user_id)
        # Project Scoped Token
        self.assertEqual(
            self.v2_sample_token['access']['token']['tenant']['id'],
            token_data.project_id)
        self.assertEqual(
            self.v2_sample_token['access']['token']['tenant']['name'],
            token_data.project_name)
        self.assertTrue(token_data.project_scoped)
        self.assertTrue(token_data.scoped)
        self.assertTrue(token_data.trust_scoped)
        self.assertEqual(
            [r['name']
             for r in self.v2_sample_token['access']['user']['roles']],
            token_data.role_names)
        token_data['token'].pop('tenant')
        self.assertFalse(token_data.scoped)
        self.assertFalse(token_data.project_scoped)
        self.assertFalse(token_data.domain_scoped)
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'project_id')
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'project_name')
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'project_domain_id')
        self.assertRaises(exception.UnexpectedError, getattr, token_data,
                          'project_domain_id')
        # No Domain Scoped tokens in V2
        self.assertRaises(NotImplementedError, getattr, token_data,
                          'domain_id')
        self.assertRaises(NotImplementedError, getattr, token_data,
                          'domain_name')
        token_data['domain'] = {'id': uuid.uuid4().hex,
                                'name': uuid.uuid4().hex}
        self.assertRaises(NotImplementedError, getattr, token_data,
                          'domain_id')
        self.assertRaises(NotImplementedError, getattr, token_data,
                          'domain_name')
        self.assertFalse(token_data.domain_scoped)

        token_data['token']['audit_ids'] = [uuid.uuid4().hex]
        self.assertEqual(token_data.audit_chain_id,
                         token_data['token']['audit_ids'][0])
        token_data['token']['audit_ids'].append(uuid.uuid4().hex)
        self.assertEqual(token_data.audit_chain_id,
                         token_data['token']['audit_ids'][1])
        self.assertEqual(token_data.audit_id,
                         token_data['token']['audit_ids'][0])
        del token_data['token']['audit_ids']
        self.assertIsNone(token_data.audit_id)
        self.assertIsNone(token_data.audit_chain_id)

    def test_token_model_unknown(self):
        self.assertRaises(exception.UnsupportedTokenVersionException,
                          token_model.KeystoneToken,
                          token_id=uuid.uuid4().hex,
                          token_data={'bogus_data': uuid.uuid4().hex})

    def test_token_model_dual_scoped_token(self):
        domain = {'id': uuid.uuid4().hex,
                  'name': uuid.uuid4().hex}
        self.v2_sample_token['access']['domain'] = domain
        self.v3_sample_token['token']['domain'] = domain

        # V2 Tokens Cannot be domain scoped, this should work
        token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                  token_data=self.v2_sample_token)

        self.assertRaises(exception.UnexpectedError,
                          token_model.KeystoneToken,
                          token_id=uuid.uuid4().hex,
                          token_data=self.v3_sample_token)
