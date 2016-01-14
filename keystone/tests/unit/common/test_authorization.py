# Copyright 2015 IBM Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import copy
import uuid

from keystone.common import authorization
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.models import token_model
from keystone.tests import unit
from keystone.tests.unit import test_token_provider


class TestTokenToAuthContext(unit.BaseTestCase):
    def test_token_is_project_scoped_with_trust(self):
        # Check auth_context result when the token is project-scoped and has
        # trust info.

        # SAMPLE_V3_TOKEN has OS-TRUST:trust in it.
        token_data = test_token_provider.SAMPLE_V3_TOKEN
        token = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                          token_data=token_data)

        auth_context = authorization.token_to_auth_context(token)

        self.assertEqual(token, auth_context['token'])
        self.assertTrue(auth_context['is_delegated_auth'])
        self.assertEqual(token_data['token']['user']['id'],
                         auth_context['user_id'])
        self.assertEqual(token_data['token']['user']['domain']['id'],
                         auth_context['user_domain_id'])
        self.assertEqual(token_data['token']['project']['id'],
                         auth_context['project_id'])
        self.assertEqual(token_data['token']['project']['domain']['id'],
                         auth_context['project_domain_id'])
        self.assertNotIn('domain_id', auth_context)
        self.assertNotIn('domain_name', auth_context)
        self.assertEqual(token_data['token']['OS-TRUST:trust']['id'],
                         auth_context['trust_id'])
        self.assertEqual(
            token_data['token']['OS-TRUST:trust']['trustor_user_id'],
            auth_context['trustor_id'])
        self.assertEqual(
            token_data['token']['OS-TRUST:trust']['trustee_user_id'],
            auth_context['trustee_id'])
        self.assertItemsEqual(
            [r['name'] for r in token_data['token']['roles']],
            auth_context['roles'])
        self.assertIsNone(auth_context['consumer_id'])
        self.assertIsNone(auth_context['access_token_id'])
        self.assertNotIn('group_ids', auth_context)

    def test_token_is_domain_scoped(self):
        # Check contents of auth_context when token is domain-scoped.
        token_data = copy.deepcopy(test_token_provider.SAMPLE_V3_TOKEN)
        del token_data['token']['project']

        domain_id = uuid.uuid4().hex
        domain_name = uuid.uuid4().hex
        token_data['token']['domain'] = {'id': domain_id, 'name': domain_name}

        token = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                          token_data=token_data)

        auth_context = authorization.token_to_auth_context(token)

        self.assertNotIn('project_id', auth_context)
        self.assertNotIn('project_domain_id', auth_context)

        self.assertEqual(domain_id, auth_context['domain_id'])
        self.assertEqual(domain_name, auth_context['domain_name'])

    def test_token_is_unscoped(self):
        # Check contents of auth_context when the token is unscoped.
        token_data = copy.deepcopy(test_token_provider.SAMPLE_V3_TOKEN)
        del token_data['token']['project']

        token = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                          token_data=token_data)

        auth_context = authorization.token_to_auth_context(token)

        self.assertNotIn('project_id', auth_context)
        self.assertNotIn('project_domain_id', auth_context)
        self.assertNotIn('domain_id', auth_context)
        self.assertNotIn('domain_name', auth_context)

    def test_token_is_for_federated_user(self):
        # When the token is for a federated user then group_ids is in
        # auth_context.
        token_data = copy.deepcopy(test_token_provider.SAMPLE_V3_TOKEN)

        group_ids = [uuid.uuid4().hex for x in range(1, 5)]

        federation_data = {'identity_provider': {'id': uuid.uuid4().hex},
                           'protocol': {'id': 'saml2'},
                           'groups': [{'id': gid} for gid in group_ids]}
        token_data['token']['user'][federation_constants.FEDERATION] = (
            federation_data)

        token = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                          token_data=token_data)

        auth_context = authorization.token_to_auth_context(token)

        self.assertItemsEqual(group_ids, auth_context['group_ids'])

    def test_oauth_variables_set_for_oauth_token(self):
        token_data = copy.deepcopy(test_token_provider.SAMPLE_V3_TOKEN)
        access_token_id = uuid.uuid4().hex
        consumer_id = uuid.uuid4().hex
        token_data['token']['OS-OAUTH1'] = {'access_token_id': access_token_id,
                                            'consumer_id': consumer_id}
        token = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                          token_data=token_data)

        auth_context = authorization.token_to_auth_context(token)

        self.assertEqual(access_token_id, auth_context['access_token_id'])
        self.assertEqual(consumer_id, auth_context['consumer_id'])

    def test_oauth_variables_not_set(self):
        token_data = copy.deepcopy(test_token_provider.SAMPLE_V3_TOKEN)
        token = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                          token_data=token_data)

        auth_context = authorization.token_to_auth_context(token)

        self.assertIsNone(auth_context['access_token_id'])
        self.assertIsNone(auth_context['consumer_id'])

    def test_token_is_not_KeystoneToken_raises_exception(self):
        # If the token isn't a KeystoneToken then an UnexpectedError exception
        # is raised.
        self.assertRaises(exception.UnexpectedError,
                          authorization.token_to_auth_context, {})

    def test_user_id_missing_in_token_raises_exception(self):
        # If there's no user ID in the token then an Unauthorized
        # exception is raised.
        token_data = copy.deepcopy(test_token_provider.SAMPLE_V3_TOKEN)
        del token_data['token']['user']['id']

        token = token_model.KeystoneToken(token_id=uuid.uuid4().hex,
                                          token_data=token_data)

        self.assertRaises(exception.Unauthorized,
                          authorization.token_to_auth_context, token)
