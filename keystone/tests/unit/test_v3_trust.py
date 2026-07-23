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

import http.client
from unittest import mock
import urllib
import uuid

import flask

from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_utils import timeutils

from keystone.api._shared import delegation
from keystone.api import trusts as trusts_api
from keystone.common import authorization
from keystone.common import context
from keystone.common import provider_api
import keystone.conf
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone import oauth1
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_v3

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TestTrustOperations(test_v3.RestfulTestCase):
    """Test module for create, read, update and delete operations on trusts.

    This module is specific to tests for trust CRUD operations. All other tests
    related to trusts that are authentication or authorization specific should
    live in the keystone/tests/unit/test_v3_auth.py module.

    """

    def setUp(self):
        super().setUp()
        # create a trustee to delegate stuff to
        self.trustee_user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        self.trustee_user_id = self.trustee_user['id']

    def test_create_trust_bad_request(self):
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': {}},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_create_trust_with_invalid_expiration_fails(self):
        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )

        ref['expires_at'] = 'bad'
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

        ref['expires_at'] = ''
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

        ref['expires_at'] = 'Z'
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_trusts_do_not_implement_updates(self):
        with self.test_client() as c:
            # create a new trust
            token = self.get_scoped_token()
            ref = unit.new_trust_ref(
                trustor_user_id=self.user_id,
                trustee_user_id=self.trustee_user_id,
                project_id=self.project_id,
                role_ids=[self.role_id],
            )
            r = c.post(
                '/v3/OS-TRUST/trusts',
                json={'trust': ref},
                headers={'X-Auth-Token': token},
            )
            trust_id = r.json['trust']['id']
            c.patch(
                f'/v3/OS-TRUST/trusts/{trust_id}',
                json={'trust': ref},
                headers={'X-Auth-Token': token},
                expected_status_code=http.client.METHOD_NOT_ALLOWED,
            )
            c.put(
                f'/v3/OS-TRUST/trusts/{trust_id}',
                json={'trust': ref},
                headers={'X-Auth-Token': token},
                expected_status_code=http.client.METHOD_NOT_ALLOWED,
            )

    def test_trust_crud(self):
        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        # get the trust
        r = self.get(
            '/OS-TRUST/trusts/{trust_id}'.format(trust_id=trust['id'])
        )
        self.assertValidTrustResponse(r, ref)

        # validate roles on the trust
        r = self.get(
            '/OS-TRUST/trusts/{trust_id}/roles'.format(trust_id=trust['id'])
        )
        roles = self.assertValidRoleListResponse(r, self.role)
        self.assertIn(self.role['id'], [x['id'] for x in roles])
        self.head(
            '/OS-TRUST/trusts/{trust_id}/roles/{role_id}'.format(
                trust_id=trust['id'], role_id=self.role['id']
            ),
            expected_status=http.client.OK,
        )
        r = self.get(
            '/OS-TRUST/trusts/{trust_id}/roles/{role_id}'.format(
                trust_id=trust['id'], role_id=self.role['id']
            )
        )
        self.assertValidRoleResponse(r, self.role)

        # list all trusts
        r = self.get('/OS-TRUST/trusts')
        self.assertValidTrustListResponse(r, trust)

        # delete the trust
        self.delete('/OS-TRUST/trusts/{trust_id}'.format(trust_id=trust['id']))

        # ensure the trust is not found
        self.get(
            '/OS-TRUST/trusts/{trust_id}'.format(trust_id=trust['id']),
            expected_status=http.client.NOT_FOUND,
        )

    def test_list_trusts(self):
        # create three trusts with the same trustor and trustee
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires={'minutes': 1},
            role_ids=[self.role_id],
        )
        for i in range(3):
            ref['expires_at'] = (
                timeutils.utcnow()
                .replace(year=2032)
                .strftime(unit.TIME_FORMAT)
            )
            r = self.post('/OS-TRUST/trusts', body={'trust': ref})
            self.assertValidTrustResponse(r, ref)

        # list all trusts
        list_url = '/OS-TRUST/trusts'
        r = self.get(list_url)
        self.head(list_url, expected_status=http.client.OK)
        trusts = r.result['trusts']
        self.assertEqual(3, len(trusts))
        self.assertValidTrustListResponse(r)

        # list all trusts for the trustor
        list_for_trustor_url = (
            f'/OS-TRUST/trusts?trustor_user_id={self.user_id}'
        )
        r = self.get(list_for_trustor_url)
        self.head(list_for_trustor_url, expected_status=http.client.OK)
        trusts = r.result['trusts']
        self.assertEqual(3, len(trusts))
        self.assertValidTrustListResponse(r)

        # list all trusts for trustee as the trustor
        list_as_trustor_url = (
            f'/OS-TRUST/trusts?trustee_user_id={self.user_id}'
        )
        r = self.get(list_as_trustor_url)
        self.head(list_as_trustor_url, expected_status=http.client.OK)
        trusts = r.result['trusts']
        self.assertEqual(0, len(trusts))

        # list all trusts as the trustee is forbidden
        # FIXME(dmendiza): This test is not written to do what the above
        # comment says it should be doing. The main issue is that it's
        # still using the trustor credentiasl to make the request.
        # list_all_as_trustee_url = (
        #     '/OS-TRUST/trusts?trustee_user_id=%s' % self.trustee_user_id
        # )
        # r = self.get(
        #     list_all_as_trustee_url,
        #     expected_status=http.client.FORBIDDEN
        # )
        # self.head(
        #     list_all_as_trustee_url,
        #     expected_status=http.client.FORBIDDEN
        # )

    def test_create_trust_with_expiration_in_the_past_fails(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires='2010-06-04T08:44:31.999999Z',
            role_ids=[self.role_id],
        )

        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_delete_trust(self):
        # create a trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires={'minutes': 1},
            role_ids=[self.role_id],
        )
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        # delete the trust
        self.delete('/OS-TRUST/trusts/{trust_id}'.format(trust_id=trust['id']))

        # ensure the trust isn't found
        self.get(
            '/OS-TRUST/trusts/{trust_id}'.format(trust_id=trust['id']),
            expected_status=http.client.NOT_FOUND,
        )

    def test_create_trust_without_trustee_returns_bad_request(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )

        # trustee_user_id is required to create a trust
        del ref['trustee_user_id']

        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_create_trust_without_impersonation_returns_bad_request(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )

        # impersonation is required to create a trust
        del ref['impersonation']

        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_create_trust_with_bad_remaining_uses_returns_bad_request(self):
        # negative numbers, strings, non-integers, and 0 are not value values
        for value in [-1, 0, "a bad value", 7.2]:
            ref = unit.new_trust_ref(
                trustor_user_id=self.user_id,
                trustee_user_id=self.trustee_user_id,
                project_id=self.project_id,
                remaining_uses=value,
                role_ids=[self.role_id],
            )
            self.post(
                '/OS-TRUST/trusts',
                body={'trust': ref},
                expected_status=http.client.BAD_REQUEST,
            )

    def test_create_trust_with_non_existant_trustee_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=uuid.uuid4().hex,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.NOT_FOUND,
        )

    def test_create_trust_with_trustee_as_trustor_returns_forbidden(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=self.user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        # NOTE(lbragstad): This fails because the user making the request isn't
        # the trustor defined in the request.
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.FORBIDDEN,
        )

    def test_create_trust_with_non_existant_project_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=uuid.uuid4().hex,
            role_ids=[self.role_id],
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.NOT_FOUND,
        )

    def test_create_trust_with_non_existant_role_id_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[uuid.uuid4().hex],
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.NOT_FOUND,
        )

    def test_create_trust_with_extra_attributes_fails(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        ref['roles'].append({'fake_key': 'fake_value'})

        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_create_trust_with_non_existant_role_name_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_names=[uuid.uuid4().hex],
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.NOT_FOUND,
        )

    def test_create_trust_with_role_name_ambiguous_returns_bad_request(self):
        # Create second role with the same name
        role_ref = unit.new_role_ref(
            name=self.role['name'], domain_id=uuid.uuid4().hex
        )
        self.post('/roles', body={'role': role_ref})

        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_names=[self.role['name']],
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_exercise_trust_scoped_token_without_impersonation(self):
        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires={'minutes': 1},
            role_ids=[self.role_id],
        )
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(resp)

        # get a trust-scoped token as the trustee
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'],
        )
        resp = self.v3_create_token(auth_data)
        resp_body = resp.json_body['token']

        self.assertValidProjectScopedTokenResponse(resp, self.trustee_user)
        self.assertEqual(self.trustee_user['id'], resp_body['user']['id'])
        self.assertEqual(self.trustee_user['name'], resp_body['user']['name'])
        self.assertEqual(self.domain['id'], resp_body['user']['domain']['id'])
        self.assertEqual(
            self.domain['name'], resp_body['user']['domain']['name']
        )
        self.assertEqual(self.project['id'], resp_body['project']['id'])
        self.assertEqual(self.project['name'], resp_body['project']['name'])

    def test_exercise_trust_scoped_token_with_impersonation(self):
        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires={'minutes': 1},
            role_ids=[self.role_id],
        )
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(resp)

        # get a trust-scoped token as the trustee
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'],
        )
        resp = self.v3_create_token(auth_data)
        resp_body = resp.json_body['token']

        self.assertValidProjectScopedTokenResponse(resp, self.user)
        self.assertEqual(self.user['id'], resp_body['user']['id'])
        self.assertEqual(self.user['name'], resp_body['user']['name'])
        self.assertEqual(self.domain['id'], resp_body['user']['domain']['id'])
        self.assertEqual(
            self.domain['name'], resp_body['user']['domain']['name']
        )
        self.assertEqual(self.project['id'], resp_body['project']['id'])
        self.assertEqual(self.project['name'], resp_body['project']['name'])

    def test_forbidden_trust_impersonation_in_redelegation(self):
        """Test forbiddance of impersonation in trust redelegation.

        Check that trustee not allowed to create a trust (with impersonation
        set to true) from a redelegated trust (with impersonation set to false)
        """
        # create trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            role_ids=[self.role_id],
            allow_redelegation=True,
        )
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user_id,
            password=self.trustee_user['password'],
            trust_id=trust['id'],
        )
        resp = self.v3_create_token(auth_data)

        # create third-party user, which will be trustee in trust created from
        # redelegated trust
        third_party_trustee = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        third_party_trustee_id = third_party_trustee['id']

        # create trust from redelegated trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=third_party_trustee_id,
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id],
        )
        ref['redelegated_trust_id'] = trust['id']
        self.admin_request(
            path='/v3/OS-TRUST/trusts',
            body={'trust': ref},
            token=resp.headers.get('X-Subject-Token'),
            method='POST',
            expected_status=http.client.FORBIDDEN,
        )

    def test_trust_deleted_when_user_deleted(self):
        # create trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            role_ids=[self.role_id],
            allow_redelegation=True,
        )
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)

        # list all trusts
        r = self.get('/OS-TRUST/trusts')
        self.assertEqual(1, len(r.result['trusts']))

        # delete the trustee will delete the trust
        self.delete(
            '/users/{user_id}'.format(user_id=trust['trustee_user_id'])
        )

        self.get(
            '/OS-TRUST/trusts/{trust_id}'.format(trust_id=trust['id']),
            expected_status=http.client.NOT_FOUND,
        )

        # create another user as the new trustee
        trustee_user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        trustee_user_id = trustee_user['id']
        # create the trust again
        ref['trustee_user_id'] = trustee_user_id
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)
        r = self.get('/OS-TRUST/trusts')
        self.assertEqual(1, len(r.result['trusts']))

        # delete the trustor will delete the trust
        self.delete(
            '/users/{user_id}'.format(user_id=trust['trustor_user_id'])
        )

        # call the backend method directly to bypass authentication since the
        # user has been deleted.
        self.assertRaises(
            exception.TrustNotFound, PROVIDERS.trust_api.get_trust, trust['id']
        )

    def test_trust_deleted_when_project_deleted(self):
        # create trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            role_ids=[self.role_id],
            allow_redelegation=True,
        )
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)

        # list all trusts
        r = self.get('/OS-TRUST/trusts')
        self.assertEqual(1, len(r.result['trusts']))

        # delete the project will delete the trust.
        self.delete(
            '/projects/{project_id}'.format(project_id=trust['project_id'])
        )

        # call the backend method directly to bypass authentication since the
        # user no longer has the assignment on the project.
        self.assertRaises(
            exception.TrustNotFound, PROVIDERS.trust_api.get_trust, trust['id']
        )


class TrustsWithApplicationCredentials(test_v3.RestfulTestCase):
    def setUp(self):
        super().setUp()
        self.trustee_user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        self.trustee_user_id = self.trustee_user['id']

    def config_overrides(self):
        super().config_overrides()
        self.config_fixture.config(
            group='auth', methods='password,application_credential'
        )

    def test_create_trust_with_application_credential(self):
        app_cred = {
            'id': uuid.uuid4().hex,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'name': uuid.uuid4().hex,
            'roles': [{'id': self.role_id}],
            'secret': uuid.uuid4().hex,
        }
        app_cred_api = PROVIDERS.application_credential_api
        app_cred_api.create_application_credential(app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred['id'], secret=app_cred['secret']
        )
        token_data = self.v3_create_token(
            auth_data, expected_status=http.client.CREATED
        )
        trust_body = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        self.post(
            path='/OS-TRUST/trusts',
            body={'trust': trust_body},
            token=token_data.headers['x-subject-token'],
            expected_status=http.client.FORBIDDEN,
        )

    def _get_app_cred_token(self, unrestricted=False):
        app_cred = {
            'id': uuid.uuid4().hex,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'name': uuid.uuid4().hex,
            'roles': [{'id': self.role_id}],
            'secret': uuid.uuid4().hex,
        }
        if unrestricted:
            app_cred['unrestricted'] = True
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred
        )
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred['id'], secret=app_cred['secret']
        )
        r = self.v3_create_token(
            auth_data, expected_status=http.client.CREATED
        )
        return r.headers['x-subject-token']

    def test_create_trust_with_unrestricted_application_credential(self):
        """Unrestricted app cred must also be blocked from creating trusts."""
        trust_body = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': trust_body},
            token=self._get_app_cred_token(unrestricted=True),
            expected_status=http.client.FORBIDDEN,
        )

    def test_list_trusts_with_application_credential(self):
        """App cred token must not be able to list trusts."""
        self.get(
            '/OS-TRUST/trusts',
            token=self._get_app_cred_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_get_trust_with_application_credential(self):
        """App cred token must not be able to read a specific trust."""
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust_id = r.result['trust']['id']
        self.get(
            f'/OS-TRUST/trusts/{trust_id}',
            token=self._get_app_cred_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_list_trust_roles_with_application_credential(self):
        """App cred token must not be able to list roles for a trust."""
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust_id = r.result['trust']['id']
        self.get(
            f'/OS-TRUST/trusts/{trust_id}/roles',
            token=self._get_app_cred_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_get_trust_role_with_application_credential(self):
        """App cred token must not be able to get a specific trust role."""
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust_id = r.result['trust']['id']
        self.get(
            f'/OS-TRUST/trusts/{trust_id}/roles/{self.role_id}',
            token=self._get_app_cred_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_delete_trust_with_application_credential(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires={'minutes': 1},
            role_ids=[self.role_id],
        )
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        app_cred = {
            'id': uuid.uuid4().hex,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'name': uuid.uuid4().hex,
            'roles': [{'id': self.role_id}],
            'secret': uuid.uuid4().hex,
        }
        app_cred_api = PROVIDERS.application_credential_api
        app_cred_api.create_application_credential(app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred['id'], secret=app_cred['secret']
        )
        token_data = self.v3_create_token(
            auth_data, expected_status=http.client.CREATED
        )
        # delete the trust
        self.delete(
            path='/OS-TRUST/trusts/{trust_id}'.format(trust_id=trust['id']),
            token=token_data.headers['x-subject-token'],
            expected_status=http.client.FORBIDDEN,
        )


class TrustsWithOtherDelegatedTokens(test_v3.RestfulTestCase):
    """OAuth1 access-token and ec2credential tokens must not manage trusts.

    Mirrors TrustsWithApplicationCredentials, closing the gap identified
    in LP#2153453 comments #9-10 ("EC2 tokens can still create trusts and
    authorize OAuth1") that was never actually fixed for either token
    type in this file.
    """

    def setUp(self):
        super().setUp()
        self.trustee_user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        self.trustee_user_id = self.trustee_user['id']
        self.base_url = 'http://localhost/v3'
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS,
            )
        )

    def _make_trust_ref(self):
        return unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id],
        )

    def _get_ec2_token(self):
        blob, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=self.project_id
        )
        self.post('/credentials', body={'credential': ref})
        signer = ec2_utils.Ec2Signer(blob['secret'])
        params = {
            'SignatureMethod': 'HmacSHA256',
            'SignatureVersion': '2',
            'AWSAccessKeyId': blob['access'],
        }
        request = {
            'host': 'foo',
            'verb': 'GET',
            'path': '/bar',
            'params': params,
        }
        sig_ref = {
            'access': blob['access'],
            'signature': signer.generate(request),
            'host': 'foo',
            'verb': 'GET',
            'path': '/bar',
            'params': params,
        }
        r = self.post(
            '/ec2tokens',
            body={'ec2Credentials': sig_ref},
            expected_status=http.client.OK,
        )
        return r.headers.get('X-Subject-Token')

    def _urllib_parse_qs_text_keys(self, content):
        results = urllib.parse.parse_qs(content)
        return {key.decode('utf-8'): value for key, value in results.items()}

    def _create_single_consumer(self):
        ref = {'description': uuid.uuid4().hex}
        resp = self.post('/OS-OAUTH1/consumers', body={'consumer': ref})
        return resp.result['consumer']

    def _create_request_token(self, consumer, project_id):
        endpoint = '/OS-OAUTH1/request_token'
        client = oauth1.Client(
            consumer['key'],
            client_secret=consumer['secret'],
            signature_method=oauth1.SIG_HMAC,
            callback_uri='oob',
        )
        headers = {'requested_project_id': project_id}
        url, headers, body = client.sign(
            self.base_url + endpoint, http_method='POST', headers=headers
        )
        return endpoint, headers

    def _create_access_token(self, consumer, token):
        endpoint = '/OS-OAUTH1/access_token'
        client = oauth1.Client(
            consumer['key'],
            client_secret=consumer['secret'],
            resource_owner_key=token.key,
            resource_owner_secret=token.secret,
            signature_method=oauth1.SIG_HMAC,
            verifier=token.verifier,
        )
        url, headers, body = client.sign(
            self.base_url + endpoint, http_method='POST'
        )
        headers.update({'Content-Type': 'application/json'})
        return endpoint, headers

    def _get_oauth_token_request(self, consumer, token):
        client = oauth1.Client(
            consumer['key'],
            client_secret=consumer['secret'],
            resource_owner_key=token.key,
            resource_owner_secret=token.secret,
            signature_method=oauth1.SIG_HMAC,
        )
        endpoint = '/auth/tokens'
        url, headers, body = client.sign(
            self.base_url + endpoint, http_method='POST'
        )
        headers.update({'Content-Type': 'application/json'})
        ref = {'auth': {'identity': {'oauth1': {}, 'methods': ['oauth1']}}}
        return endpoint, headers, ref

    def _authorize_request_token(self, request_id):
        if isinstance(request_id, bytes):
            request_id = request_id.decode()
        return f'/OS-OAUTH1/authorize/{request_id}'

    def _get_oauth1_token(self):
        consumer = self._create_single_consumer()
        consumer = {'key': consumer['id'], 'secret': consumer['secret']}

        url, headers = self._create_request_token(consumer, self.project_id)
        content = self.post(
            url,
            headers=headers,
            response_content_type='application/x-www-form-urlencoded',
        )
        credentials = self._urllib_parse_qs_text_keys(content.result)
        request_key = credentials['oauth_token'][0]
        request_secret = credentials['oauth_token_secret'][0]
        request_token = oauth1.Token(request_key, request_secret)

        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        resp = self.put(url, body=body, expected_status=http.client.OK)
        verifier = resp.result['token']['oauth_verifier']

        request_token.set_verifier(verifier)
        url, headers = self._create_access_token(consumer, request_token)
        content = self.post(
            url,
            headers=headers,
            response_content_type='application/x-www-form-urlencoded',
        )
        credentials = self._urllib_parse_qs_text_keys(content.result)
        access_key = credentials['oauth_token'][0]
        access_secret = credentials['oauth_token_secret'][0]
        access_token = oauth1.Token(access_key, access_secret)

        url, headers, body = self._get_oauth_token_request(
            consumer, access_token
        )
        content = self.post(url, headers=headers, body=body)
        return content.headers['X-Subject-Token']

    def test_create_trust_with_ec2_token(self):
        """An ec2credential token must not be able to create a trust."""
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': self._make_trust_ref()},
            token=self._get_ec2_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_list_trusts_with_ec2_token(self):
        """An ec2credential token must not be able to list trusts."""
        self.get(
            '/OS-TRUST/trusts',
            token=self._get_ec2_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_get_trust_with_ec2_token(self):
        """An ec2credential token must not be able to read a trust."""
        r = self.post(
            '/OS-TRUST/trusts', body={'trust': self._make_trust_ref()}
        )
        trust_id = r.result['trust']['id']
        self.get(
            f'/OS-TRUST/trusts/{trust_id}',
            token=self._get_ec2_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_delete_trust_with_ec2_token(self):
        """An ec2credential token must not be able to delete a trust."""
        r = self.post(
            '/OS-TRUST/trusts', body={'trust': self._make_trust_ref()}
        )
        trust_id = r.result['trust']['id']
        self.delete(
            f'/OS-TRUST/trusts/{trust_id}',
            token=self._get_ec2_token(),
            expected_status=http.client.FORBIDDEN,
        )
        self.get(
            f'/OS-TRUST/trusts/{trust_id}', expected_status=http.client.OK
        )

    def test_create_trust_with_oauth1_token(self):
        """An OAuth1 access-token-scoped token must not create a trust.

        Without the delegation-boundary check, this still ends up 403
        today -- but only by accident, via _find_redelegated_trust()'s
        unrelated "delegated by trust only" check (OAuth-scoped tokens are
        also flagged is_delegated_auth). Assert the specific message so
        this test actually exercises the delegation-boundary check.
        """
        r = self.post(
            '/OS-TRUST/trusts',
            body={'trust': self._make_trust_ref()},
            token=self._get_oauth1_token(),
            expected_status=http.client.FORBIDDEN,
        )
        self.assertIn(
            'Delegated tokens cannot manage trusts',
            r.result['error']['message'],
        )

    def test_list_trusts_with_oauth1_token(self):
        """An OAuth1 access-token-scoped token must not list trusts."""
        self.get(
            '/OS-TRUST/trusts',
            token=self._get_oauth1_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_get_trust_with_oauth1_token(self):
        """An OAuth1 access-token-scoped token must not read a trust."""
        r = self.post(
            '/OS-TRUST/trusts', body={'trust': self._make_trust_ref()}
        )
        trust_id = r.result['trust']['id']
        self.get(
            f'/OS-TRUST/trusts/{trust_id}',
            token=self._get_oauth1_token(),
            expected_status=http.client.FORBIDDEN,
        )

    def test_delete_trust_with_oauth1_token(self):
        """An OAuth1 access-token-scoped token must not delete a trust."""
        r = self.post(
            '/OS-TRUST/trusts', body={'trust': self._make_trust_ref()}
        )
        trust_id = r.result['trust']['id']
        self.delete(
            f'/OS-TRUST/trusts/{trust_id}',
            token=self._get_oauth1_token(),
            expected_status=http.client.FORBIDDEN,
        )
        self.get(
            f'/OS-TRUST/trusts/{trust_id}', expected_status=http.client.OK
        )

    def test_escape_hatch_does_not_extend_to_oauth1_or_ec2(self):
        """allow_insecure_application_credential_trust_escalation is app-cred-only.

        Enabling it must not exempt oauth1 or ec2credential tokens from
        the trust-management block -- only application_credential has a
        documented use case for this escape hatch.
        """
        self.config_fixture.config(
            group='security_compliance',
            allow_insecure_application_credential_trust_escalation=True,
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': self._make_trust_ref()},
            token=self._get_ec2_token(),
            expected_status=http.client.FORBIDDEN,
        )
        self.post(
            '/OS-TRUST/trusts',
            body={'trust': self._make_trust_ref()},
            token=self._get_oauth1_token(),
            expected_status=http.client.FORBIDDEN,
        )


class TestTrustGuardUnit(unit.BaseTestCase):
    """Unit-level tests for _check_delegated_token (LP#2153453).

    Calls the guard directly with a stub Flask request context,
    independent of HTTP request handling or the auth middleware. Matters
    for ec2credential specifically: an unrelated, already-landed fix bans
    ec2credential-method tokens at the auth middleware layer before this
    guard ever runs, so an HTTP-level test would pass regardless of
    whether the guard itself recognizes ec2credential as delegated. It
    also matters for oauth1, since _find_redelegated_trust()'s unrelated
    "delegated by trust only" check happens to also reject oauth1-scoped
    trust creation, masking whether this guard's own check fires.
    """

    def _check(self, methods, trust_id=None, escape_hatch=False):
        CONF.set_override(
            'allow_insecure_application_credential_trust_escalation',
            escape_hatch,
            group='security_compliance',
        )
        self.addCleanup(
            CONF.clear_override,
            'allow_insecure_application_credential_trust_escalation',
            group='security_compliance',
        )
        app = flask.Flask('test-trusts-guard')
        with app.test_request_context('/'):
            token = mock.Mock()
            token.methods = methods
            oslo_context = mock.Mock()
            oslo_context.trust_id = trust_id
            flask.request.environ[authorization.AUTH_CONTEXT_ENV] = {
                'token': token
            }
            flask.request.environ[context.REQUEST_CONTEXT_ENV] = oslo_context
            trusts_api._check_delegated_token()

    def test_rejects_ec2credential_token(self):
        self.assertRaises(
            exception.ForbiddenAction, self._check, ['ec2credential']
        )

    def test_rejects_oauth1_token(self):
        self.assertRaises(exception.ForbiddenAction, self._check, ['oauth1'])

    def test_allows_trust_scoped_token_with_primary_method(self):
        """A trust-scoped token from a primary auth method is legitimate.

        This is the trust redelegation feature working as designed: a
        trustee authenticates (e.g. with a password) to get a trust-scoped
        token, then uses it to create a further, narrower trust, or to
        read/list their own trust. Blocking on trust_id alone would break
        that feature; only the underlying auth method matters here.
        """
        self._check(['password'], trust_id=uuid.uuid4().hex)

    def test_rejects_ec2_derived_trust_scoped_token(self):
        """An EC2 credential's blob can embed a trust_id.

        See keystone.api.credentials._assign_unique_id -- this produces a
        token that is both trust-scoped and ec2credential-derived. The
        method check alone must still catch this; trust_id doesn't need
        its own check.
        """
        self.assertRaises(
            exception.ForbiddenAction,
            self._check,
            ['ec2credential'],
            trust_id=uuid.uuid4().hex,
        )

    def test_rejects_empty_methods(self):
        """An empty method list must be treated as delegated, not allowed.

        This is the fernet round-trip case: methods is serialised as a
        bitmask over CONF.auth.methods, and a name absent from that list
        encodes to 0 and decodes back to []. Since issuperset([]) is True,
        an EC2- or OAuth2-derived token read back from its payload used to
        pass straight through.
        """
        self.assertRaises(exception.ForbiddenAction, self._check, [])

    def test_rejects_empty_methods_with_trust_scope(self):
        """Same, for a token that is additionally trust-scoped."""
        self.assertRaises(
            exception.ForbiddenAction,
            self._check,
            [],
            trust_id=uuid.uuid4().hex,
        )

    def test_allows_password_token(self):
        self._check(['password'])

    def test_escape_hatch_allows_application_credential(self):
        self._check(['application_credential'], escape_hatch=True)

    def test_escape_hatch_does_not_allow_ec2credential(self):
        self.assertRaises(
            exception.ForbiddenAction,
            self._check,
            ['ec2credential'],
            escape_hatch=True,
        )

    def test_escape_hatch_does_not_allow_oauth1(self):
        self.assertRaises(
            exception.ForbiddenAction,
            self._check,
            ['oauth1'],
            escape_hatch=True,
        )


class TestSharedDelegationGuardUnit(unit.BaseTestCase):
    """Unit tests for keystone.api._shared.delegation.

    LP#2153453, LP#2158538, LP#2159643. Used by trusts.py, os_oauth1.py,
    users.py, credentials.py, and
    auth/plugins/token.py to classify a token's methods as primary
    (allowed) or delegated (blocked from the sensitive actions each of
    those callers guards).
    """

    def _token(self, methods):
        token = mock.Mock()
        token.methods = methods
        return token

    def test_rejects_empty_methods(self):
        """Cover the fernet round-trip gap.

        ec2credential/oauth2_credential have no bit in the method
        bitmask, so a token carrying only one of those decodes back to
        an empty list on any cache miss.
        """
        self.assertTrue(delegation.is_delegated_method(self._token([])))

    def test_allows_builtin_primary_method(self):
        self.assertFalse(
            delegation.is_delegated_method(self._token(['password']))
        )

    def test_rejects_known_delegated_method(self):
        self.assertTrue(
            delegation.is_delegated_method(self._token(['ec2credential']))
        )

    def test_rejects_unknown_future_method_by_default(self):
        """Deny-by-default.

        A brand new, unreviewed method name must be treated as
        delegated until an operator or a future patch explicitly
        allowlists it -- this is the property an allow-by-default
        denylist design would not have.
        """
        self.assertTrue(
            delegation.is_delegated_method(
                self._token(['some_future_delegated_method'])
            )
        )

    def test_additional_primary_auth_methods_allows_custom_plugin(self):
        """A custom auth plugin is not mistaken for a delegated credential.

        E.g. a site-specific SSO integration, once listed in
        [auth] additional_primary_auth_methods.
        """
        CONF.set_override(
            'additional_primary_auth_methods', ['sso'], group='auth'
        )
        self.addCleanup(
            CONF.clear_override,
            'additional_primary_auth_methods',
            group='auth',
        )
        self.assertFalse(delegation.is_delegated_method(self._token(['sso'])))

    def test_unlisted_custom_plugin_still_denied_by_default(self):
        """An unlisted custom method is still denied without opt-in.

        Adding the extension point does not weaken the default posture
        for anyone who hasn't opted in.
        """
        self.assertTrue(delegation.is_delegated_method(self._token(['sso'])))
