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

from six.moves import http_client

import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import test_v3

CONF = keystone.conf.CONF


class TestTrustOperations(test_v3.RestfulTestCase):
    """Test module for create, read, update and delete operations on trusts.

    This module is specific to tests for trust CRUD operations. All other tests
    related to trusts that are authentication or authorization specific should
    live in the keystone/tests/unit/test_v3_auth.py module.

    """

    def setUp(self):
        super(TestTrustOperations, self).setUp()
        # create a trustee to delegate stuff to
        self.trustee_user = unit.create_user(self.identity_api,
                                             domain_id=self.domain_id)
        self.trustee_user_id = self.trustee_user['id']

    def test_create_trust_bad_request(self):
        # The server returns a 403 Forbidden rather than a 400 Bad Request, see
        # bug 1133435
        self.post('/OS-TRUST/trusts', body={'trust': {}},
                  expected_status=http_client.FORBIDDEN)

    def test_trust_crud(self):
        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        # get the trust
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']})
        self.assertValidTrustResponse(r, ref)

        # validate roles on the trust
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles' % {
                'trust_id': trust['id']})
        roles = self.assertValidRoleListResponse(r, self.role)
        self.assertIn(self.role['id'], [x['id'] for x in roles])
        self.head(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            expected_status=http_client.OK)
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']})
        self.assertValidRoleResponse(r, self.role)

        # list all trusts
        r = self.get('/OS-TRUST/trusts')
        self.assertValidTrustListResponse(r, trust)

        # trusts are immutable
        self.patch(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            body={'trust': ref},
            expected_status=http_client.NOT_FOUND)

        # delete the trust
        self.delete(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']})

        # ensure the trust is not found
        self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=http_client.NOT_FOUND)

    def test_list_trusts(self):
        # create three trusts with the same trustor and trustee
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        for i in range(3):
            ref['expires_at'] = datetime.datetime.utcnow().replace(
                year=2032).strftime(unit.TIME_FORMAT)
            r = self.post('/OS-TRUST/trusts', body={'trust': ref})
            self.assertValidTrustResponse(r, ref)

        # list all trusts
        r = self.get('/OS-TRUST/trusts')
        trusts = r.result['trusts']
        self.assertEqual(3, len(trusts))
        self.assertValidTrustListResponse(r)

        # list all trusts for the trustor
        r = self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                     self.user_id)
        trusts = r.result['trusts']
        self.assertEqual(3, len(trusts))
        self.assertValidTrustListResponse(r)

        # list all trusts as the trustor as the trustee.
        r = self.get('/OS-TRUST/trusts?trustee_user_id=%s' %
                     self.user_id)
        trusts = r.result['trusts']
        self.assertEqual(0, len(trusts))

        # list all trusts as the trustee is forbidden
        r = self.get('/OS-TRUST/trusts?trustee_user_id=%s' %
                     self.trustee_user_id,
                     expected_status=http_client.FORBIDDEN)

    def test_delete_trust(self):
        # create a trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        # delete the trust
        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']})

        # ensure the trust isn't found
        self.get('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=http_client.NOT_FOUND)

    def test_create_trust_without_trustee_returns_bad_request(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])

        # trustee_user_id is required to create a trust
        del ref['trustee_user_id']

        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_create_trust_without_impersonation_returns_bad_request(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])

        # impersonation is required to create a trust
        del ref['impersonation']

        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_create_trust_with_bad_remaining_uses_returns_bad_request(self):
        # negative numbers, strings, non-integers, and 0 are not value values
        for value in [-1, 0, "a bad value", 7.2]:
            ref = unit.new_trust_ref(
                trustor_user_id=self.user_id,
                trustee_user_id=self.trustee_user_id,
                project_id=self.project_id,
                remaining_uses=value,
                role_ids=[self.role_id])
            self.post('/OS-TRUST/trusts',
                      body={'trust': ref},
                      expected_status=http_client.BAD_REQUEST)

    def test_create_trust_with_non_existant_trustee_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=uuid.uuid4().hex,
            project_id=self.project_id,
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_create_trust_with_trustee_as_trustor_returns_forbidden(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=self.user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])
        # NOTE(lbragstad): This fails because the user making the request isn't
        # the trustor defined in the request.
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.FORBIDDEN)

    def test_create_trust_with_non_existant_project_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=uuid.uuid4().hex,
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_create_trust_with_non_existant_role_id_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[uuid.uuid4().hex])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_create_trust_with_non_existant_role_name_returns_not_found(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_names=[uuid.uuid4().hex])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_validate_trust_scoped_token_against_v2(self):
        # get a project-scoped token
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        token = self.get_requested_token(auth_data)

        user = unit.new_user_ref(CONF.identity.default_domain_id)
        trustee = self.identity_api.create_user(user)

        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.default_domain_user['id'],
            trustee_user_id=trustee['id'],
            project_id=self.default_domain_project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        # get a v3 trust-scoped token as the trustee
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=user['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(
            r, trustee)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path,
            token=self.get_admin_token(),
            method='GET'
        )

    def test_v3_v2_intermix_trustee_not_in_default_domain_failed(self):
        # get a project-scoped token
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        token = self.get_requested_token(auth_data)

        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.default_domain_project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        # get a trust-scoped token as the trustee
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(
            r, self.trustee_user)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token=self.get_admin_token(),
            method='GET', expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix_project_not_in_default_domain_failed(self):
        # create a trustee in default domain to delegate stuff to
        trustee_user = unit.create_user(self.identity_api,
                                        domain_id=test_v3.DEFAULT_DOMAIN_ID)
        trustee_user_id = trustee_user['id']

        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        # get a project-scoped token as the default_domain_user
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        token = self.get_requested_token(auth_data)

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        # get a trust-scoped token as the trustee
        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r, trustee_user)
        token = r.headers.get('X-Subject-Token')

        # ensure the token is invalid against v2
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token=self.get_admin_token(),
            method='GET', expected_status=http_client.UNAUTHORIZED)

    def test_exercise_trust_scoped_token_without_impersonation(self):
        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(resp)

        # get a trust-scoped token as the trustee
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        resp = self.v3_create_token(auth_data)
        resp_body = resp.json_body['token']

        self.assertValidProjectScopedTokenResponse(resp,
                                                   self.trustee_user)
        self.assertEqual(self.trustee_user['id'], resp_body['user']['id'])
        self.assertEqual(self.trustee_user['name'], resp_body['user']['name'])
        self.assertEqual(self.domain['id'], resp_body['user']['domain']['id'])
        self.assertEqual(self.domain['name'],
                         resp_body['user']['domain']['name'])
        self.assertEqual(self.project['id'], resp_body['project']['id'])
        self.assertEqual(self.project['name'], resp_body['project']['name'])

    def test_exercise_trust_scoped_token_with_impersonation(self):
        # create a new trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(resp)

        # get a trust-scoped token as the trustee
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        resp = self.v3_create_token(auth_data)
        resp_body = resp.json_body['token']

        self.assertValidProjectScopedTokenResponse(resp, self.user)
        self.assertEqual(self.user['id'], resp_body['user']['id'])
        self.assertEqual(self.user['name'], resp_body['user']['name'])
        self.assertEqual(self.domain['id'], resp_body['user']['domain']['id'])
        self.assertEqual(self.domain['name'],
                         resp_body['user']['domain']['name'])
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
            allow_redelegation=True)
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user_id,
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        resp = self.v3_create_token(auth_data)

        # create third-party user, which will be trustee in trust created from
        # redelegated trust
        third_party_trustee = unit.create_user(self.identity_api,
                                               domain_id=self.domain_id)
        third_party_trustee_id = third_party_trustee['id']

        # create trust from redelegated trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=third_party_trustee_id,
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id])
        ref['redelegated_trust_id'] = trust['id']
        self.admin_request(path='/v3/OS-TRUST/trusts',
                           body={'trust': ref},
                           token=resp.headers.get('X-Subject-Token'),
                           method='POST',
                           expected_status=http_client.FORBIDDEN)

    def test_trust_deleted_when_user_deleted(self):
        # create trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            role_ids=[self.role_id],
            allow_redelegation=True)
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)

        # list all trusts
        r = self.get('/OS-TRUST/trusts')
        self.assertEqual(1, len(r.result['trusts']))

        # delete the trustee will delete the trust
        self.delete(
            '/users/%(user_id)s' % {'user_id': trust['trustee_user_id']})

        self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=http_client.NOT_FOUND)

        # create another user as the new trustee
        trustee_user = unit.create_user(self.identity_api,
                                        domain_id=self.domain_id)
        trustee_user_id = trustee_user['id']
        # create the trust again
        ref['trustee_user_id'] = trustee_user_id
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)
        r = self.get('/OS-TRUST/trusts')
        self.assertEqual(1, len(r.result['trusts']))

        # delete the trustor will delete the trust
        self.delete(
            '/users/%(user_id)s' % {'user_id': trust['trustor_user_id']})

        # call the backend method directly to bypass authentication since the
        # user has been deleted.
        self.assertRaises(exception.TrustNotFound,
                          self.trust_api.get_trust,
                          trust['id'])

    def test_trust_deleted_when_project_deleted(self):
        # create trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            role_ids=[self.role_id],
            allow_redelegation=True)
        resp = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(resp)

        # list all trusts
        r = self.get('/OS-TRUST/trusts')
        self.assertEqual(1, len(r.result['trusts']))

        # delete the project will delete the trust.
        self.delete(
            '/projects/%(project_id)s' % {'project_id': trust['project_id']})

        # call the backend method directly to bypass authentication since the
        # user no longer has the assignment on the project.
        self.assertRaises(exception.TrustNotFound,
                          self.trust_api.get_trust,
                          trust['id'])
