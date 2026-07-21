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

import hashlib
import http.client
import json
from unittest import mock
import urllib
import uuid

from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_db import exception as oslo_db_exception
from testtools import matchers

from keystone.api import credentials as credentials_api
from keystone.api import ec2tokens
from keystone.api import users as users_api
from keystone.common import provider_api
from keystone.common import utils
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone import oauth1
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_v3

PROVIDERS = provider_api.ProviderAPIs
CRED_TYPE_EC2 = ec2tokens.CRED_TYPE_EC2


class CredentialBaseTestCase(test_v3.RestfulTestCase):
    def setUp(self):
        super().setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS,
            )
        )

    def _create_dict_blob_credential(self):
        blob, credential = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=self.project_id
        )

        # Store the blob as a dict *not* JSON ref bug #1259584
        # This means we can test the dict->json workaround, added
        # as part of the bugfix for backwards compatibility works.
        credential['blob'] = blob
        credential_id = credential['id']

        # Create direct via the DB API to avoid validation failure
        PROVIDERS.credential_api.create_credential(credential_id, credential)

        return json.dumps(blob), credential_id

    def _get_ec2_sig_ref(self, blob):
        """Return a signed ec2Credentials dict for use with POST /ec2tokens."""
        signer = ec2_utils.Ec2Signer(blob['secret'])
        params = {
            'SignatureMethod': 'HmacSHA256',
            'SignatureVersion': '2',
            'AWSAccessKeyId': blob['access'],
        }
        return {
            'access': blob['access'],
            'signature': signer.generate(
                {
                    'host': 'foo',
                    'verb': 'GET',
                    'path': '/bar',
                    'params': params,
                }
            ),
            'host': 'foo',
            'verb': 'GET',
            'path': '/bar',
            'params': params,
        }

    def _test_get_token(self, access, secret):
        """Test signature validation with the access/secret provided."""
        signer = ec2_utils.Ec2Signer(secret)
        params = {
            'SignatureMethod': 'HmacSHA256',
            'SignatureVersion': '2',
            'AWSAccessKeyId': access,
        }
        request = {
            'host': 'foo',
            'verb': 'GET',
            'path': '/bar',
            'params': params,
        }
        signature = signer.generate(request)

        # Now make a request to validate the signed dummy request via the
        # ec2tokens API.  This proves the v3 ec2 credentials actually work.
        sig_ref = {
            'access': access,
            'signature': signature,
            'host': 'foo',
            'verb': 'GET',
            'path': '/bar',
            'params': params,
        }
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role_id
        )
        token = self.get_system_scoped_token()
        r = self.post(
            '/ec2tokens',
            body={'ec2Credentials': sig_ref},
            expected_status=http.client.OK,
            token=token,
        )
        self.assertValidTokenResponse(r)
        return r.result['token']


class CredentialTestCase(CredentialBaseTestCase):
    """Test credential CRUD."""

    def setUp(self):
        super().setUp()

        self.credential = unit.new_credential_ref(
            user_id=self.user['id'], project_id=self.project_id
        )

        PROVIDERS.credential_api.create_credential(
            self.credential['id'], self.credential
        )

    def test_credential_api_delete_credentials_for_project(self):
        PROVIDERS.credential_api.delete_credentials_for_project(
            self.project_id
        )
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.project_id
        self.assertRaises(
            exception.CredentialNotFound,
            PROVIDERS.credential_api.get_credential,
            credential_id=self.credential['id'],
        )

    def test_credential_api_delete_credentials_for_user(self):
        PROVIDERS.credential_api.delete_credentials_for_user(self.user_id)
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.user_id
        self.assertRaises(
            exception.CredentialNotFound,
            PROVIDERS.credential_api.get_credential,
            credential_id=self.credential['id'],
        )

    def test_list_credentials(self):
        """Call ``GET /credentials``."""
        r = self.get('/credentials')
        self.assertValidCredentialListResponse(r, ref=self.credential)

    def test_list_credentials_does_not_fetch_each_credential(self):
        with mock.patch.object(
            PROVIDERS.credential_api, 'get_credential'
        ) as get_credential_mock:
            r = self.get('/credentials')

        self.assertValidCredentialListResponse(r, ref=self.credential)
        get_credential_mock.assert_not_called()

    def test_list_credentials_filtered_by_user_id(self):
        """Call ``GET  /credentials?user_id={user_id}``."""
        credential = unit.new_credential_ref(user_id=uuid.uuid4().hex)
        PROVIDERS.credential_api.create_credential(
            credential['id'], credential
        )

        r = self.get('/credentials?user_id={}'.format(self.user['id']))
        self.assertValidCredentialListResponse(r, ref=self.credential)
        for cred in r.result['credentials']:
            self.assertEqual(self.user['id'], cred['user_id'])

    def test_list_credentials_filtered_by_type(self):
        """Call ``GET  /credentials?type={type}``."""
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role_id
        )
        token = self.get_system_scoped_token()

        # The type ec2 was chosen, instead of a random string,
        # because the type must be in the list of supported types
        ec2_credential = unit.new_credential_ref(
            user_id=uuid.uuid4().hex,
            project_id=self.project_id,
            type=CRED_TYPE_EC2,
        )

        ec2_resp = PROVIDERS.credential_api.create_credential(
            ec2_credential['id'], ec2_credential
        )

        # The type cert was chosen for the same reason as ec2
        r = self.get('/credentials?type=cert', token=token)

        # Testing the filter for two different types
        self.assertValidCredentialListResponse(r, ref=self.credential)
        for cred in r.result['credentials']:
            self.assertEqual('cert', cred['type'])

        r_ec2 = self.get('/credentials?type=ec2', token=token)
        self.assertThat(r_ec2.result['credentials'], matchers.HasLength(1))
        cred_ec2 = r_ec2.result['credentials'][0]

        self.assertValidCredentialListResponse(r_ec2, ref=ec2_resp)
        self.assertEqual(CRED_TYPE_EC2, cred_ec2['type'])
        self.assertEqual(ec2_credential['id'], cred_ec2['id'])

    def test_list_credentials_filtered_by_type_and_user_id(self):
        """Call ``GET  /credentials?user_id={user_id}&type={type}``."""
        user1_id = uuid.uuid4().hex
        user2_id = uuid.uuid4().hex

        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role_id
        )
        token = self.get_system_scoped_token()

        # Creating credentials for two different users
        credential_user1_ec2 = unit.new_credential_ref(
            user_id=user1_id, type=CRED_TYPE_EC2
        )
        credential_user1_cert = unit.new_credential_ref(user_id=user1_id)
        credential_user2_cert = unit.new_credential_ref(user_id=user2_id)

        PROVIDERS.credential_api.create_credential(
            credential_user1_ec2['id'], credential_user1_ec2
        )
        PROVIDERS.credential_api.create_credential(
            credential_user1_cert['id'], credential_user1_cert
        )
        PROVIDERS.credential_api.create_credential(
            credential_user2_cert['id'], credential_user2_cert
        )

        r = self.get(f'/credentials?user_id={user1_id}&type=ec2', token=token)
        self.assertValidCredentialListResponse(r, ref=credential_user1_ec2)
        self.assertThat(r.result['credentials'], matchers.HasLength(1))
        cred = r.result['credentials'][0]
        self.assertEqual(CRED_TYPE_EC2, cred['type'])
        self.assertEqual(user1_id, cred['user_id'])

    def test_create_credential(self):
        """Call ``POST /credentials``."""
        ref = unit.new_credential_ref(user_id=self.user['id'])
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

    def test_get_credential(self):
        """Call ``GET /credentials/{credential_id}``."""
        r = self.get(
            '/credentials/{credential_id}'.format(
                credential_id=self.credential['id']
            )
        )
        self.assertValidCredentialResponse(r, self.credential)

    def test_update_credential(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        update_ref = {'blob': uuid.uuid4().hex}
        r = self.patch(
            '/credentials/{credential_id}'.format(
                credential_id=self.credential['id']
            ),
            body={'credential': update_ref},
        )
        expected = dict(self.credential, **update_ref)
        self.assertValidCredentialResponse(r, expected)

    def test_update_credential_rejects_non_blob_fields(self):
        """PATCH only accepts `blob` (LP#2159643).

        `type`, `project_id`, and `user_id` are all immutable after
        creation. The only way to change any of those is to delete the
        credential and create a new one.
        """
        ref = unit.new_credential_ref(
            user_id=self.user['id'], project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']

        for update_ref in (
            {'type': 'ec2', 'project_id': self.project_id},
            {'project_id': self.project_id},
            {'user_id': uuid.uuid4().hex},
        ):
            self.patch(
                f'/credentials/{credential_id}',
                body={'credential': update_ref},
                expected_status=http.client.BAD_REQUEST,
            )
        stored = PROVIDERS.credential_api.get_credential(credential_id)
        self.assertEqual(ref['type'], stored['type'])
        self.assertEqual(self.project_id, stored['project_id'])
        self.assertEqual(self.user['id'], stored['user_id'])

    def test_update_credential_non_owner(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        alt_user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        alt_user_id = alt_user['id']
        alt_project = unit.new_project_ref(domain_id=self.domain_id)
        alt_project_id = alt_project['id']
        PROVIDERS.resource_api.create_project(alt_project['id'], alt_project)
        alt_role = unit.new_role_ref(name='reader')
        alt_role_id = alt_role['id']
        PROVIDERS.role_api.create_role(alt_role_id, alt_role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            alt_user_id, alt_project_id, alt_role_id
        )
        auth = self.build_authentication_request(
            user_id=alt_user_id,
            password=alt_user['password'],
            project_id=alt_project_id,
        )
        ref = unit.new_credential_ref(
            user_id=alt_user_id, project_id=alt_project_id
        )
        r = self.post('/credentials', auth=auth, body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']

        # Cannot change the credential to be owned by another user -- PATCH
        # no longer accepts user_id/project_id at all. See LP#2159643.
        update_ref = {'user_id': self.user_id, 'project_id': self.project_id}
        self.patch(
            f'/credentials/{credential_id}',
            expected_status=http.client.BAD_REQUEST,
            auth=auth,
            body={'credential': update_ref},
        )

    def test_update_ec2_credential_change_trust_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=self.project_id
        )
        blob['trust_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different trust
        blob['trust_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )
        # Try removing the trust
        del blob['trust_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_update_ec2_credential_change_app_cred_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=self.project_id
        )
        blob['app_cred_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different app cred
        blob['app_cred_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )
        # Try removing the app cred
        del blob['app_cred_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_update_ec2_credential_change_access_token_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=self.project_id
        )
        blob['access_token_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different access token
        blob['access_token_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )
        # Try removing the access token
        del blob['access_token_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_update_ec2_credential_change_access_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=self.project_id
        )
        blob['access_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different access_id
        blob['access_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )
        # Try removing the access_id
        del blob['access_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_cannot_change_credential_type_via_patch(self):
        """PATCH rejects a type change; only blob is mutable."""
        ref = unit.new_credential_ref(
            user_id=self.user_id, project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        credential_id = r.result['credential']['id']
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': {'type': 'ec2'}},
            expected_status=http.client.BAD_REQUEST,
        )
        stored = PROVIDERS.credential_api.get_credential(credential_id)
        self.assertEqual(ref['type'], stored['type'])

    def test_delete_credential(self):
        """Call ``DELETE /credentials/{credential_id}``."""
        self.delete(
            '/credentials/{credential_id}'.format(
                credential_id=self.credential['id']
            )
        )

    def test_delete_credential_retries_on_deadlock(self):
        patcher = mock.patch(
            'sqlalchemy.orm.query.Query.delete', autospec=True
        )

        class FakeDeadlock:
            def __init__(self, mock_patcher):
                self.deadlock_count = 2
                self.mock_patcher = mock_patcher
                self.patched = True

            def __call__(self, *args, **kwargs):
                if self.deadlock_count > 1:
                    self.deadlock_count -= 1
                else:
                    self.mock_patcher.stop()
                    self.patched = False
                raise oslo_db_exception.DBDeadlock

        sql_delete_mock = patcher.start()
        side_effect = FakeDeadlock(patcher)
        sql_delete_mock.side_effect = side_effect

        try:
            PROVIDERS.credential_api.delete_credentials_for_user(
                user_id=self.user['id']
            )
        finally:
            if side_effect.patched:
                patcher.stop()

        # initial attempt + 1 retry
        self.assertEqual(sql_delete_mock.call_count, 2)

    def test_create_ec2_credential(self):
        """Call ``POST /credentials`` for creating ec2 credential."""
        blob, ref = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        access = blob['access'].encode('utf-8')
        self.assertEqual(
            hashlib.sha256(access).hexdigest(), r.result['credential']['id']
        )
        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.post(
            '/credentials',
            body={'credential': ref},
            expected_status=http.client.CONFLICT,
        )

    def test_get_ec2_dict_blob(self):
        """Ensure non-JSON blob data is correctly converted."""
        expected_blob, credential_id = self._create_dict_blob_credential()

        r = self.get(f'/credentials/{credential_id}')

        # use json.loads to transform the blobs back into Python dictionaries
        # to avoid problems with the keys being in different orders.
        self.assertEqual(
            json.loads(expected_blob),
            json.loads(r.result['credential']['blob']),
        )

    def test_list_ec2_dict_blob(self):
        """Ensure non-JSON blob data is correctly converted."""
        expected_blob, credential_id = self._create_dict_blob_credential()

        list_r = self.get('/credentials')
        list_creds = list_r.result['credentials']
        list_ids = [r['id'] for r in list_creds]
        self.assertIn(credential_id, list_ids)
        # use json.loads to transform the blobs back into Python dictionaries
        # to avoid problems with the keys being in different orders.
        for r in list_creds:
            if r['id'] == credential_id:
                self.assertEqual(
                    json.loads(expected_blob), json.loads(r['blob'])
                )

    def test_create_non_ec2_credential(self):
        """Test creating non-ec2 credential.

        Call ``POST /credentials``.
        """
        blob, ref = unit.new_cert_credential(user_id=self.user['id'])

        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is not same as hash of access key id for
        # non-ec2 credentials
        access = blob['access'].encode('utf-8')
        self.assertNotEqual(
            hashlib.sha256(access).hexdigest(), r.result['credential']['id']
        )

    def test_create_ec2_credential_with_missing_project_id(self):
        """Test Creating ec2 credential with missing project_id.

        Call ``POST /credentials``.
        """
        _, ref = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=None
        )
        # Assert bad request status when missing project_id
        self.post(
            '/credentials',
            body={'credential': ref},
            expected_status=http.client.BAD_REQUEST,
        )

    def test_create_ec2_credential_with_invalid_blob(self):
        """Test creating ec2 credential with invalid blob.

        Call ``POST /credentials``.
        """
        ref = unit.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id,
            blob='{"abc":"def"d}',
            type=CRED_TYPE_EC2,
        )
        # Assert bad request status when request contains invalid blob
        response = self.post(
            '/credentials',
            body={'credential': ref},
            expected_status=http.client.BAD_REQUEST,
        )
        self.assertValidErrorResponse(response)

    def test_create_credential_with_admin_token(self):
        # Make sure we can create credential with the static admin token
        ref = unit.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref},
            token=self.get_admin_token(),
        )
        self.assertValidCredentialResponse(r, ref)


class TestCredentialTrustScoped(CredentialBaseTestCase):
    """Test credential with trust scoped token."""

    def setUp(self):
        super().setUp()

        self.trustee_user = unit.new_user_ref(domain_id=self.domain_id)
        password = self.trustee_user['password']
        self.trustee_user = PROVIDERS.identity_api.create_user(
            self.trustee_user
        )
        self.trustee_user['password'] = password
        self.trustee_user_id = self.trustee_user['id']
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS,
            )
        )

    def config_overrides(self):
        super().config_overrides()
        self.config_fixture.config(group='trust')

    def test_trust_scoped_token_cannot_create_ec2_credential(self):
        """A trust-scoped token cannot create any credential (LP#2159643).

        Trust-scoped tokens creating EC2 credentials was never a
        deliberately-designed feature: it dates back to bug 1242597 /
        OSSA-2013-032, where trust tokens creating EC2 credentials already
        existed generically and the ec2tokens exchange did not preserve
        trust scoping, allowing privilege escalation to the trustor's
        full role set. That bug's fix embedded trust_id in the blob
        rather than removing the underlying capability. Delegated tokens
        (trust included) are now rejected from /v3/credentials outright,
        which removes this path rather than carving it out.
        """
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires={'minutes': 1},
            role_ids=[self.role_id],
        )
        del ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'],
        )
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r, self.user)
        token_id = r.headers.get('X-Subject-Token')

        _, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=self.project_id
        )
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def _get_trust_token(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id],
        )
        del ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'],
        )
        r = self.v3_create_token(auth_data)
        return r.headers.get('X-Subject-Token')

    def test_trust_token_cannot_rescope_credential_project(self):
        """A credential's project_id can never be moved via PATCH.

        Originally, the project-boundary check only validated the stored
        (pre-image) project_id, not the requested one, so a delegated
        token could PATCH an in-scope credential to move it to any other
        project. PATCH no longer accepts project_id at all, for any
        token, which closes this more generally. See LP#2159643.
        """
        other_project = unit.new_project_ref(domain_id=self.domain_id)
        other_project = PROVIDERS.resource_api.create_project(
            other_project['id'], other_project
        )
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, other_project['id'], self.role_id
        )
        ref = unit.new_credential_ref(
            user_id=self.user_id, project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        cred_id = r.result['credential']['id']

        trust_token = self._get_trust_token()
        self.patch(
            f'/credentials/{cred_id}',
            body={'credential': {'project_id': other_project['id']}},
            token=trust_token,
            expected_status=http.client.BAD_REQUEST,
        )
        stored = PROVIDERS.credential_api.get_credential(cred_id)
        self.assertEqual(self.project_id, stored['project_id'])

    def test_trust_token_cannot_list_totp_credentials(self):
        """Trust-scoped token must not see TOTP/MFA credentials (project_id=None).

        TOTP credentials have no project anchor. Before this fix the
        project boundary check skipped null-project credentials, allowing a
        delegation token to enumerate and exfiltrate MFA secrets.
        """
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']

        trust_token = self._get_trust_token()

        r = self.get(f'/credentials?user_id={self.user_id}', token=trust_token)
        listed_ids = [c['id'] for c in r.result['credentials']]
        self.assertNotIn(totp_id, listed_ids)

    def test_trust_token_cannot_read_totp_credential(self):
        """Trust-scoped token must not read a TOTP credential blob."""
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']

        trust_token = self._get_trust_token()
        self.get(
            f'/credentials/{totp_id}',
            token=trust_token,
            expected_status=http.client.FORBIDDEN,
        )

    def test_escape_hatch_allows_admin_trust_token_to_read_ec2_credential(
        self,
    ):
        """The escape hatch's one use case still works: admin trust + ec2."""
        self.config_fixture.config(
            group='security_compliance',
            allow_insecure_admin_trust_cross_project_credentials_access=True,
        )
        blob, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        ec2_id = r.result['credential']['id']

        # _get_trust_token() grants self.role_id, which load_sample_data()
        # creates as the "admin" role.
        trust_token = self._get_trust_token()
        r = self.get(f'/credentials/{ec2_id}', token=trust_token)
        self.assertEqual(
            blob['access'],
            json.loads(r.result['credential']['blob'])['access'],
        )

    def test_escape_hatch_still_blocks_non_ec2_credential_regardless_of_role(
        self,
    ):
        """The escape hatch never exempts non-ec2 credentials."""
        self.config_fixture.config(
            group='security_compliance',
            allow_insecure_admin_trust_cross_project_credentials_access=True,
        )
        ref = unit.new_credential_ref(user_id=self.user_id)
        r = self.post('/credentials', body={'credential': ref})
        credential_id = r.result['credential']['id']

        trust_token = self._get_trust_token()
        self.get(
            f'/credentials/{credential_id}',
            token=trust_token,
            expected_status=http.client.FORBIDDEN,
        )

    def test_escape_hatch_still_blocks_non_admin_trust_token(self):
        """The insecure escape hatch does not exempt non-admin-role tokens."""
        self.config_fixture.config(
            group='security_compliance',
            allow_insecure_admin_trust_cross_project_credentials_access=True,
        )
        _, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        ec2_id = r.result['credential']['id']

        member_role = unit.new_role_ref(name='member')
        PROVIDERS.role_api.create_role(member_role['id'], member_role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, member_role['id']
        )
        trust_ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            role_ids=[member_role['id']],
        )
        del trust_ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': trust_ref})
        trust = r.result['trust']
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'],
        )
        r = self.v3_create_token(auth_data)
        trust_token = r.headers.get('X-Subject-Token')

        self.get(
            f'/credentials/{ec2_id}',
            token=trust_token,
            expected_status=http.client.FORBIDDEN,
        )

    def test_trust_token_cannot_update_totp_credential(self):
        """Trust-scoped token must not be able to update a TOTP credential blob."""
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']

        trust_token = self._get_trust_token()
        self.patch(
            f'/credentials/{totp_id}',
            token=trust_token,
            body={'credential': {'blob': totp_ref['blob']}},
            expected_status=http.client.FORBIDDEN,
        )

    def test_trust_token_cannot_delete_totp_credential(self):
        """Trust-scoped token must not delete a TOTP credential."""
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']

        trust_token = self._get_trust_token()
        self.delete(
            f'/credentials/{totp_id}',
            token=trust_token,
            expected_status=http.client.FORBIDDEN,
        )
        # Confirm it still exists
        self.get(f'/credentials/{totp_id}', expected_status=http.client.OK)

    def test_ec2_auth_trust_cross_project_scoped_to_trust(self):
        """Trust-backed EC2 credential with mismatched project_id is safe.

        When an EC2 credential's project_id differs from the trust's
        project_id, the trust mechanism constrains the resulting token to
        the trust's project -- not the credential's project. This means the
        cross-project escalation does not occur for trust-backed credentials,
        and no additional auth-time check is needed in that branch.

        This test documents and protects that invariant.
        """
        trust_ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id],
        )
        del trust_ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': trust_ref})
        trust = self.assertValidTrustResponse(r)

        other_project = unit.new_project_ref(domain_id=self.domain_id)
        other_project = PROVIDERS.resource_api.create_project(
            other_project['id'], other_project
        )

        # Plant a credential with project_id pointing to the other project
        # but trust_id from the trust above (scoped to self.project_id).
        blob, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=other_project['id']
        )
        blob['trust_id'] = trust['id']
        ref['blob'] = json.dumps(blob)
        PROVIDERS.credential_api.create_credential(ref['id'], ref)

        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role_id
        )
        token = self.get_system_scoped_token()
        r = self.post(
            '/ec2tokens',
            body={'ec2Credentials': self._get_ec2_sig_ref(blob)},
            token=token,
            expected_status=http.client.OK,
        )
        # The resulting token is scoped to the trust's project, not to
        # other_project -- the trust mechanism prevents cross-project escalation.
        token_project = r.result['token']['project']['id']
        self.assertEqual(self.project_id, token_project)
        self.assertNotEqual(other_project['id'], token_project)


class TestCredentialAppCreds(CredentialBaseTestCase):
    """Test credential with application credential token."""

    def setUp(self):
        super().setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS,
            )
        )

    def test_app_cred_cannot_create_ec2_credential(self):
        """An application credential cannot create any credential (LP#2159643).

        Delegated tokens (application credentials included) are now
        rejected from /v3/credentials outright.
        """
        ref = unit.new_application_credential_ref(roles=[{'id': self.role_id}])
        del ref['id']
        ref['unrestricted'] = True
        r = self.post(
            f'/users/{self.user_id}/application_credentials',
            body={'application_credential': ref},
        )
        app_cred = r.result['application_credential']

        auth_data = self.build_authentication_request(
            app_cred_id=app_cred['id'], secret=app_cred['secret']
        )
        r = self.v3_create_token(auth_data)
        token_id = r.headers.get('X-Subject-Token')

        _, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=self.project_id
        )
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def _get_app_cred_token(self, unrestricted=False):
        """Create an application credential and return its token."""
        ref = unit.new_application_credential_ref(roles=[{'id': self.role_id}])
        del ref['id']
        if unrestricted:
            ref['unrestricted'] = True
        r = self.post(
            f'/users/{self.user_id}/application_credentials',
            body={'application_credential': ref},
        )
        app_cred = r.result['application_credential']
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred['id'], secret=app_cred['secret']
        )
        r = self.v3_create_token(auth_data)
        return r.headers.get('X-Subject-Token')

    def test_app_cred_token_cannot_patch_credential(self):
        """An application-credential token cannot PATCH /v3/credentials."""
        token_id = self._get_app_cred_token(unrestricted=True)
        ref = unit.new_credential_ref(
            user_id=self.user_id, project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        credential_id = r.result['credential']['id']

        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': {'type': 'ec2'}},
            token=token_id,
            expected_status=http.client.BAD_REQUEST,
        )
        stored = PROVIDERS.credential_api.get_credential(credential_id)
        self.assertEqual('cert', stored['type'])

        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': {'blob': 'rotated-blob'}},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )
        stored = PROVIDERS.credential_api.get_credential(credential_id)
        self.assertEqual('cert', stored['type'])
        self.assertEqual(self.project_id, stored['project_id'])

    def test_app_cred_token_cannot_move_credential_cross_project(self):
        """PATCH must not let a caller rewrite project_id either (LP#2158931).

        The pre-image project check alone wasn't enough: it validated
        the credential's *current* project, never the *new* project_id
        in the request body, so a delegated token scoped to project A
        could rewrite a credential it already owned there to point at
        an unrelated project B.
        """
        app_cred_token = self._get_app_cred_token(unrestricted=True)
        ref = unit.new_credential_ref(
            user_id=self.user_id, project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        credential_id = r.result['credential']['id']

        other_project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(
            other_project['id'], other_project
        )

        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': {'project_id': other_project['id']}},
            token=app_cred_token,
            expected_status=http.client.BAD_REQUEST,
        )
        stored = PROVIDERS.credential_api.get_credential(credential_id)
        self.assertEqual(self.project_id, stored['project_id'])

    def test_restricted_app_cred_cannot_create_ec2_credential(self):
        """Test that a restricted app cred cannot create EC2 credentials.

        A restricted application credential must not be allowed to
        create EC2 credentials via POST /credentials either, as this
        would bypass the guard on the OS-EC2 endpoint.
        """
        token_id = self._get_app_cred_token(unrestricted=False)
        blob, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=self.project_id
        )
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def test_app_cred_ec2_credential_cross_project_forbidden(self):
        """EC2 credential project_id must match the app cred project.

        An unrestricted app cred scoped to project A must not be used to
        create an EC2 credential targeting a different project B.

        Call ``POST /credentials``.
        """
        token_id = self._get_app_cred_token(unrestricted=True)

        other_project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(
            other_project['id'], other_project
        )

        _, ec2_ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=other_project['id']
        )
        self.post(
            '/credentials',
            body={'credential': ec2_ref},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def test_app_cred_ec2_auth_cross_project_rejected(self):
        """EC2 auth is rejected when credential project differs from app cred.

        A pre-existing EC2 credential whose project_id does not match the
        linked application credential's project must be rejected at
        authentication time, preventing cross-project lateral movement.

        Call ``POST /ec2tokens``.
        """
        ref = unit.new_application_credential_ref(roles=[{'id': self.role_id}])
        del ref['id']
        r = self.post(
            f'/users/{self.user_id}/application_credentials',
            body={'application_credential': ref},
        )
        app_cred = r.result['application_credential']

        other_project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(
            other_project['id'], other_project
        )

        # Bypass the API to plant a credential with a mismatched project_id.
        # This simulates a credential that existed before the creation-time
        # check was added, or one created via a direct DB write.
        blob = {
            'access': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'trust_id': None,
            'app_cred_id': app_cred['id'],
        }
        _, ec2_ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=other_project['id'], blob=blob
        )
        PROVIDERS.credential_api.create_credential(ec2_ref['id'], ec2_ref)

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
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role_id
        )
        token = self.get_system_scoped_token()
        self.post(
            '/ec2tokens',
            body={'ec2Credentials': sig_ref},
            token=token,
            expected_status=http.client.UNAUTHORIZED,
        )

    def test_app_cred_token_cannot_list_totp_credentials(self):
        """App cred token must not see TOTP/MFA credentials (project_id=None).

        TOTP credentials have no project anchor. Before this fix the
        project boundary check skipped null-project credentials, allowing a
        delegation token to enumerate and exfiltrate MFA secrets.
        """
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']

        app_cred_token = self._get_app_cred_token(unrestricted=True)

        r = self.get(
            f'/credentials?user_id={self.user_id}', token=app_cred_token
        )
        listed_ids = [c['id'] for c in r.result['credentials']]
        self.assertNotIn(totp_id, listed_ids)

    def test_app_cred_token_cannot_read_totp_credential(self):
        """App cred token must not read a TOTP credential blob."""
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']
        app_cred_token = self._get_app_cred_token(unrestricted=True)

        self.get(
            f'/credentials/{totp_id}',
            token=app_cred_token,
            expected_status=http.client.FORBIDDEN,
        )

    def test_app_cred_token_cannot_update_totp_credential(self):
        """App cred token must not update a TOTP credential blob."""
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']
        app_cred_token = self._get_app_cred_token(unrestricted=True)

        self.patch(
            f'/credentials/{totp_id}',
            token=app_cred_token,
            body={'credential': {'blob': totp_ref['blob']}},
            expected_status=http.client.FORBIDDEN,
        )

    def test_app_cred_token_cannot_delete_totp_credential(self):
        """App cred token must not delete a TOTP credential blob."""
        totp_ref = {
            'user_id': self.user_id,
            'type': 'totp',
            'blob': '{"seed": "JBSWY3DPEHPK3PXP"}',
        }
        r = self.post('/credentials', body={'credential': totp_ref})
        totp_id = r.result['credential']['id']
        app_cred_token = self._get_app_cred_token(unrestricted=True)

        self.delete(
            f'/credentials/{totp_id}',
            token=app_cred_token,
            expected_status=http.client.FORBIDDEN,
        )


class TestCredentialAccessToken(CredentialBaseTestCase):
    """Test credential with access token."""

    def setUp(self):
        super().setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS,
            )
        )
        self.base_url = 'http://localhost/v3'

    def _urllib_parse_qs_text_keys(self, content):
        results = urllib.parse.parse_qs(content)
        return {key.decode('utf-8'): value for key, value in results.items()}

    def _create_single_consumer(self):
        endpoint = '/OS-OAUTH1/consumers'

        ref = {'description': uuid.uuid4().hex}
        resp = self.post(endpoint, body={'consumer': ref})
        return resp.result['consumer']

    def _create_request_token(self, consumer, project_id, base_url=None):
        endpoint = '/OS-OAUTH1/request_token'
        client = oauth1.Client(
            consumer['key'],
            client_secret=consumer['secret'],
            signature_method=oauth1.SIG_HMAC,
            callback_uri="oob",
        )
        headers = {'requested_project_id': project_id}
        if not base_url:
            base_url = self.base_url
        url, headers, body = client.sign(
            base_url + endpoint, http_method='POST', headers=headers
        )
        return endpoint, headers

    def _create_access_token(self, consumer, token, base_url=None):
        endpoint = '/OS-OAUTH1/access_token'
        client = oauth1.Client(
            consumer['key'],
            client_secret=consumer['secret'],
            resource_owner_key=token.key,
            resource_owner_secret=token.secret,
            signature_method=oauth1.SIG_HMAC,
            verifier=token.verifier,
        )
        if not base_url:
            base_url = self.base_url
        url, headers, body = client.sign(
            base_url + endpoint, http_method='POST'
        )
        headers.update({'Content-Type': 'application/json'})
        return endpoint, headers

    def _get_oauth_token(self, consumer, token):
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

    def _get_access_token(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        consumer = {'key': consumer_id, 'secret': consumer_secret}

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

        url, headers, body = self._get_oauth_token(consumer, access_token)
        content = self.post(url, headers=headers, body=body)
        return access_key, content.headers['X-Subject-Token']

    def test_access_token_cannot_create_ec2_credential(self):
        """An OAuth1 access token cannot create any credential (LP#2159643).

        Same history as the trust-scoped case: this was never a
        deliberate feature, just a side effect of access-token-derived
        tokens being otherwise broadly capable. Delegated tokens
        (OAuth1 access tokens included) are now rejected from
        /v3/credentials outright.
        """
        _, token_id = self._get_access_token()

        _, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=self.project_id
        )
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def test_access_token_cannot_get_credential_via_os_ec2(self):
        """An OAuth1 token cannot read an EC2 cred via OS-EC2 (LP#2159643)."""
        uri = f'/users/{self.user_id}/credentials/OS-EC2'
        ec2_cred = self.post(uri, body={'tenant_id': self.project_id}).result[
            'credential'
        ]
        _, token_id = self._get_access_token()
        self.get(
            '/'.join([uri, ec2_cred['access']]),
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def test_access_token_cannot_delete_credential_via_os_ec2(self):
        """An OAuth1 token cannot delete an EC2 cred via OS-EC2 (2159643)."""
        uri = f'/users/{self.user_id}/credentials/OS-EC2'
        ec2_cred = self.post(uri, body={'tenant_id': self.project_id}).result[
            'credential'
        ]
        _, token_id = self._get_access_token()
        cred_uri = '/'.join([uri, ec2_cred['access']])
        self.delete(
            cred_uri, token=token_id, expected_status=http.client.FORBIDDEN
        )
        self.get(cred_uri, expected_status=http.client.OK)

    def test_ec2_auth_access_token_cross_project_blocked(self):
        """OAuth1 access-token-backed EC2 credential must not auth cross-project.

        Auth-time check: if a cross-project EC2 credential backed by an OAuth1
        access token exists, POST /ec2tokens must reject it when the
        credential's project_id differs from the access token's project_id.
        """
        access_key, _ = self._get_access_token()

        # Retrieve the stored access token to get its project_id
        access_token = PROVIDERS.oauth_api.get_access_token(
            access_key.decode('utf-8')
            if isinstance(access_key, bytes)
            else access_key
        )

        # Create a second project (cross-project target)
        other_project = unit.new_project_ref(domain_id=self.domain_id)
        other_project = PROVIDERS.resource_api.create_project(
            other_project['id'], other_project
        )

        # Directly inject an EC2 credential whose project_id points to the
        # other project but whose access_token_id references the token above.
        # This simulates a pre-existing cross-project credential.
        blob, ref = unit.new_ec2_credential(
            user_id=self.user_id, project_id=other_project['id']
        )
        blob['access_token_id'] = (
            access_key.decode('utf-8')
            if isinstance(access_key, bytes)
            else access_key
        )
        ref['blob'] = json.dumps(blob)
        PROVIDERS.credential_api.create_credential(ref['id'], ref)

        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role_id
        )
        token = self.get_system_scoped_token()
        self.post(
            '/ec2tokens',
            body={'ec2Credentials': self._get_ec2_sig_ref(blob)},
            token=token,
            expected_status=http.client.UNAUTHORIZED,
        )


class TestCredentialEc2(CredentialBaseTestCase):
    """Test v3 credential compatibility with ec2tokens."""

    def test_ec2_credential_signature_validate(self):
        """Test signature validation with a v3 ec2 credential."""
        blob, ref = unit.new_ec2_credential(
            user_id=self.user['id'], project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is same as hash of access key id
        access = blob['access'].encode('utf-8')
        self.assertEqual(
            hashlib.sha256(access).hexdigest(), r.result['credential']['id']
        )

        cred_blob = json.loads(r.result['credential']['blob'])
        self.assertEqual(blob, cred_blob)
        self._test_get_token(
            access=cred_blob['access'], secret=cred_blob['secret']
        )

    def test_ec2_credential_signature_validate_legacy(self):
        """Test signature validation with a legacy v3 ec2 credential."""
        cred_json, _ = self._create_dict_blob_credential()
        cred_blob = json.loads(cred_json)
        self._test_get_token(
            access=cred_blob['access'], secret=cred_blob['secret']
        )

    def _get_ec2_cred_uri(self):
        return f'/users/{self.user_id}/credentials/OS-EC2'

    def _get_ec2_cred(self):
        uri = self._get_ec2_cred_uri()
        r = self.post(uri, body={'tenant_id': self.project_id})
        return r.result['credential']

    def test_ec2_create_credential(self):
        """Test ec2 credential creation."""
        ec2_cred = self._get_ec2_cred()
        self.assertEqual(self.user_id, ec2_cred['user_id'])
        self.assertEqual(self.project_id, ec2_cred['tenant_id'])
        self.assertIsNone(ec2_cred['trust_id'])
        self._test_get_token(
            access=ec2_cred['access'], secret=ec2_cred['secret']
        )
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        self.assertThat(ec2_cred['links']['self'], matchers.EndsWith(uri))

    def test_ec2_get_credential(self):
        ec2_cred = self._get_ec2_cred()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        r = self.get(uri)
        self.assertDictEqual(ec2_cred, r.result['credential'])
        self.assertThat(ec2_cred['links']['self'], matchers.EndsWith(uri))

    def _get_ec2_token_via_own_credential(self):
        """Create an EC2 credential and exchange it for a token."""
        ec2_cred = self._get_ec2_cred()
        blob = {'access': ec2_cred['access'], 'secret': ec2_cred['secret']}
        r = self.post(
            '/ec2tokens',
            body={'ec2Credentials': self._get_ec2_sig_ref(blob)},
            expected_status=http.client.OK,
        )
        return ec2_cred, r.headers.get('X-Subject-Token')

    def test_ec2_token_cannot_list_credentials_via_os_ec2(self):
        """An ec2credential token must not list EC2 creds via OS-EC2.

        The OS-EC2 compat endpoint has its own, separate delegation check
        from /v3/credentials, and it never recognized ec2credential tokens
        as delegated either -- so an ec2credential token could list every
        EC2 credential (secrets included) belonging to the user.
        """
        _, ec2_token = self._get_ec2_token_via_own_credential()
        self.get(
            self._get_ec2_cred_uri(),
            token=ec2_token,
            expected_status=http.client.FORBIDDEN,
        )

    def test_ec2_token_cannot_get_credential_via_os_ec2(self):
        """An ec2credential token must not read an EC2 cred via OS-EC2."""
        ec2_cred, ec2_token = self._get_ec2_token_via_own_credential()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        self.get(uri, token=ec2_token, expected_status=http.client.FORBIDDEN)

    def test_ec2_token_cannot_delete_credential_via_os_ec2(self):
        """An ec2credential token must not delete an EC2 cred via OS-EC2."""
        ec2_cred, ec2_token = self._get_ec2_token_via_own_credential()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        self.delete(
            uri, token=ec2_token, expected_status=http.client.FORBIDDEN
        )
        # the credential must still exist afterwards
        self.get(uri, expected_status=http.client.OK)

    def test_ec2_token_cannot_patch_credential_via_credentials_api(self):
        """An ec2credential token must not PATCH /v3/credentials."""
        ref = unit.new_credential_ref(
            user_id=self.user_id, project_id=self.project_id
        )
        r = self.post('/credentials', body={'credential': ref})
        credential_id = r.result['credential']['id']
        original_blob = r.result['credential']['blob']

        _, ec2_token = self._get_ec2_token_via_own_credential()
        self.patch(
            f'/credentials/{credential_id}',
            body={'credential': {'blob': 'rotated-blob'}},
            token=ec2_token,
            expected_status=http.client.FORBIDDEN,
        )
        self.get(
            f'/credentials/{credential_id}',
            token=ec2_token,
            expected_status=http.client.FORBIDDEN,
        )
        stored = PROVIDERS.credential_api.get_credential(credential_id)
        self.assertEqual(original_blob, stored['blob'])

    def test_ec2_cannot_get_non_ec2_credential(self):
        access_key = uuid.uuid4().hex
        cred_id = utils.hash_access_key(access_key)
        non_ec2_cred = unit.new_credential_ref(
            user_id=self.user_id, project_id=self.project_id
        )
        non_ec2_cred['id'] = cred_id
        PROVIDERS.credential_api.create_credential(cred_id, non_ec2_cred)
        uri = '/'.join([self._get_ec2_cred_uri(), access_key])
        # if access_key is not found, ec2 controller raises Unauthorized
        # exception
        self.get(uri, expected_status=http.client.UNAUTHORIZED)

    def test_ec2_list_credentials(self):
        """Test ec2 credential listing."""
        self._get_ec2_cred()
        uri = self._get_ec2_cred_uri()
        r = self.get(uri)
        cred_list = r.result['credentials']
        self.assertEqual(1, len(cred_list))
        self.assertThat(r.result['links']['self'], matchers.EndsWith(uri))

        # non-EC2 credentials won't be fetched
        non_ec2_cred = unit.new_credential_ref(
            user_id=self.user_id, project_id=self.project_id
        )
        non_ec2_cred['type'] = uuid.uuid4().hex
        PROVIDERS.credential_api.create_credential(
            non_ec2_cred['id'], non_ec2_cred
        )
        r = self.get(uri)
        cred_list_2 = r.result['credentials']
        # still one element because non-EC2 credentials are not returned.
        self.assertEqual(1, len(cred_list_2))
        self.assertEqual(cred_list[0], cred_list_2[0])

    def test_ec2_delete_credential(self):
        """Test ec2 credential deletion."""
        ec2_cred = self._get_ec2_cred()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        cred_from_credential_api = (
            PROVIDERS.credential_api.list_credentials_for_user(
                self.user_id, type=CRED_TYPE_EC2
            )
        )
        self.assertEqual(1, len(cred_from_credential_api))
        self.delete(uri)
        self.assertRaises(
            exception.CredentialNotFound,
            PROVIDERS.credential_api.get_credential,
            cred_from_credential_api[0]['id'],
        )

    def _get_app_cred_token(self, unrestricted=False):
        """Create an application credential and return a token for it."""
        ref = unit.new_application_credential_ref(roles=[{'id': self.role_id}])
        del ref['id']
        if unrestricted:
            ref['unrestricted'] = True
        r = self.post(
            f'/users/{self.user_id}/application_credentials',
            body={'application_credential': ref},
        )
        app_cred = r.result['application_credential']
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred['id'], secret=app_cred['secret']
        )
        r = self.v3_create_token(auth_data)
        return r.headers.get('X-Subject-Token')

    def test_ec2_create_credential_with_restricted_app_cred(self):
        """Test that a restricted app cred cannot create EC2 credentials.

        A restricted application credential must not be allowed to create
        EC2 credentials, as this would bypass the role restriction and
        grant full user access to S3.
        """
        token_id = self._get_app_cred_token(unrestricted=False)
        uri = self._get_ec2_cred_uri()
        self.post(
            uri,
            body={'tenant_id': self.project_id},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def test_unrestricted_app_cred_cannot_create_ec2_credential(self):
        """An unrestricted app cred cannot create EC2 creds either (LP#2159643).

        "unrestricted" only ever governed app-cred management, not this.
        """
        token_id = self._get_app_cred_token(unrestricted=True)
        uri = self._get_ec2_cred_uri()
        self.post(
            uri,
            body={'tenant_id': self.project_id},
            token=token_id,
            expected_status=http.client.FORBIDDEN,
        )

    def _get_trust_token(self):
        """Create a trust and return a trust-scoped token for the trustee."""
        trustee = unit.new_user_ref(domain_id=self.domain_id)
        password = trustee['password']
        trustee = PROVIDERS.identity_api.create_user(trustee)
        trustee['password'] = password
        trust_ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=trustee['id'],
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id],
        )
        del trust_ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': trust_ref})
        trust = r.result['trust']
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password'],
            trust_id=trust['id'],
        )
        r = self.v3_create_token(auth_data)
        return r.headers.get('X-Subject-Token')

    def test_trust_scoped_token_cannot_create_ec2_credential(self):
        """A trust-scoped token cannot create an EC2 cred via OS-EC2 (LP#2159643).

        Previously only checked project scope, so same-project access
        was allowed. Now rejected outright, regardless of project.
        """
        trust_token = self._get_trust_token()
        uri = self._get_ec2_cred_uri()
        self.post(
            uri,
            body={'tenant_id': self.project_id},
            token=trust_token,
            expected_status=http.client.FORBIDDEN,
        )

    def test_trust_scoped_token_cannot_get_credential_via_os_ec2(self):
        """A trust-scoped token cannot read an EC2 cred (LP#2159643)."""
        ec2_cred = self._get_ec2_cred()
        trust_token = self._get_trust_token()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        self.get(uri, token=trust_token, expected_status=http.client.FORBIDDEN)

    def test_trust_scoped_token_cannot_delete_credential_via_os_ec2(self):
        """A trust-scoped token cannot delete an EC2 cred (LP#2159643)."""
        ec2_cred = self._get_ec2_cred()
        trust_token = self._get_trust_token()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        self.delete(
            uri, token=trust_token, expected_status=http.client.FORBIDDEN
        )
        # the credential must still exist afterwards
        self.get(uri, expected_status=http.client.OK)


class TestPrimaryAuthGuards(unit.BaseTestCase):
    """Unit-level tests for the delegated-token guards (LP#2159643).

    Calls the guards directly with stub tokens, independent of HTTP/
    middleware. Matters for ec2credential specifically: an unrelated,
    already-landed fix bans ec2credential-method tokens at the auth
    middleware layer before these guards ever run, so an HTTP-level test
    would pass regardless of whether the guards recognize it as delegated.
    """

    def _token(self, methods):
        token = mock.Mock()
        token.methods = methods
        return token

    def _oslo_context(self, trust_id=None):
        ctx = mock.Mock()
        ctx.trust_id = trust_id
        return ctx

    def test_require_primary_auth_rejects_ec2credential_token(self):
        self.assertRaises(
            exception.ForbiddenAction,
            credentials_api._require_primary_auth,
            self._token(['ec2credential']),
            self._oslo_context(),
            'cert',
        )

    def test_require_primary_auth_allows_password_token(self):
        credentials_api._require_primary_auth(
            self._token(['password']), self._oslo_context(), 'cert'
        )

    def test_require_primary_auth_allows_custom_method_via_config(self):
        """A custom auth plugin is not mistaken for a delegated credential.

        Once listed in [auth] additional_primary_auth_methods.
        """
        credentials_api.CONF.set_override(
            'additional_primary_auth_methods', ['sso'], group='auth'
        )
        self.addCleanup(
            credentials_api.CONF.clear_override,
            'additional_primary_auth_methods',
            group='auth',
        )
        credentials_api._require_primary_auth(
            self._token(['sso']), self._oslo_context(), 'cert'
        )

    def test_require_primary_auth_rejects_unlisted_custom_method(self):
        self.assertRaises(
            exception.ForbiddenAction,
            credentials_api._require_primary_auth,
            self._token(['sso']),
            self._oslo_context(),
            'cert',
        )

    def test_require_primary_auth_rejects_empty_methods(self):
        """An empty method list must be treated as delegated, not allowed."""
        self.assertRaises(
            exception.ForbiddenAction,
            credentials_api._require_primary_auth,
            self._token([]),
            self._oslo_context(),
            'cert',
        )

    def test_require_primary_auth_rejects_empty_methods_with_trust_scope(self):
        """Same, for a token that is additionally trust-scoped."""
        self.assertRaises(
            exception.ForbiddenAction,
            credentials_api._require_primary_auth,
            self._token([]),
            self._oslo_context(trust_id=uuid.uuid4().hex),
            'cert',
        )

    def test_require_primary_auth_rejects_trust_scoped_token(self):
        self.assertRaises(
            exception.ForbiddenAction,
            credentials_api._require_primary_auth,
            self._token(['password']),
            self._oslo_context(trust_id=uuid.uuid4().hex),
            'cert',
        )

    def test_require_primary_auth_escape_hatch_requires_ec2_type(self):
        """The escape hatch is scoped to ec2-type credentials only."""
        credentials_api.CONF.set_override(
            'allow_insecure_admin_trust_cross_project_credentials_access',
            True,
            group='security_compliance',
        )
        self.addCleanup(
            credentials_api.CONF.clear_override,
            'allow_insecure_admin_trust_cross_project_credentials_access',
            group='security_compliance',
        )
        with mock.patch.object(
            credentials_api.ENFORCER, 'enforce_call', return_value=None
        ):
            credentials_api._require_primary_auth(
                self._token(['ec2credential']), self._oslo_context(), 'ec2'
            )
            self.assertRaises(
                exception.ForbiddenAction,
                credentials_api._require_primary_auth,
                self._token(['ec2credential']),
                self._oslo_context(),
                'cert',
            )

    def test_require_primary_auth_for_ec2_rejects_ec2credential_token(self):
        self.assertRaises(
            exception.ForbiddenAction,
            users_api._require_primary_auth_for_ec2,
            self._oslo_context(),
            self._token(['ec2credential']),
        )

    def test_require_primary_auth_for_ec2_allows_password_token(self):
        users_api._require_primary_auth_for_ec2(
            self._oslo_context(), self._token(['password'])
        )

    def test_require_primary_auth_for_ec2_rejects_trust_scoped_token(self):
        self.assertRaises(
            exception.ForbiddenAction,
            users_api._require_primary_auth_for_ec2,
            self._oslo_context(trust_id=uuid.uuid4().hex),
            self._token(['password']),
        )

    def test_require_primary_auth_for_ec2_rejects_empty_methods(self):
        """Same fernet round-trip gap as _require_primary_auth."""
        self.assertRaises(
            exception.ForbiddenAction,
            users_api._require_primary_auth_for_ec2,
            self._oslo_context(),
            self._token([]),
        )
