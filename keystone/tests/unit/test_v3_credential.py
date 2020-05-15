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
import json
from unittest import mock
import uuid

import http.client
from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_db import exception as oslo_db_exception
from testtools import matchers
import urllib

from keystone.api import ec2tokens
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
        super(CredentialBaseTestCase, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    def _create_dict_blob_credential(self):
        blob, credential = unit.new_ec2_credential(user_id=self.user['id'],
                                                   project_id=self.project_id)

        # Store the blob as a dict *not* JSON ref bug #1259584
        # This means we can test the dict->json workaround, added
        # as part of the bugfix for backwards compatibility works.
        credential['blob'] = blob
        credential_id = credential['id']

        # Create direct via the DB API to avoid validation failure
        PROVIDERS.credential_api.create_credential(credential_id, credential)

        return json.dumps(blob), credential_id

    def _test_get_token(self, access, secret):
        """Test signature validation with the access/secret provided."""
        signer = ec2_utils.Ec2Signer(secret)
        params = {'SignatureMethod': 'HmacSHA256',
                  'SignatureVersion': '2',
                  'AWSAccessKeyId': access}
        request = {'host': 'foo',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}
        signature = signer.generate(request)

        # Now make a request to validate the signed dummy request via the
        # ec2tokens API.  This proves the v3 ec2 credentials actually work.
        sig_ref = {'access': access,
                   'signature': signature,
                   'host': 'foo',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}
        r = self.post(
            '/ec2tokens',
            body={'ec2Credentials': sig_ref},
            expected_status=http.client.OK)
        self.assertValidTokenResponse(r)
        return r.result['token']


class CredentialTestCase(CredentialBaseTestCase):
    """Test credential CRUD."""

    def setUp(self):

        super(CredentialTestCase, self).setUp()

        self.credential = unit.new_credential_ref(user_id=self.user['id'],
                                                  project_id=self.project_id)

        PROVIDERS.credential_api.create_credential(
            self.credential['id'],
            self.credential)

    def test_credential_api_delete_credentials_for_project(self):
        PROVIDERS.credential_api.delete_credentials_for_project(
            self.project_id
        )
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.project_id
        self.assertRaises(exception.CredentialNotFound,
                          PROVIDERS.credential_api.get_credential,
                          credential_id=self.credential['id'])

    def test_credential_api_delete_credentials_for_user(self):
        PROVIDERS.credential_api.delete_credentials_for_user(self.user_id)
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.user_id
        self.assertRaises(exception.CredentialNotFound,
                          PROVIDERS.credential_api.get_credential,
                          credential_id=self.credential['id'])

    def test_list_credentials(self):
        """Call ``GET /credentials``."""
        r = self.get('/credentials')
        self.assertValidCredentialListResponse(r, ref=self.credential)

    def test_list_credentials_filtered_by_user_id(self):
        """Call ``GET  /credentials?user_id={user_id}``."""
        credential = unit.new_credential_ref(user_id=uuid.uuid4().hex)
        PROVIDERS.credential_api.create_credential(
            credential['id'], credential
        )

        r = self.get('/credentials?user_id=%s' % self.user['id'])
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
        ec2_credential = unit.new_credential_ref(user_id=uuid.uuid4().hex,
                                                 project_id=self.project_id,
                                                 type=CRED_TYPE_EC2)

        ec2_resp = PROVIDERS.credential_api.create_credential(
            ec2_credential['id'], ec2_credential)

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
        credential_user1_ec2 = unit.new_credential_ref(user_id=user1_id,
                                                       type=CRED_TYPE_EC2)
        credential_user1_cert = unit.new_credential_ref(user_id=user1_id)
        credential_user2_cert = unit.new_credential_ref(user_id=user2_id)

        PROVIDERS.credential_api.create_credential(
            credential_user1_ec2['id'], credential_user1_ec2)
        PROVIDERS.credential_api.create_credential(
            credential_user1_cert['id'], credential_user1_cert)
        PROVIDERS.credential_api.create_credential(
            credential_user2_cert['id'], credential_user2_cert)

        r = self.get(
            '/credentials?user_id=%s&type=ec2' % user1_id, token=token
        )
        self.assertValidCredentialListResponse(r, ref=credential_user1_ec2)
        self.assertThat(r.result['credentials'], matchers.HasLength(1))
        cred = r.result['credentials'][0]
        self.assertEqual(CRED_TYPE_EC2, cred['type'])
        self.assertEqual(user1_id, cred['user_id'])

    def test_create_credential(self):
        """Call ``POST /credentials``."""
        ref = unit.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

    def test_get_credential(self):
        """Call ``GET /credentials/{credential_id}``."""
        r = self.get(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential['id']})
        self.assertValidCredentialResponse(r, self.credential)

    def test_update_credential(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        ref = unit.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id)
        del ref['id']
        r = self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential['id']},
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

    def test_update_credential_to_ec2_type(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        # Create a credential without providing a project_id
        ref = unit.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']

        # Updating the credential to ec2 requires a project_id
        update_ref = {'type': 'ec2', 'project_id': self.project_id}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref})

    def test_update_credential_to_ec2_missing_project_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        # Create a credential without providing a project_id
        ref = unit.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']

        # Updating such credential to ec2 type without providing a project_id
        # will fail
        update_ref = {'type': 'ec2'}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)

    def test_update_credential_to_ec2_with_previously_set_project_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        # Create a credential providing a project_id
        ref = unit.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id)
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']

        # Since the created credential above already has a project_id, the
        # update request will not fail
        update_ref = {'type': 'ec2'}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref})

    def test_update_credential_non_owner(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        alt_user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id)
        alt_user_id = alt_user['id']
        alt_project = unit.new_project_ref(domain_id=self.domain_id)
        alt_project_id = alt_project['id']
        PROVIDERS.resource_api.create_project(
            alt_project['id'], alt_project)
        alt_role = unit.new_role_ref(name='reader')
        alt_role_id = alt_role['id']
        PROVIDERS.role_api.create_role(alt_role_id, alt_role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            alt_user_id, alt_project_id, alt_role_id)
        auth = self.build_authentication_request(
            user_id=alt_user_id,
            password=alt_user['password'],
            project_id=alt_project_id)
        ref = unit.new_credential_ref(user_id=alt_user_id,
                                      project_id=alt_project_id)
        r = self.post(
            '/credentials',
            auth=auth,
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']

        # Cannot change the credential to be owned by another user
        update_ref = {'user_id': self.user_id, 'project_id': self.project_id}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            expected_status=403,
            auth=auth,
            body={'credential': update_ref})

    def test_update_ec2_credential_change_trust_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(user_id=self.user['id'],
                                            project_id=self.project_id)
        blob['trust_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different trust
        blob['trust_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)
        # Try removing the trust
        del blob['trust_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)

    def test_update_ec2_credential_change_app_cred_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(user_id=self.user['id'],
                                            project_id=self.project_id)
        blob['app_cred_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different app cred
        blob['app_cred_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)
        # Try removing the app cred
        del blob['app_cred_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)

    def test_update_ec2_credential_change_access_token_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(user_id=self.user['id'],
                                            project_id=self.project_id)
        blob['access_token_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different access token
        blob['access_token_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)
        # Try removing the access token
        del blob['access_token_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)

    def test_update_ec2_credential_change_access_id(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        blob, ref = unit.new_ec2_credential(user_id=self.user['id'],
                                            project_id=self.project_id)
        blob['access_id'] = uuid.uuid4().hex
        ref['blob'] = json.dumps(blob)
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        credential_id = r.result.get('credential')['id']
        # Try changing to a different access_id
        blob['access_id'] = uuid.uuid4().hex
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)
        # Try removing the access_id
        del blob['access_id']
        update_ref = {'blob': json.dumps(blob)}
        self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id},
            body={'credential': update_ref},
            expected_status=http.client.BAD_REQUEST)

    def test_delete_credential(self):
        """Call ``DELETE /credentials/{credential_id}``."""
        self.delete(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential['id']})

    def test_delete_credential_retries_on_deadlock(self):
        patcher = mock.patch('sqlalchemy.orm.query.Query.delete',
                             autospec=True)

        class FakeDeadlock(object):
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
                user_id=self.user['id'])
        finally:
            if side_effect.patched:
                patcher.stop()

        # initial attempt + 1 retry
        self.assertEqual(sql_delete_mock.call_count, 2)

    def test_create_ec2_credential(self):
        """Call ``POST /credentials`` for creating ec2 credential."""
        blob, ref = unit.new_ec2_credential(user_id=self.user['id'],
                                            project_id=self.project_id)
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        access = blob['access'].encode('utf-8')
        self.assertEqual(hashlib.sha256(access).hexdigest(),
                         r.result['credential']['id'])
        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.post(
            '/credentials',
            body={'credential': ref}, expected_status=http.client.CONFLICT)

    def test_get_ec2_dict_blob(self):
        """Ensure non-JSON blob data is correctly converted."""
        expected_blob, credential_id = self._create_dict_blob_credential()

        r = self.get(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id})

        # use json.loads to transform the blobs back into Python dictionaries
        # to avoid problems with the keys being in different orders.
        self.assertEqual(json.loads(expected_blob),
                         json.loads(r.result['credential']['blob']))

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
                self.assertEqual(json.loads(expected_blob),
                                 json.loads(r['blob']))

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
        self.assertNotEqual(hashlib.sha256(access).hexdigest(),
                            r.result['credential']['id'])

    def test_create_ec2_credential_with_missing_project_id(self):
        """Test Creating ec2 credential with missing project_id.

        Call ``POST /credentials``.
        """
        _, ref = unit.new_ec2_credential(user_id=self.user['id'],
                                         project_id=None)
        # Assert bad request status when missing project_id
        self.post(
            '/credentials',
            body={'credential': ref}, expected_status=http.client.BAD_REQUEST)

    def test_create_ec2_credential_with_invalid_blob(self):
        """Test creating ec2 credential with invalid blob.

        Call ``POST /credentials``.
        """
        ref = unit.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id,
                                      blob='{"abc":"def"d}',
                                      type=CRED_TYPE_EC2)
        # Assert bad request status when request contains invalid blob
        response = self.post(
            '/credentials',
            body={'credential': ref}, expected_status=http.client.BAD_REQUEST)
        self.assertValidErrorResponse(response)

    def test_create_credential_with_admin_token(self):
        # Make sure we can create credential with the static admin token
        ref = unit.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref},
            token=self.get_admin_token())
        self.assertValidCredentialResponse(r, ref)


class TestCredentialTrustScoped(CredentialBaseTestCase):
    """Test credential with trust scoped token."""

    def setUp(self):
        super(TestCredentialTrustScoped, self).setUp()

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
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    def config_overrides(self):
        super(TestCredentialTrustScoped, self).config_overrides()
        self.config_fixture.config(group='trust')

    def test_trust_scoped_ec2_credential(self):
        """Test creating trust scoped ec2 credential.

        Call ``POST /credentials``.
        """
        # Create the trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        # Get a trust scoped token
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r, self.user)
        trust_id = r.result['token']['OS-TRUST:trust']['id']
        token_id = r.headers.get('X-Subject-Token')

        # Create the credential with the trust scoped token
        blob, ref = unit.new_ec2_credential(user_id=self.user_id,
                                            project_id=self.project_id)
        r = self.post('/credentials', body={'credential': ref}, token=token_id)

        # We expect the response blob to contain the trust_id
        ret_ref = ref.copy()
        ret_blob = blob.copy()
        ret_blob['trust_id'] = trust_id
        ret_ref['blob'] = json.dumps(ret_blob)
        self.assertValidCredentialResponse(r, ref=ret_ref)

        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        access = blob['access'].encode('utf-8')
        self.assertEqual(hashlib.sha256(access).hexdigest(),
                         r.result['credential']['id'])

        # Create a role assignment to ensure that it is ignored and only the
        # trust-delegated roles are used
        role = unit.new_role_ref(name='reader')
        role_id = role['id']
        PROVIDERS.role_api.create_role(role_id, role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, role_id)

        ret_blob = json.loads(r.result['credential']['blob'])
        ec2token = self._test_get_token(
            access=ret_blob['access'], secret=ret_blob['secret'])
        ec2_roles = [role['id'] for role in ec2token['roles']]
        self.assertIn(self.role_id, ec2_roles)
        self.assertNotIn(role_id, ec2_roles)

        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=http.client.CONFLICT)


class TestCredentialAppCreds(CredentialBaseTestCase):
    """Test credential with application credential token."""

    def setUp(self):
        super(TestCredentialAppCreds, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    def test_app_cred_ec2_credential(self):
        """Test creating ec2 credential from an application credential.

        Call ``POST /credentials``.
        """
        # Create the app cred
        ref = unit.new_application_credential_ref(roles=[{'id': self.role_id}])
        del ref['id']
        r = self.post('/users/%s/application_credentials' % self.user_id,
                      body={'application_credential': ref})
        app_cred = r.result['application_credential']

        # Get an application credential token
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred['id'],
            secret=app_cred['secret'])
        r = self.v3_create_token(auth_data)
        token_id = r.headers.get('X-Subject-Token')

        # Create the credential with the app cred token
        blob, ref = unit.new_ec2_credential(user_id=self.user_id,
                                            project_id=self.project_id)
        r = self.post('/credentials', body={'credential': ref}, token=token_id)

        # We expect the response blob to contain the app_cred_id
        ret_ref = ref.copy()
        ret_blob = blob.copy()
        ret_blob['app_cred_id'] = app_cred['id']
        ret_ref['blob'] = json.dumps(ret_blob)
        self.assertValidCredentialResponse(r, ref=ret_ref)

        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        access = blob['access'].encode('utf-8')
        self.assertEqual(hashlib.sha256(access).hexdigest(),
                         r.result['credential']['id'])

        # Create a role assignment to ensure that it is ignored and only the
        # roles in the app cred are used
        role = unit.new_role_ref(name='reader')
        role_id = role['id']
        PROVIDERS.role_api.create_role(role_id, role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, role_id)

        ret_blob = json.loads(r.result['credential']['blob'])
        ec2token = self._test_get_token(
            access=ret_blob['access'], secret=ret_blob['secret'])
        ec2_roles = [role['id'] for role in ec2token['roles']]
        self.assertIn(self.role_id, ec2_roles)
        self.assertNotIn(role_id, ec2_roles)

        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=http.client.CONFLICT)


class TestCredentialAccessToken(CredentialBaseTestCase):
    """Test credential with access token."""

    def setUp(self):
        super(TestCredentialAccessToken, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
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
        client = oauth1.Client(consumer['key'],
                               client_secret=consumer['secret'],
                               signature_method=oauth1.SIG_HMAC,
                               callback_uri="oob")
        headers = {'requested_project_id': project_id}
        if not base_url:
            base_url = self.base_url
        url, headers, body = client.sign(base_url + endpoint,
                                         http_method='POST',
                                         headers=headers)
        return endpoint, headers

    def _create_access_token(self, consumer, token, base_url=None):
        endpoint = '/OS-OAUTH1/access_token'
        client = oauth1.Client(consumer['key'],
                               client_secret=consumer['secret'],
                               resource_owner_key=token.key,
                               resource_owner_secret=token.secret,
                               signature_method=oauth1.SIG_HMAC,
                               verifier=token.verifier)
        if not base_url:
            base_url = self.base_url
        url, headers, body = client.sign(base_url + endpoint,
                                         http_method='POST')
        headers.update({'Content-Type': 'application/json'})
        return endpoint, headers

    def _get_oauth_token(self, consumer, token):
        client = oauth1.Client(consumer['key'],
                               client_secret=consumer['secret'],
                               resource_owner_key=token.key,
                               resource_owner_secret=token.secret,
                               signature_method=oauth1.SIG_HMAC)
        endpoint = '/auth/tokens'
        url, headers, body = client.sign(self.base_url + endpoint,
                                         http_method='POST')
        headers.update({'Content-Type': 'application/json'})
        ref = {'auth': {'identity': {'oauth1': {}, 'methods': ['oauth1']}}}
        return endpoint, headers, ref

    def _authorize_request_token(self, request_id):
        if isinstance(request_id, bytes):
            request_id = request_id.decode()
        return '/OS-OAUTH1/authorize/%s' % (request_id)

    def _get_access_token(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        consumer = {'key': consumer_id, 'secret': consumer_secret}

        url, headers = self._create_request_token(consumer, self.project_id)
        content = self.post(
            url, headers=headers,
            response_content_type='application/x-www-form-urlencoded')
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
            url, headers=headers,
            response_content_type='application/x-www-form-urlencoded')
        credentials = self._urllib_parse_qs_text_keys(content.result)
        access_key = credentials['oauth_token'][0]
        access_secret = credentials['oauth_token_secret'][0]
        access_token = oauth1.Token(access_key, access_secret)

        url, headers, body = self._get_oauth_token(consumer, access_token)
        content = self.post(url, headers=headers, body=body)
        return access_key, content.headers['X-Subject-Token']

    def test_access_token_ec2_credential(self):
        """Test creating ec2 credential from an oauth access token.

        Call ``POST /credentials``.
        """
        access_key, token_id = self._get_access_token()

        # Create the credential with the access token
        blob, ref = unit.new_ec2_credential(user_id=self.user_id,
                                            project_id=self.project_id)
        r = self.post('/credentials', body={'credential': ref}, token=token_id)

        # We expect the response blob to contain the access_token_id
        ret_ref = ref.copy()
        ret_blob = blob.copy()
        ret_blob['access_token_id'] = access_key.decode('utf-8')
        ret_ref['blob'] = json.dumps(ret_blob)
        self.assertValidCredentialResponse(r, ref=ret_ref)

        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        access = blob['access'].encode('utf-8')
        self.assertEqual(hashlib.sha256(access).hexdigest(),
                         r.result['credential']['id'])

        # Create a role assignment to ensure that it is ignored and only the
        # roles in the access token are used
        role = unit.new_role_ref(name='reader')
        role_id = role['id']
        PROVIDERS.role_api.create_role(role_id, role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, role_id)

        ret_blob = json.loads(r.result['credential']['blob'])
        ec2token = self._test_get_token(
            access=ret_blob['access'], secret=ret_blob['secret'])
        ec2_roles = [role['id'] for role in ec2token['roles']]
        self.assertIn(self.role_id, ec2_roles)
        self.assertNotIn(role_id, ec2_roles)


class TestCredentialEc2(CredentialBaseTestCase):
    """Test v3 credential compatibility with ec2tokens."""

    def test_ec2_credential_signature_validate(self):
        """Test signature validation with a v3 ec2 credential."""
        blob, ref = unit.new_ec2_credential(user_id=self.user['id'],
                                            project_id=self.project_id)
        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is same as hash of access key id
        access = blob['access'].encode('utf-8')
        self.assertEqual(hashlib.sha256(access).hexdigest(),
                         r.result['credential']['id'])

        cred_blob = json.loads(r.result['credential']['blob'])
        self.assertEqual(blob, cred_blob)
        self._test_get_token(access=cred_blob['access'],
                             secret=cred_blob['secret'])

    def test_ec2_credential_signature_validate_legacy(self):
        """Test signature validation with a legacy v3 ec2 credential."""
        cred_json, _ = self._create_dict_blob_credential()
        cred_blob = json.loads(cred_json)
        self._test_get_token(access=cred_blob['access'],
                             secret=cred_blob['secret'])

    def _get_ec2_cred_uri(self):
        return '/users/%s/credentials/OS-EC2' % self.user_id

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
        self._test_get_token(access=ec2_cred['access'],
                             secret=ec2_cred['secret'])
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        self.assertThat(ec2_cred['links']['self'],
                        matchers.EndsWith(uri))

    def test_ec2_get_credential(self):
        ec2_cred = self._get_ec2_cred()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        r = self.get(uri)
        self.assertDictEqual(ec2_cred, r.result['credential'])
        self.assertThat(ec2_cred['links']['self'],
                        matchers.EndsWith(uri))

    def test_ec2_cannot_get_non_ec2_credential(self):
        access_key = uuid.uuid4().hex
        cred_id = utils.hash_access_key(access_key)
        non_ec2_cred = unit.new_credential_ref(
            user_id=self.user_id,
            project_id=self.project_id)
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
        self.assertThat(r.result['links']['self'],
                        matchers.EndsWith(uri))

        # non-EC2 credentials won't be fetched
        non_ec2_cred = unit.new_credential_ref(
            user_id=self.user_id,
            project_id=self.project_id)
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
            PROVIDERS.credential_api
            .list_credentials_for_user(self.user_id, type=CRED_TYPE_EC2))
        self.assertEqual(1, len(cred_from_credential_api))
        self.delete(uri)
        self.assertRaises(exception.CredentialNotFound,
                          PROVIDERS.credential_api.get_credential,
                          cred_from_credential_api[0]['id'])
