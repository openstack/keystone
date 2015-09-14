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
import uuid

from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_config import cfg
from six.moves import http_client
from testtools import matchers

from keystone import exception
from keystone.tests.unit import test_v3


CONF = cfg.CONF


class CredentialBaseTestCase(test_v3.RestfulTestCase):
    def _create_dict_blob_credential(self):
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        credential_id = hashlib.sha256(blob['access']).hexdigest()
        credential = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        credential['id'] = credential_id

        # Store the blob as a dict *not* JSON ref bug #1259584
        # This means we can test the dict->json workaround, added
        # as part of the bugfix for backwards compatibility works.
        credential['blob'] = blob
        credential['type'] = 'ec2'
        # Create direct via the DB API to avoid validation failure
        self.credential_api.create_credential(
            credential_id,
            credential)
        expected_blob = json.dumps(blob)
        return expected_blob, credential_id


class CredentialTestCase(CredentialBaseTestCase):
    """Test credential CRUD."""
    def setUp(self):

        super(CredentialTestCase, self).setUp()

        self.credential_id = uuid.uuid4().hex
        self.credential = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        self.credential['id'] = self.credential_id
        self.credential_api.create_credential(
            self.credential_id,
            self.credential)

    def test_credential_api_delete_credentials_for_project(self):
        self.credential_api.delete_credentials_for_project(self.project_id)
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.project_id
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          credential_id=self.credential_id)

    def test_credential_api_delete_credentials_for_user(self):
        self.credential_api.delete_credentials_for_user(self.user_id)
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.user_id
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          credential_id=self.credential_id)

    def test_list_credentials(self):
        """Call ``GET /credentials``."""
        r = self.get('/credentials')
        self.assertValidCredentialListResponse(r, ref=self.credential)

    def test_list_credentials_filtered_by_user_id(self):
        """Call ``GET  /credentials?user_id={user_id}``."""
        credential = self.new_credential_ref(
            user_id=uuid.uuid4().hex)
        self.credential_api.create_credential(
            credential['id'], credential)

        r = self.get('/credentials?user_id=%s' % self.user['id'])
        self.assertValidCredentialListResponse(r, ref=self.credential)
        for cred in r.result['credentials']:
            self.assertEqual(self.user['id'], cred['user_id'])

    def test_list_credentials_filtered_by_type(self):
        """Call ``GET  /credentials?type={type}``."""
        # The type ec2 was chosen, instead of a random string,
        # because the type must be in the list of supported types
        ec2_credential = self.new_credential_ref(user_id=uuid.uuid4().hex,
                                                 project_id=self.project_id,
                                                 cred_type='ec2')

        ec2_resp = self.credential_api.create_credential(
            ec2_credential['id'], ec2_credential)

        # The type cert was chosen for the same reason as ec2
        r = self.get('/credentials?type=cert')

        # Testing the filter for two different types
        self.assertValidCredentialListResponse(r, ref=self.credential)
        for cred in r.result['credentials']:
            self.assertEqual('cert', cred['type'])

        r_ec2 = self.get('/credentials?type=ec2')
        self.assertThat(r_ec2.result['credentials'], matchers.HasLength(1))
        cred_ec2 = r_ec2.result['credentials'][0]

        self.assertValidCredentialListResponse(r_ec2, ref=ec2_resp)
        self.assertEqual('ec2', cred_ec2['type'])
        self.assertEqual(cred_ec2['id'], ec2_credential['id'])

    def test_list_credentials_filtered_by_type_and_user_id(self):
        """Call ``GET  /credentials?user_id={user_id}&type={type}``."""
        user1_id = uuid.uuid4().hex
        user2_id = uuid.uuid4().hex

        # Creating credentials for two different users
        credential_user1_ec2 = self.new_credential_ref(
            user_id=user1_id, cred_type='ec2')
        credential_user1_cert = self.new_credential_ref(
            user_id=user1_id)
        credential_user2_cert = self.new_credential_ref(
            user_id=user2_id)

        self.credential_api.create_credential(
            credential_user1_ec2['id'], credential_user1_ec2)
        self.credential_api.create_credential(
            credential_user1_cert['id'], credential_user1_cert)
        self.credential_api.create_credential(
            credential_user2_cert['id'], credential_user2_cert)

        r = self.get('/credentials?user_id=%s&type=ec2' % user1_id)
        self.assertValidCredentialListResponse(r, ref=credential_user1_ec2)
        self.assertThat(r.result['credentials'], matchers.HasLength(1))
        cred = r.result['credentials'][0]
        self.assertEqual('ec2', cred['type'])
        self.assertEqual(user1_id, cred['user_id'])

    def test_create_credential(self):
        """Call ``POST /credentials``."""
        ref = self.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

    def test_get_credential(self):
        """Call ``GET /credentials/{credential_id}``."""
        r = self.get(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential_id})
        self.assertValidCredentialResponse(r, self.credential)

    def test_update_credential(self):
        """Call ``PATCH /credentials/{credential_id}``."""
        ref = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        del ref['id']
        r = self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential_id},
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

    def test_delete_credential(self):
        """Call ``DELETE /credentials/{credential_id}``."""
        self.delete(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential_id})

    def test_create_ec2_credential(self):
        """Call ``POST /credentials`` for creating ec2 credential."""
        ref = self.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id)
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        ref['blob'] = json.dumps(blob)
        ref['type'] = 'ec2'
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        self.assertEqual(r.result['credential']['id'],
                         hashlib.sha256(blob['access']).hexdigest())
        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.post(
            '/credentials',
            body={'credential': ref}, expected_status=409)

    def test_get_ec2_dict_blob(self):
        """Ensure non-JSON blob data is correctly converted."""
        expected_blob, credential_id = self._create_dict_blob_credential()

        r = self.get(
            '/credentials/%(credential_id)s' % {
                'credential_id': credential_id})
        self.assertEqual(expected_blob, r.result['credential']['blob'])

    def test_list_ec2_dict_blob(self):
        """Ensure non-JSON blob data is correctly converted."""
        expected_blob, credential_id = self._create_dict_blob_credential()

        list_r = self.get('/credentials')
        list_creds = list_r.result['credentials']
        list_ids = [r['id'] for r in list_creds]
        self.assertIn(credential_id, list_ids)
        for r in list_creds:
            if r['id'] == credential_id:
                self.assertEqual(expected_blob, r['blob'])

    def test_create_non_ec2_credential(self):
        """Call ``POST /credentials`` for creating non-ec2 credential."""
        ref = self.new_credential_ref(user_id=self.user['id'])
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        ref['blob'] = json.dumps(blob)
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is not same as hash of access key id for
        # non-ec2 credentials
        self.assertNotEqual(r.result['credential']['id'],
                            hashlib.sha256(blob['access']).hexdigest())

    def test_create_ec2_credential_with_missing_project_id(self):
        """Call ``POST /credentials`` for creating ec2
           credential with missing project_id.
        """
        ref = self.new_credential_ref(user_id=self.user['id'])
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        ref['blob'] = json.dumps(blob)
        ref['type'] = 'ec2'
        # Assert bad request status when missing project_id
        self.post(
            '/credentials',
            body={'credential': ref}, expected_status=http_client.BAD_REQUEST)

    def test_create_ec2_credential_with_invalid_blob(self):
        """Call ``POST /credentials`` for creating ec2
           credential with invalid blob.
        """
        ref = self.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id)
        ref['blob'] = '{"abc":"def"d}'
        ref['type'] = 'ec2'
        # Assert bad request status when request contains invalid blob
        response = self.post(
            '/credentials',
            body={'credential': ref}, expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(response)

    def test_create_credential_with_admin_token(self):
        # Make sure we can create credential with the static admin token
        ref = self.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref},
            token=CONF.admin_token)
        self.assertValidCredentialResponse(r, ref)


class TestCredentialTrustScoped(test_v3.RestfulTestCase):
    """Test credential with trust scoped token."""
    def setUp(self):
        super(TestCredentialTrustScoped, self).setUp()

        self.trustee_user = self.new_user_ref(domain_id=self.domain_id)
        password = self.trustee_user['password']
        self.trustee_user = self.identity_api.create_user(self.trustee_user)
        self.trustee_user['password'] = password
        self.trustee_user_id = self.trustee_user['id']

    def config_overrides(self):
        super(TestCredentialTrustScoped, self).config_overrides()
        self.config_fixture.config(group='trust', enabled=True)

    def test_trust_scoped_ec2_credential(self):
        """Call ``POST /credentials`` for creating ec2 credential."""
        # Create the trust
        ref = self.new_trust_ref(
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
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(r, self.user)
        trust_id = r.result['token']['OS-TRUST:trust']['id']
        token_id = r.headers.get('X-Subject-Token')

        # Create the credential with the trust scoped token
        ref = self.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id)
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        ref['blob'] = json.dumps(blob)
        ref['type'] = 'ec2'
        r = self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id)

        # We expect the response blob to contain the trust_id
        ret_ref = ref.copy()
        ret_blob = blob.copy()
        ret_blob['trust_id'] = trust_id
        ret_ref['blob'] = json.dumps(ret_blob)
        self.assertValidCredentialResponse(r, ref=ret_ref)

        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        self.assertEqual(r.result['credential']['id'],
                         hashlib.sha256(blob['access']).hexdigest())

        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=409)


class TestCredentialEc2(CredentialBaseTestCase):
    """Test v3 credential compatibility with ec2tokens."""
    def setUp(self):
        super(TestCredentialEc2, self).setUp()

    def _validate_signature(self, access, secret):
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
            expected_status=200)
        self.assertValidTokenResponse(r)

    def test_ec2_credential_signature_validate(self):
        """Test signature validation with a v3 ec2 credential."""
        ref = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        ref['blob'] = json.dumps(blob)
        ref['type'] = 'ec2'
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is same as hash of access key id
        self.assertEqual(r.result['credential']['id'],
                         hashlib.sha256(blob['access']).hexdigest())

        cred_blob = json.loads(r.result['credential']['blob'])
        self.assertEqual(blob, cred_blob)
        self._validate_signature(access=cred_blob['access'],
                                 secret=cred_blob['secret'])

    def test_ec2_credential_signature_validate_legacy(self):
        """Test signature validation with a legacy v3 ec2 credential."""
        cred_json, credential_id = self._create_dict_blob_credential()
        cred_blob = json.loads(cred_json)
        self._validate_signature(access=cred_blob['access'],
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
        self._validate_signature(access=ec2_cred['access'],
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

    def test_ec2_list_credentials(self):
        """Test ec2 credential listing."""
        self._get_ec2_cred()
        uri = self._get_ec2_cred_uri()
        r = self.get(uri)
        cred_list = r.result['credentials']
        self.assertEqual(1, len(cred_list))
        self.assertThat(r.result['links']['self'],
                        matchers.EndsWith(uri))

    def test_ec2_delete_credential(self):
        """Test ec2 credential deletion."""
        ec2_cred = self._get_ec2_cred()
        uri = '/'.join([self._get_ec2_cred_uri(), ec2_cred['access']])
        cred_from_credential_api = (
            self.credential_api
            .list_credentials_for_user(self.user_id))
        self.assertEqual(1, len(cred_from_credential_api))
        self.delete(uri)
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          cred_from_credential_api[0]['id'])
