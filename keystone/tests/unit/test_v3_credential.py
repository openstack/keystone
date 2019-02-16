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
from oslo_serialization import jsonutils
from six.moves import http_client
from testtools import matchers

from keystone.common import provider_api
from keystone.common import utils
from keystone.contrib.ec2 import controllers
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile
from keystone.tests.unit import test_v3


PROVIDERS = provider_api.ProviderAPIs
CRED_TYPE_EC2 = controllers.CRED_TYPE_EC2


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
        # The type ec2 was chosen, instead of a random string,
        # because the type must be in the list of supported types
        ec2_credential = unit.new_credential_ref(user_id=uuid.uuid4().hex,
                                                 project_id=self.project_id,
                                                 type=CRED_TYPE_EC2)

        ec2_resp = PROVIDERS.credential_api.create_credential(
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
        self.assertEqual(CRED_TYPE_EC2, cred_ec2['type'])
        self.assertEqual(ec2_credential['id'], cred_ec2['id'])

    def test_list_credentials_filtered_by_type_and_user_id(self):
        """Call ``GET  /credentials?user_id={user_id}&type={type}``."""
        user1_id = uuid.uuid4().hex
        user2_id = uuid.uuid4().hex

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

        r = self.get('/credentials?user_id=%s&type=ec2' % user1_id)
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
            expected_status=http_client.BAD_REQUEST)

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

    def test_delete_credential(self):
        """Call ``DELETE /credentials/{credential_id}``."""
        self.delete(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential['id']})

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
            body={'credential': ref}, expected_status=http_client.CONFLICT)

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
            body={'credential': ref}, expected_status=http_client.BAD_REQUEST)

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
            body={'credential': ref}, expected_status=http_client.BAD_REQUEST)
        self.assertValidErrorResponse(response)

    def test_create_credential_with_admin_token(self):
        # Make sure we can create credential with the static admin token
        ref = unit.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref},
            token=self.get_admin_token())
        self.assertValidCredentialResponse(r, ref)


class CredentialSelfServiceTestCase(CredentialBaseTestCase):
    """Test self-service credential CRUD."""

    def _policy_fixture(self):
        return ksfixtures.Policy(self.tmpfilename, self.config_fixture)

    def _set_policy(self, new_policy):
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write(jsonutils.dumps(new_policy))

    def setUp(self):
        self.tempfile = self.useFixture(temporaryfile.SecureTempFile())
        self.tmpfilename = self.tempfile.file_name
        super(CredentialSelfServiceTestCase, self).setUp()

        # set the self-service credential policies
        self_service_credential_policies = {
            "identity:create_credential": "user_id:%(credential.user_id)s",
            "identity:list_credentials": "user_id:%(user_id)s",
            "identity:get_credential": "user_id:%(target.credential.user_id)s",
            "identity:update_credential":
                "user_id:%(target.credential.user_id)s",
            "identity:delete_credential":
                "user_id:%(target.credential.user_id)s"
        }
        self._set_policy(self_service_credential_policies)

        # remove the 'admin' role from user and replace it with an
        # arbitrary role
        PROVIDERS.assignment_api.remove_role_from_user_and_project(
            self.user_id, self.project_id, self.role_id)
        self.arbitrary_role = unit.new_role_ref(name=uuid.uuid4().hex)
        PROVIDERS.role_api.create_role(self.arbitrary_role['id'],
                                       self.arbitrary_role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, self.arbitrary_role['id'])

        self.credential = unit.new_credential_ref(user_id=self.user['id'],
                                                  project_id=self.project_id)

        PROVIDERS.credential_api.create_credential(
            self.credential['id'],
            self.credential)

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

    def test_delete_credential(self):
        """Call ``DELETE /credentials/{credential_id}``."""
        self.delete(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential['id']})


class TestCredentialTrustScoped(test_v3.RestfulTestCase):
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
        blob, ref = unit.new_ec2_credential(user_id=self.user['id'],
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

        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.post(
            '/credentials',
            body={'credential': ref},
            token=token_id,
            expected_status=http_client.CONFLICT)


class TestCredentialEc2(CredentialBaseTestCase):
    """Test v3 credential compatibility with ec2tokens."""

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
            expected_status=http_client.OK)
        self.assertValidTokenResponse(r)

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
        self._validate_signature(access=cred_blob['access'],
                                 secret=cred_blob['secret'])

    def test_ec2_credential_signature_validate_legacy(self):
        """Test signature validation with a legacy v3 ec2 credential."""
        cred_json, _ = self._create_dict_blob_credential()
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
        self.get(uri, expected_status=http_client.UNAUTHORIZED)

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
