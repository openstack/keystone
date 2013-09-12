# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.tests import test_v3


class CredentialTestCase(test_v3.RestfulTestCase):
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

    def test_list_credentials(self):
        """Call ``GET /credentials``."""
        r = self.get('/credentials')
        self.assertValidCredentialListResponse(r, ref=self.credential)

    def test_list_credentials_xml(self):
        """Call ``GET /credentials`` (xml data)."""
        r = self.get('/credentials', content_type='xml')
        self.assertValidCredentialListResponse(r, ref=self.credential)

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
        ref = self.new_credential_ref(user_id=self.user['id'])
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

    def test_create_ec2_credential_with_invalid_blob(self):
        """Call ``POST /credentials`` for creating ec2
           credential with invalid blob.
        """
        ref = self.new_credential_ref(user_id=self.user['id'])
        ref['blob'] = '{"abc":"def"d}'
        ref['type'] = 'ec2'
        # Assert 400 status for bad request containing invalid
        # blob
        response = self.post(
            '/credentials',
            body={'credential': ref}, expected_status=400)
        self.assertValidErrorResponse(response)
