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

import copy
import os
import tempfile
import uuid

from six.moves import urllib

from keystone.common import sql
from keystone.common.sql import migration_helpers
from keystone import config
from keystone import contrib
from keystone.contrib import oauth1
from keystone.contrib.oauth1 import controllers
from keystone import exception
from keystone.openstack.common.db.sqlalchemy import migration
from keystone.openstack.common import importutils
from keystone.openstack.common import jsonutils
from keystone.tests import test_v3


CONF = config.CONF


class OAuth1Tests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'oauth1'
    EXTENSION_TO_ADD = 'oauth1_extension'

    CONSUMER_URL = '/OS-OAUTH1/consumers'

    def setup_database(self):
        super(OAuth1Tests, self).setup_database()
        package_name = '.'.join((contrib.__name__, self.EXTENSION_NAME))
        package = importutils.import_module(package_name)
        abs_path = migration_helpers.find_migrate_repo(package)
        migration.db_version_control(sql.get_engine(), abs_path)
        migration.db_sync(sql.get_engine(), abs_path)

    def setUp(self):
        super(OAuth1Tests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        self.controller = controllers.OAuthControllerV3()

    def _create_single_consumer(self):
        ref = {'description': uuid.uuid4().hex}
        resp = self.post(
            self.CONSUMER_URL,
            body={'consumer': ref})
        return resp.result['consumer']

    def _create_request_token(self, consumer, project_id):
        endpoint = '/OS-OAUTH1/request_token'
        client = oauth1.Client(consumer['key'],
                               client_secret=consumer['secret'],
                               signature_method=oauth1.SIG_HMAC,
                               callback_uri="oob")
        headers = {'requested_project_id': project_id}
        url, headers, body = client.sign(self.base_url + endpoint,
                                         http_method='POST',
                                         headers=headers)
        return endpoint, headers

    def _create_access_token(self, consumer, token):
        endpoint = '/OS-OAUTH1/access_token'
        client = oauth1.Client(consumer['key'],
                               client_secret=consumer['secret'],
                               resource_owner_key=token.key,
                               resource_owner_secret=token.secret,
                               signature_method=oauth1.SIG_HMAC,
                               verifier=token.verifier)
        url, headers, body = client.sign(self.base_url + endpoint,
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
        return '/OS-OAUTH1/authorize/%s' % (request_id)


class ConsumerCRUDTests(OAuth1Tests):

    def _consumer_create(self, description=None, description_flag=True,
                         **kwargs):
        if description_flag:
            ref = {'description': description}
        else:
            ref = {}
        if kwargs:
            ref.update(kwargs)
        resp = self.post(
            self.CONSUMER_URL,
            body={'consumer': ref})
        consumer = resp.result['consumer']
        consumer_id = consumer['id']
        self.assertEqual(consumer['description'], description)
        self.assertIsNotNone(consumer_id)
        self.assertIsNotNone(consumer['secret'])
        return consumer

    def test_consumer_create(self):
        description = uuid.uuid4().hex
        self._consumer_create(description=description)

    def test_consumer_create_none_desc_1(self):
        self._consumer_create()

    def test_consumer_create_none_desc_2(self):
        self._consumer_create(description_flag=False)

    def test_consumer_create_normalize_field(self):
        # If create a consumer with a field with : or - in the name,
        # the name is normalized by converting those chars to _.
        field_name = 'some:weird-field'
        field_value = uuid.uuid4().hex
        extra_fields = {field_name: field_value}
        consumer = self._consumer_create(**extra_fields)
        normalized_field_name = 'some_weird_field'
        self.assertEqual(field_value, consumer[normalized_field_name])

    def test_consumer_delete(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        resp = self.delete(self.CONSUMER_URL + '/%s' % consumer_id)
        self.assertResponseStatus(resp, 204)

    def test_consumer_get(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        resp = self.get(self.CONSUMER_URL + '/%s' % consumer_id)
        self_url = ['http://localhost/v3', self.CONSUMER_URL,
                    '/', consumer_id]
        self_url = ''.join(self_url)
        self.assertEqual(resp.result['consumer']['links']['self'], self_url)
        self.assertEqual(resp.result['consumer']['id'], consumer_id)

    def test_consumer_list(self):
        self._consumer_create()
        resp = self.get(self.CONSUMER_URL)
        entities = resp.result['consumers']
        self.assertIsNotNone(entities)
        self_url = ['http://localhost/v3', self.CONSUMER_URL]
        self_url = ''.join(self_url)
        self.assertEqual(resp.result['links']['self'], self_url)
        self.assertValidListLinks(resp.result['links'])

    def test_consumer_update(self):
        consumer = self._create_single_consumer()
        original_id = consumer['id']
        original_description = consumer['description']
        update_description = original_description + '_new'

        update_ref = {'description': update_description}
        update_resp = self.patch(self.CONSUMER_URL + '/%s' % original_id,
                                 body={'consumer': update_ref})
        consumer = update_resp.result['consumer']
        self.assertEqual(consumer['description'], update_description)
        self.assertEqual(consumer['id'], original_id)

    def test_consumer_update_bad_secret(self):
        consumer = self._create_single_consumer()
        original_id = consumer['id']
        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = uuid.uuid4().hex
        update_ref['secret'] = uuid.uuid4().hex
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_bad_id(self):
        consumer = self._create_single_consumer()
        original_id = consumer['id']
        original_description = consumer['description']
        update_description = original_description + "_new"

        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = update_description
        update_ref['id'] = update_description
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_normalize_field(self):
        # If update a consumer with a field with : or - in the name,
        # the name is normalized by converting those chars to _.
        field1_name = 'some:weird-field'
        field1_orig_value = uuid.uuid4().hex

        extra_fields = {field1_name: field1_orig_value}
        consumer = self._consumer_create(**extra_fields)
        consumer_id = consumer['id']

        field1_new_value = uuid.uuid4().hex

        field2_name = 'weird:some-field'
        field2_value = uuid.uuid4().hex

        update_ref = {field1_name: field1_new_value,
                      field2_name: field2_value}

        update_resp = self.patch(self.CONSUMER_URL + '/%s' % consumer_id,
                                 body={'consumer': update_ref})
        consumer = update_resp.result['consumer']

        normalized_field1_name = 'some_weird_field'
        self.assertEqual(field1_new_value, consumer[normalized_field1_name])

        normalized_field2_name = 'weird_some_field'
        self.assertEqual(field2_value, consumer[normalized_field2_name])

    def test_consumer_create_no_description(self):
        resp = self.post(self.CONSUMER_URL, body={'consumer': {}})
        consumer = resp.result['consumer']
        consumer_id = consumer['id']
        self.assertIsNone(consumer['description'])
        self.assertIsNotNone(consumer_id)
        self.assertIsNotNone(consumer['secret'])

    def test_consumer_get_bad_id(self):
        self.get(self.CONSUMER_URL + '/%(consumer_id)s'
                 % {'consumer_id': uuid.uuid4().hex},
                 expected_status=404)


class OAuthFlowTests(OAuth1Tests):

    def test_oauth_flow(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        self.consumer = {'key': consumer_id, 'secret': consumer_secret}
        self.assertIsNotNone(self.consumer['secret'])

        url, headers = self._create_request_token(self.consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        request_key = credentials['oauth_token'][0]
        request_secret = credentials['oauth_token_secret'][0]
        self.request_token = oauth1.Token(request_key, request_secret)
        self.assertIsNotNone(self.request_token.key)

        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        resp = self.put(url, body=body, expected_status=200)
        self.verifier = resp.result['token']['oauth_verifier']

        self.request_token.set_verifier(self.verifier)
        url, headers = self._create_access_token(self.consumer,
                                                 self.request_token)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        access_key = credentials['oauth_token'][0]
        access_secret = credentials['oauth_token_secret'][0]
        self.access_token = oauth1.Token(access_key, access_secret)
        self.assertIsNotNone(self.access_token.key)

        url, headers, body = self._get_oauth_token(self.consumer,
                                                   self.access_token)
        content = self.post(url, headers=headers, body=body)
        self.keystone_token_id = content.headers['X-Subject-Token']
        self.keystone_token = content.result['token']
        self.assertIsNotNone(self.keystone_token_id)


class AccessTokenCRUDTests(OAuthFlowTests):
    def test_delete_access_token_dne(self):
        self.delete('/users/%(user)s/OS-OAUTH1/access_tokens/%(auth)s'
                    % {'user': self.user_id,
                       'auth': uuid.uuid4().hex},
                    expected_status=404)

    def test_list_no_access_tokens(self):
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens'
                        % {'user_id': self.user_id})
        entities = resp.result['access_tokens']
        self.assertEqual([], entities)
        self.assertValidListLinks(resp.result['links'])

    def test_get_single_access_token(self):
        self.test_oauth_flow()
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens/%(key)s'
                        % {'user_id': self.user_id,
                           'key': self.access_token.key})
        entity = resp.result['access_token']
        self.assertEqual(entity['id'], self.access_token.key)
        self.assertEqual(entity['consumer_id'], self.consumer['key'])

    def test_get_access_token_dne(self):
        self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens/%(key)s'
                 % {'user_id': self.user_id,
                    'key': uuid.uuid4().hex},
                 expected_status=404)

    def test_list_all_roles_in_access_token(self):
        self.test_oauth_flow()
        resp = self.get('/users/%(id)s/OS-OAUTH1/access_tokens/%(key)s/roles'
                        % {'id': self.user_id,
                           'key': self.access_token.key})
        entities = resp.result['roles']
        self.assertTrue(entities)
        self.assertValidListLinks(resp.result['links'])

    def test_get_role_in_access_token(self):
        self.test_oauth_flow()
        url = ('/users/%(id)s/OS-OAUTH1/access_tokens/%(key)s/roles/%(role)s'
               % {'id': self.user_id, 'key': self.access_token.key,
                  'role': self.role_id})
        resp = self.get(url)
        entity = resp.result['role']
        self.assertEqual(entity['id'], self.role_id)

    def test_get_role_in_access_token_dne(self):
        self.test_oauth_flow()
        url = ('/users/%(id)s/OS-OAUTH1/access_tokens/%(key)s/roles/%(role)s'
               % {'id': self.user_id, 'key': self.access_token.key,
                  'role': uuid.uuid4().hex})
        self.get(url, expected_status=404)

    def test_list_and_delete_access_tokens(self):
        self.test_oauth_flow()
        # List access_tokens should be > 0
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens'
                        % {'user_id': self.user_id})
        entities = resp.result['access_tokens']
        self.assertTrue(entities)
        self.assertValidListLinks(resp.result['links'])

        # Delete access_token
        resp = self.delete('/users/%(user)s/OS-OAUTH1/access_tokens/%(auth)s'
                           % {'user': self.user_id,
                              'auth': self.access_token.key})
        self.assertResponseStatus(resp, 204)

        # List access_token should be 0
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens'
                        % {'user_id': self.user_id})
        entities = resp.result['access_tokens']
        self.assertEqual([], entities)
        self.assertValidListLinks(resp.result['links'])


class AuthTokenTests(OAuthFlowTests):

    def test_keystone_token_is_valid(self):
        self.test_oauth_flow()
        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        r = self.get('/auth/tokens', headers=headers)
        self.assertValidTokenResponse(r, self.user)

        # now verify the oauth section
        oauth_section = r.result['token']['OS-OAUTH1']
        self.assertEqual(oauth_section['access_token_id'],
                         self.access_token.key)
        self.assertEqual(oauth_section['consumer_id'], self.consumer['key'])

        # verify the roles section
        roles_list = r.result['token']['roles']
        # we can just verify the 0th role since we are only assigning one role
        self.assertEqual(roles_list[0]['id'], self.role_id)

        # verify that the token can perform delegated tasks
        ref = self.new_user_ref(domain_id=self.domain_id)
        r = self.admin_request(path='/v3/users', headers=headers,
                               method='POST', body={'user': ref})
        self.assertValidUserResponse(r, ref)

    def test_delete_access_token_also_revokes_token(self):
        self.test_oauth_flow()

        # Delete access token
        resp = self.delete('/users/%(user)s/OS-OAUTH1/access_tokens/%(auth)s'
                           % {'user': self.user_id,
                              'auth': self.access_token.key})
        self.assertResponseStatus(resp, 204)

        # Check Keystone Token no longer exists
        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        self.get('/auth/tokens', headers=headers,
                 expected_status=404)

    def test_deleting_consumer_also_deletes_tokens(self):
        self.test_oauth_flow()

        # Delete consumer
        consumer_id = self.consumer['key']
        resp = self.delete('/OS-OAUTH1/consumers/%(consumer_id)s'
                           % {'consumer_id': consumer_id})
        self.assertResponseStatus(resp, 204)

        # List access_token should be 0
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens'
                        % {'user_id': self.user_id})
        entities = resp.result['access_tokens']
        self.assertEqual([], entities)

        # Check Keystone Token no longer exists
        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        self.head('/auth/tokens', headers=headers,
                  expected_status=404)

    def test_change_user_password_also_deletes_tokens(self):
        self.test_oauth_flow()

        # delegated keystone token exists
        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        r = self.get('/auth/tokens', headers=headers)
        self.assertValidTokenResponse(r, self.user)

        user = {'password': uuid.uuid4().hex}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body={'user': user})

        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        self.admin_request(path='/auth/tokens', headers=headers,
                           method='GET', expected_status=404)

    def test_deleting_project_also_invalidates_tokens(self):
        self.test_oauth_flow()

        # delegated keystone token exists
        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        r = self.get('/auth/tokens', headers=headers)
        self.assertValidTokenResponse(r, self.user)

        r = self.delete('/projects/%(project_id)s' % {
            'project_id': self.project_id})

        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        self.admin_request(path='/auth/tokens', headers=headers,
                           method='GET', expected_status=404)

    def test_token_chaining_is_not_allowed(self):
        self.test_oauth_flow()

        #attempt to re-authenticate (token chain) with the given token
        path = '/v3/auth/tokens/'
        auth_data = self.build_authentication_request(
            token=self.keystone_token_id)

        self.admin_request(
            path=path,
            body=auth_data,
            token=self.keystone_token_id,
            method='POST',
            expected_status=403)

    def test_delete_keystone_tokens_by_consumer_id(self):
        self.test_oauth_flow()
        self.token_api.get_token(self.keystone_token_id)
        self.token_api.delete_tokens(self.user_id,
                                     consumer_id=self.consumer['key'])
        self.assertRaises(exception.TokenNotFound, self.token_api.get_token,
                          self.keystone_token_id)

    def _create_trust_get_token(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)

        trust_token = r.headers['X-Subject-Token']
        return trust_token

    def _approve_request_token_url(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        self.consumer = {'key': consumer_id, 'secret': consumer_secret}
        self.assertIsNotNone(self.consumer['secret'])

        url, headers = self._create_request_token(self.consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        request_key = credentials['oauth_token'][0]
        request_secret = credentials['oauth_token_secret'][0]
        self.request_token = oauth1.Token(request_key, request_secret)
        self.assertIsNotNone(self.request_token.key)

        url = self._authorize_request_token(request_key)

        return url

    def test_oauth_token_cannot_create_new_trust(self):
        self.test_oauth_flow()
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  token=self.keystone_token_id,
                  expected_status=403)

    def test_oauth_token_cannot_authorize_request_token(self):
        self.test_oauth_flow()
        url = self._approve_request_token_url()
        body = {'roles': [{'id': self.role_id}]}
        self.put(url, body=body, token=self.keystone_token_id,
                 expected_status=403)

    def test_oauth_token_cannot_list_request_tokens(self):
        self._set_policy({"identity:list_access_tokens": [],
                          "identity:create_consumer": [],
                          "identity:authorize_request_token": []})
        self.test_oauth_flow()
        url = '/users/%s/OS-OAUTH1/access_tokens' % self.user_id
        self.get(url, token=self.keystone_token_id,
                 expected_status=403)

    def _set_policy(self, new_policy):
        _unused, self.tmpfilename = tempfile.mkstemp()
        self.config_fixture.config(policy_file=self.tmpfilename)
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write(jsonutils.dumps(new_policy))
        self.addCleanup(os.remove, self.tmpfilename)

    def test_trust_token_cannot_authorize_request_token(self):
        trust_token = self._create_trust_get_token()
        url = self._approve_request_token_url()
        body = {'roles': [{'id': self.role_id}]}
        self.put(url, body=body, token=trust_token, expected_status=403)

    def test_trust_token_cannot_list_request_tokens(self):
        self._set_policy({"identity:list_access_tokens": [],
                          "identity:create_trust": []})
        trust_token = self._create_trust_get_token()
        url = '/users/%s/OS-OAUTH1/access_tokens' % self.user_id
        self.get(url, token=trust_token, expected_status=403)


class MaliciousOAuth1Tests(OAuth1Tests):

    def test_bad_consumer_secret(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer = {'key': consumer_id, 'secret': uuid.uuid4().hex}
        url, headers = self._create_request_token(consumer, self.project_id)
        self.post(url, headers=headers, expected_status=401)

    def test_bad_request_token_key(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        consumer = {'key': consumer_id, 'secret': consumer_secret}
        url, headers = self._create_request_token(consumer, self.project_id)
        self.post(url, headers=headers)
        url = self._authorize_request_token(uuid.uuid4().hex)
        body = {'roles': [{'id': self.role_id}]}
        self.put(url, body=body, expected_status=404)

    def test_bad_verifier(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        consumer = {'key': consumer_id, 'secret': consumer_secret}

        url, headers = self._create_request_token(consumer, self.project_id)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        request_key = credentials['oauth_token'][0]
        request_secret = credentials['oauth_token_secret'][0]
        request_token = oauth1.Token(request_key, request_secret)

        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        resp = self.put(url, body=body, expected_status=200)
        verifier = resp.result['token']['oauth_verifier']
        self.assertIsNotNone(verifier)

        request_token.set_verifier(uuid.uuid4().hex)
        url, headers = self._create_access_token(consumer, request_token)
        self.post(url, headers=headers, expected_status=401)

    def test_bad_authorizing_roles(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        consumer = {'key': consumer_id, 'secret': consumer_secret}

        url, headers = self._create_request_token(consumer, self.project_id)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        request_key = credentials['oauth_token'][0]

        self.assignment_api.remove_role_from_user_and_project(
            self.user_id, self.project_id, self.role_id)
        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        self.admin_request(path=url, method='PUT',
                           body=body, expected_status=404)

    def test_expired_authorizing_request_token(self):
        CONF.oauth1.request_token_duration = -1

        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        self.consumer = {'key': consumer_id, 'secret': consumer_secret}
        self.assertIsNotNone(self.consumer['key'])

        url, headers = self._create_request_token(self.consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        request_key = credentials['oauth_token'][0]
        request_secret = credentials['oauth_token_secret'][0]
        self.request_token = oauth1.Token(request_key, request_secret)
        self.assertIsNotNone(self.request_token.key)

        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        self.put(url, body=body, expected_status=401)

    def test_expired_creating_keystone_token(self):
        CONF.oauth1.access_token_duration = -1
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        consumer_secret = consumer['secret']
        self.consumer = {'key': consumer_id, 'secret': consumer_secret}
        self.assertIsNotNone(self.consumer['key'])

        url, headers = self._create_request_token(self.consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        request_key = credentials['oauth_token'][0]
        request_secret = credentials['oauth_token_secret'][0]
        self.request_token = oauth1.Token(request_key, request_secret)
        self.assertIsNotNone(self.request_token.key)

        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        resp = self.put(url, body=body, expected_status=200)
        self.verifier = resp.result['token']['oauth_verifier']

        self.request_token.set_verifier(self.verifier)
        url, headers = self._create_access_token(self.consumer,
                                                 self.request_token)
        content = self.post(url, headers=headers)
        credentials = urllib.parse.parse_qs(content.result)
        access_key = credentials['oauth_token'][0]
        access_secret = credentials['oauth_token_secret'][0]
        self.access_token = oauth1.Token(access_key, access_secret)
        self.assertIsNotNone(self.access_token.key)

        url, headers, body = self._get_oauth_token(self.consumer,
                                                   self.access_token)
        self.post(url, headers=headers, body=body, expected_status=401)
