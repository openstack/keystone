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

import copy
import os
import urlparse
import uuid

from keystone.common import cms
from keystone.common.sql import migration
from keystone import config
from keystone import contrib
from keystone.contrib import oauth1
from keystone.contrib.oauth1 import controllers
from keystone.openstack.common import importutils
from keystone.tests import test_v3


CONF = config.CONF


class OAuth1Tests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'oauth1'
    EXTENSION_TO_ADD = 'oauth_extension'

    def setup_database(self):
        super(OAuth1Tests, self).setup_database()
        package_name = "%s.%s.migrate_repo" % (contrib.__name__,
                                               self.EXTENSION_NAME)
        package = importutils.import_module(package_name)
        self.repo_path = os.path.abspath(os.path.dirname(package.__file__))
        migration.db_version_control(version=None, repo_path=self.repo_path)
        migration.db_sync(version=None, repo_path=self.repo_path)

    def setUp(self):
        super(OAuth1Tests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = (CONF.public_endpoint % CONF) + "v3"
        self.controller = controllers.OAuthControllerV3()

    def _create_single_consumer(self):
        ref = {'description': uuid.uuid4().hex}
        resp = self.post(
            '/OS-OAUTH1/consumers',
            body={'consumer': ref})
        return resp.result.get('consumer')

    def _oauth_request(self, consumer, token=None, **kw):
        return oauth1.Request.from_consumer_and_token(consumer=consumer,
                                                      token=token,
                                                      **kw)

    def _create_request_token(self, consumer, project_id):
        params = {'requested_project_id': project_id}
        headers = {'Content-Type': 'application/json'}
        url = '/OS-OAUTH1/request_token'
        oreq = self._oauth_request(
            consumer=consumer,
            http_url=self.base_url + url,
            http_method='POST',
            parameters=params)
        hmac = oauth1.SignatureMethod_HMAC_SHA1()
        oreq.sign_request(hmac, consumer, None)
        headers.update(oreq.to_header())
        headers.update(params)
        return url, headers

    def _create_access_token(self, consumer, token):
        headers = {'Content-Type': 'application/json'}
        url = '/OS-OAUTH1/access_token'
        oreq = self._oauth_request(
            consumer=consumer, token=token,
            http_method='POST',
            http_url=self.base_url + url)
        hmac = oauth1.SignatureMethod_HMAC_SHA1()
        oreq.sign_request(hmac, consumer, token)
        headers.update(oreq.to_header())
        return url, headers

    def _get_oauth_token(self, consumer, token):
        headers = {'Content-Type': 'application/json'}
        body = {'auth': {'identity': {'methods': ['oauth1'], 'oauth1': {}}}}
        url = '/auth/tokens'
        oreq = self._oauth_request(
            consumer=consumer, token=token,
            http_method='POST',
            http_url=self.base_url + url)
        hmac = oauth1.SignatureMethod_HMAC_SHA1()
        oreq.sign_request(hmac, consumer, token)
        headers.update(oreq.to_header())
        return url, headers, body

    def _authorize_request_token(self, request_id):
        return '/OS-OAUTH1/authorize/%s' % (request_id)


class ConsumerCRUDTests(OAuth1Tests):

    def _consumer_create(self, description=None, description_flag=True):
        if description_flag:
            ref = {'description': description}
        else:
            ref = {}
        resp = self.post(
            '/OS-OAUTH1/consumers',
            body={'consumer': ref})
        consumer = resp.result.get('consumer')
        consumer_id = consumer.get('id')
        self.assertEqual(consumer['description'], description)
        self.assertIsNotNone(consumer_id)
        self.assertIsNotNone(consumer.get('secret'))

    def test_consumer_create(self):
        description = uuid.uuid4().hex
        self._consumer_create(description=description)

    def test_consumer_create_none_desc_1(self):
        self._consumer_create()

    def test_consumer_create_none_desc_2(self):
        self._consumer_create(description_flag=False)

    def test_consumer_delete(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        resp = self.delete('/OS-OAUTH1/consumers/%(consumer_id)s'
                           % {'consumer_id': consumer_id})
        self.assertResponseStatus(resp, 204)

    def test_consumer_get(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        resp = self.get('/OS-OAUTH1/consumers/%(consumer_id)s'
                        % {'consumer_id': consumer_id})
        self.assertEqual(resp.result.get('consumer').get('id'), consumer_id)

    def test_consumer_list(self):
        resp = self.get('/OS-OAUTH1/consumers')
        entities = resp.result.get('consumers')
        self.assertIsNotNone(entities)
        self.assertValidListLinks(resp.result.get('links'))

    def test_consumer_update(self):
        consumer = self._create_single_consumer()
        original_id = consumer.get('id')
        original_description = consumer.get('description')
        update_description = original_description + "_new"

        update_ref = {'description': update_description}
        update_resp = self.patch('/OS-OAUTH1/consumers/%(consumer_id)s'
                                 % {'consumer_id': original_id},
                                 body={'consumer': update_ref})
        consumer = update_resp.result.get('consumer')
        self.assertEqual(consumer.get('description'), update_description)
        self.assertEqual(consumer.get('id'), original_id)

    def test_consumer_update_bad_secret(self):
        consumer = self._create_single_consumer()
        original_id = consumer.get('id')
        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = uuid.uuid4().hex
        update_ref['secret'] = uuid.uuid4().hex
        self.patch('/OS-OAUTH1/consumers/%(consumer_id)s'
                   % {'consumer_id': original_id},
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_bad_id(self):
        consumer = self._create_single_consumer()
        original_id = consumer.get('id')
        original_description = consumer.get('description')
        update_description = original_description + "_new"

        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = update_description
        update_ref['id'] = update_description
        self.patch('/OS-OAUTH1/consumers/%(consumer_id)s'
                   % {'consumer_id': original_id},
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_create_no_description(self):
        resp = self.post('/OS-OAUTH1/consumers', body={'consumer': {}})
        consumer = resp.result.get('consumer')
        consumer_id = consumer.get('id')
        self.assertEqual(consumer.get('description'), None)
        self.assertIsNotNone(consumer_id)
        self.assertIsNotNone(consumer.get('secret'))

    def test_consumer_get_bad_id(self):
        self.get('/OS-OAUTH1/consumers/%(consumer_id)s'
                 % {'consumer_id': uuid.uuid4().hex},
                 expected_status=404)


class OAuthFlowTests(OAuth1Tests):

    def test_oauth_flow(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        consumer_secret = consumer.get('secret')
        self.consumer = oauth1.Consumer(consumer_id, consumer_secret)
        self.assertIsNotNone(self.consumer.key)

        url, headers = self._create_request_token(self.consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urlparse.parse_qs(content.result)
        request_key = credentials.get('oauth_token')[0]
        request_secret = credentials.get('oauth_token_secret')[0]
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
        credentials = urlparse.parse_qs(content.result)
        access_key = credentials.get('oauth_token')[0]
        access_secret = credentials.get('oauth_token_secret')[0]
        self.access_token = oauth1.Token(access_key, access_secret)
        self.assertIsNotNone(self.access_token.key)

        url, headers, body = self._get_oauth_token(self.consumer,
                                                   self.access_token)
        content = self.post(url, headers=headers, body=body)
        self.keystone_token_id = content.headers.get('X-Subject-Token')
        self.keystone_token = content.result.get('token')
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
        entities = resp.result.get('access_tokens')
        self.assertTrue(len(entities) == 0)
        self.assertValidListLinks(resp.result.get('links'))

    def test_get_single_access_token(self):
        self.test_oauth_flow()
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens/%(key)s'
                        % {'user_id': self.user_id,
                           'key': self.access_token.key})
        entity = resp.result.get('access_token')
        self.assertEqual(entity['id'], self.access_token.key)
        self.assertEqual(entity['consumer_id'], self.consumer.key)

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
        entities = resp.result.get('roles')
        self.assertTrue(len(entities) > 0)
        self.assertValidListLinks(resp.result.get('links'))

    def test_get_role_in_access_token(self):
        self.test_oauth_flow()
        url = ('/users/%(id)s/OS-OAUTH1/access_tokens/%(key)s/roles/%(role)s'
               % {'id': self.user_id, 'key': self.access_token.key,
                  'role': self.role_id})
        resp = self.get(url)
        entity = resp.result.get('role')
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
        entities = resp.result.get('access_tokens')
        self.assertTrue(len(entities) > 0)
        self.assertValidListLinks(resp.result.get('links'))

        # Delete access_token
        resp = self.delete('/users/%(user)s/OS-OAUTH1/access_tokens/%(auth)s'
                           % {'user': self.user_id,
                              'auth': self.access_token.key})
        self.assertResponseStatus(resp, 204)

        # List access_token should be 0
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens'
                        % {'user_id': self.user_id})
        entities = resp.result.get('access_tokens')
        self.assertTrue(len(entities) == 0)
        self.assertValidListLinks(resp.result.get('links'))


class AuthTokenTests(OAuthFlowTests):

    def test_keystone_token_is_valid(self):
        self.test_oauth_flow()
        headers = {'X-Subject-Token': self.keystone_token_id,
                   'X-Auth-Token': self.keystone_token_id}
        r = self.get('/auth/tokens', headers=headers)
        self.assertValidTokenResponse(r, self.user)

        # now verify the oauth section
        oauth_section = r.result['token']['OS-OAUTH1']
        self.assertEquals(oauth_section['access_token_id'],
                          self.access_token.key)
        self.assertEquals(oauth_section['consumer_id'], self.consumer.key)

        # verify the roles section
        roles_list = r.result['token']['roles']
        # we can just verify the 0th role since we are only assigning one role
        self.assertEquals(roles_list[0]['id'], self.role_id)

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
        consumer_id = self.consumer.key
        resp = self.delete('/OS-OAUTH1/consumers/%(consumer_id)s'
                           % {'consumer_id': consumer_id})
        self.assertResponseStatus(resp, 204)

        # List access_token should be 0
        resp = self.get('/users/%(user_id)s/OS-OAUTH1/access_tokens'
                        % {'user_id': self.user_id})
        entities = resp.result.get('access_tokens')
        self.assertEqual(len(entities), 0)

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

    def test_list_keystone_tokens_by_consumer(self):
        self.test_oauth_flow()
        tokens = self.token_api.list_tokens(self.user_id,
                                            consumer_id=self.consumer.key)
        keystone_token_uuid = cms.cms_hash_token(self.keystone_token_id)
        self.assertTrue(len(tokens) > 0)
        self.assertTrue(keystone_token_uuid in tokens)


class MaliciousOAuth1Tests(OAuth1Tests):

    def test_bad_consumer_secret(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        consumer = oauth1.Consumer(consumer_id, "bad_secret")
        url, headers = self._create_request_token(consumer,
                                                  self.project_id)
        self.post(url, headers=headers, expected_status=500)

    def test_bad_request_token_key(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        consumer_secret = consumer.get('secret')
        consumer = oauth1.Consumer(consumer_id, consumer_secret)
        url, headers = self._create_request_token(consumer,
                                                  self.project_id)
        self.post(url, headers=headers)
        url = self._authorize_request_token("bad_key")
        body = {'roles': [{'id': self.role_id}]}
        self.put(url, body=body, expected_status=404)

    def test_bad_verifier(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        consumer_secret = consumer.get('secret')
        consumer = oauth1.Consumer(consumer_id, consumer_secret)

        url, headers = self._create_request_token(consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urlparse.parse_qs(content.result)
        request_key = credentials.get('oauth_token')[0]
        request_secret = credentials.get('oauth_token_secret')[0]
        request_token = oauth1.Token(request_key, request_secret)

        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        resp = self.put(url, body=body, expected_status=200)
        verifier = resp.result['token']['oauth_verifier']
        self.assertIsNotNone(verifier)

        request_token.set_verifier("bad verifier")
        url, headers = self._create_access_token(consumer,
                                                 request_token)
        self.post(url, headers=headers, expected_status=401)

    def test_bad_authorizing_roles(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        consumer_secret = consumer.get('secret')
        consumer = oauth1.Consumer(consumer_id, consumer_secret)

        url, headers = self._create_request_token(consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urlparse.parse_qs(content.result)
        request_key = credentials.get('oauth_token')[0]

        self.identity_api.remove_role_from_user_and_project(self.user_id,
                                                            self.project_id,
                                                            self.role_id)
        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        self.admin_request(path=url, method='PUT',
                           body=body, expected_status=404)

    def test_expired_authorizing_request_token(self):
        CONF.oauth1.request_token_duration = -1

        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        consumer_secret = consumer.get('secret')
        self.consumer = oauth1.Consumer(consumer_id, consumer_secret)
        self.assertIsNotNone(self.consumer.key)

        url, headers = self._create_request_token(self.consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urlparse.parse_qs(content.result)
        request_key = credentials.get('oauth_token')[0]
        request_secret = credentials.get('oauth_token_secret')[0]
        self.request_token = oauth1.Token(request_key, request_secret)
        self.assertIsNotNone(self.request_token.key)

        url = self._authorize_request_token(request_key)
        body = {'roles': [{'id': self.role_id}]}
        self.put(url, body=body, expected_status=401)

    def test_expired_creating_keystone_token(self):
        CONF.oauth1.access_token_duration = -1
        consumer = self._create_single_consumer()
        consumer_id = consumer.get('id')
        consumer_secret = consumer.get('secret')
        self.consumer = oauth1.Consumer(consumer_id, consumer_secret)
        self.assertIsNotNone(self.consumer.key)

        url, headers = self._create_request_token(self.consumer,
                                                  self.project_id)
        content = self.post(url, headers=headers)
        credentials = urlparse.parse_qs(content.result)
        request_key = credentials.get('oauth_token')[0]
        request_secret = credentials.get('oauth_token_secret')[0]
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
        credentials = urlparse.parse_qs(content.result)
        access_key = credentials.get('oauth_token')[0]
        access_secret = credentials.get('oauth_token_secret')[0]
        self.access_token = oauth1.Token(access_key, access_secret)
        self.assertIsNotNone(self.access_token.key)

        url, headers, body = self._get_oauth_token(self.consumer,
                                                   self.access_token)
        self.post(url, headers=headers, body=body, expected_status=401)
