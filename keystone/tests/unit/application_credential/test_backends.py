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

from oslo_config import fixture as config_fixture

from keystone.common import driver_hints
from keystone.common import provider_api
import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class ApplicationCredentialTests(object):

    def _new_app_cred_data(self, user_id, project_id=None, name=None,
                           expires=None, system=None):
        if not name:
            name = uuid.uuid4().hex
        if not expires:
            expires = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        if not system:
            system = uuid.uuid4().hex
        if not project_id:
            project_id = uuid.uuid4().hex
        app_cred_data = {
            'id': uuid.uuid4().hex,
            'name': name,
            'description': uuid.uuid4().hex,
            'user_id': user_id,
            'project_id': project_id,
            'system': system,
            'expires_at': expires,
            'roles': [
                {'id': self.role__member_['id']},
            ],
            'secret': uuid.uuid4().hex,
            'unrestricted': False
        }
        return app_cred_data

    def test_create_application_credential(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        resp = self.app_cred_api.create_application_credential(app_cred)
        resp_roles = resp.pop('roles')
        orig_roles = app_cred.pop('roles')
        self.assertDictEqual(app_cred, resp)
        self.assertEqual(orig_roles[0]['id'], resp_roles[0]['id'])

    def test_create_duplicate_application_credential_fails(self):
        # Ensure a user can't create two application credentials with the same
        # name
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        name = app_cred['name']
        self.app_cred_api.create_application_credential(app_cred)
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'],
                                           name=name)
        self.assertRaises(exception.Conflict,
                          self.app_cred_api.create_application_credential,
                          app_cred)

    def test_create_application_credential_require_role_assignments(self):
        # Ensure a user can't create an application credential for a project
        # they don't have a role assignment on
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_baz['id'])
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.app_cred_api.create_application_credential,
                          app_cred)

    def test_application_credential_allow_recursion(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        app_cred['unrestricted'] = True
        resp = self.app_cred_api.create_application_credential(app_cred)
        resp.pop('roles')
        app_cred.pop('roles')
        self.assertDictEqual(app_cred, resp)

    def test_application_credential_limits(self):
        config_fixture_ = self.user = self.useFixture(config_fixture.Config())
        config_fixture_.config(group='application_credential', user_limit=2)
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           self.project_bar['id'])
        self.app_cred_api.create_application_credential(app_cred)
        app_cred['name'] = 'two'
        self.app_cred_api.create_application_credential(app_cred)
        app_cred['name'] = 'three'
        self.assertRaises(exception.ApplicationCredentialLimitExceeded,
                          self.app_cred_api.create_application_credential,
                          app_cred)

    def test_create_application_credential_with_access_rules(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        app_cred['access_rules'] = [{
            'id': uuid.uuid4().hex,
            'service': uuid.uuid4().hex,
            'path': uuid.uuid4().hex,
            'method': uuid.uuid4().hex[16:]
        }]
        resp = self.app_cred_api.create_application_credential(app_cred)
        resp.pop('roles')
        resp_access_rules = resp.pop('access_rules')
        app_cred.pop('roles')
        orig_access_rules = app_cred.pop('access_rules')
        self.assertDictEqual(app_cred, resp)
        for i, ar in enumerate(resp_access_rules):
            self.assertDictEqual(orig_access_rules[i], ar)

    def test_create_application_credential_with_preexisting_access_rules(self):
        app_cred_1 = self._new_app_cred_data(self.user_foo['id'],
                                             project_id=self.project_bar['id'])
        app_cred_1['access_rules'] = [{
            'id': uuid.uuid4().hex,
            'service': uuid.uuid4().hex,
            'path': uuid.uuid4().hex,
            'method': uuid.uuid4().hex[16:]
        }]
        resp = self.app_cred_api.create_application_credential(app_cred_1)
        resp_access_rules_1 = resp.pop('access_rules')
        app_cred_2 = self._new_app_cred_data(self.user_foo['id'],
                                             project_id=self.project_bar['id'])
        app_cred_2['access_rules'] = [{'id': resp_access_rules_1[0]['id']}]
        resp = self.app_cred_api.create_application_credential(app_cred_2)
        resp_access_rules_2 = resp.pop('access_rules')
        self.assertDictEqual(resp_access_rules_1[0], resp_access_rules_2[0])

    def test_get_application_credential(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        create_resp = self.app_cred_api.create_application_credential(app_cred)
        app_cred_id = create_resp['id']
        get_resp = self.app_cred_api.get_application_credential(app_cred_id)
        create_resp.pop('secret')
        self.assertDictEqual(create_resp, get_resp)

    def test_get_application_credential_not_found(self):
        self.assertRaises(exception.ApplicationCredentialNotFound,
                          self.app_cred_api.get_application_credential,
                          uuid.uuid4().hex)

    def test_list_application_credentials(self):
        app_cred_1 = self._new_app_cred_data(self.user_foo['id'],
                                             project_id=self.project_bar['id'],
                                             name='app1')
        app_cred_2 = self._new_app_cred_data(self.user_foo['id'],
                                             project_id=self.project_bar['id'],
                                             name='app2')
        app_cred_3 = self._new_app_cred_data(self.user_two['id'],
                                             project_id=self.project_baz['id'],
                                             name='app3')
        resp1 = self.app_cred_api.create_application_credential(app_cred_1)
        resp2 = self.app_cred_api.create_application_credential(app_cred_2)
        resp3 = self.app_cred_api.create_application_credential(app_cred_3)
        hints = driver_hints.Hints()
        resp = self.app_cred_api.list_application_credentials(
            self.user_foo['id'], hints)
        resp_ids = [ac['id'] for ac in resp]
        self.assertIn(resp1['id'], resp_ids)
        self.assertIn(resp2['id'], resp_ids)
        self.assertNotIn(resp3['id'], resp_ids)
        for ac in resp:
            self.assertNotIn('secret_hash', ac)

    def _list_ids(self, user):
        hints = driver_hints.Hints()
        resp = self.app_cred_api.list_application_credentials(user['id'],
                                                              hints)
        return [ac['id'] for ac in resp]

    def test_delete_application_credential(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        self.app_cred_api.create_application_credential(app_cred)

        # cache the information
        self.app_cred_api.get_application_credential(app_cred['id'])

        self.assertIn(app_cred['id'], self._list_ids(self.user_foo))
        self.app_cred_api.delete_application_credential(app_cred['id'])
        self.assertNotIn(app_cred['id'], self._list_ids(self.user_foo))

        # the cache information has been invalidated.
        self.assertRaises(exception.ApplicationCredentialNotFound,
                          self.app_cred_api.get_application_credential,
                          app_cred['id'])

    def test_delete_application_credential_not_found(self):
        self.assertRaises(exception.ApplicationCredentialNotFound,
                          self.app_cred_api.delete_application_credential,
                          uuid.uuid4().hex)

    def test_deleting_a_user_deletes_application_credentials(self):
        app_cred_1 = self._new_app_cred_data(self.user_foo['id'],
                                             project_id=self.project_bar['id'],
                                             name='app1')
        app_cred_2 = self._new_app_cred_data(self.user_foo['id'],
                                             project_id=self.project_bar['id'],
                                             name='app2')
        self.app_cred_api.create_application_credential(app_cred_1)
        self.app_cred_api.create_application_credential(app_cred_2)
        self.assertIn(app_cred_1['id'], self._list_ids(self.user_foo))
        self.assertIn(app_cred_2['id'], self._list_ids(self.user_foo))

        # cache the information
        self.app_cred_api.get_application_credential(app_cred_1['id'])
        self.app_cred_api.get_application_credential(app_cred_2['id'])

        # This should trigger a notification which should invoke a callback in
        # the application credential Manager to cleanup user_foo's application
        # credentials.
        PROVIDERS.identity_api.delete_user(self.user_foo['id'])
        hints = driver_hints.Hints()
        self.assertListEqual(
            [], self.app_cred_api.list_application_credentials(
                self.user_foo['id'], hints))

        # the cache information has been invalidated.
        self.assertRaises(exception.ApplicationCredentialNotFound,
                          self.app_cred_api.get_application_credential,
                          app_cred_1['id'])
        self.assertRaises(exception.ApplicationCredentialNotFound,
                          self.app_cred_api.get_application_credential,
                          app_cred_2['id'])

    def test_removing_user_from_project_deletes_application_credentials(self):
        app_cred_proj_A_1 = self._new_app_cred_data(
            self.user_foo['id'], project_id=self.project_bar['id'],
            name='app1')
        app_cred_proj_A_2 = self._new_app_cred_data(
            self.user_foo['id'], project_id=self.project_bar['id'],
            name='app2')
        app_cred_proj_B = self._new_app_cred_data(
            self.user_foo['id'], project_id=self.project_baz['id'],
            name='app3')
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            project_id=self.project_baz['id'],
            user_id=self.user_foo['id'],
            role_id=self.role__member_['id'])
        self.app_cred_api.create_application_credential(app_cred_proj_A_1)
        self.app_cred_api.create_application_credential(app_cred_proj_A_2)
        self.app_cred_api.create_application_credential(app_cred_proj_B)
        self.assertIn(app_cred_proj_A_1['id'], self._list_ids(self.user_foo))
        self.assertIn(app_cred_proj_A_2['id'], self._list_ids(self.user_foo))
        self.assertIn(app_cred_proj_B['id'], self._list_ids(self.user_foo))

        # cache the information
        self.app_cred_api.get_application_credential(app_cred_proj_A_1['id'])
        self.app_cred_api.get_application_credential(app_cred_proj_A_2['id'])
        self.app_cred_api.get_application_credential(app_cred_proj_B['id'])

        # This should trigger a notification which should invoke a callback in
        # the application credential Manager to cleanup all of user_foo's
        # application credentials on project bar.
        PROVIDERS.assignment_api.remove_role_from_user_and_project(
            user_id=self.user_foo['id'],
            project_id=self.project_bar['id'],
            role_id=self.role__member_['id'])
        self.assertNotIn(app_cred_proj_A_1['id'],
                         self._list_ids(self.user_foo))
        self.assertNotIn(app_cred_proj_A_2['id'],
                         self._list_ids(self.user_foo))
        self.assertIn(app_cred_proj_B['id'], self._list_ids(self.user_foo))

        # the cache information has been invalidated only for the deleted
        # application credential.
        self.assertRaises(exception.ApplicationCredentialNotFound,
                          self.app_cred_api.get_application_credential,
                          app_cred_proj_A_1['id'])
        self.assertRaises(exception.ApplicationCredentialNotFound,
                          self.app_cred_api.get_application_credential,
                          app_cred_proj_A_2['id'])
        self.assertEqual(app_cred_proj_B['id'],
                         self.app_cred_api.get_application_credential(
                             app_cred_proj_B['id'])['id'])

    def test_authenticate(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        resp = self.app_cred_api.create_application_credential(app_cred)
        self.app_cred_api.authenticate(resp['id'], resp['secret'])

    def test_authenticate_not_found(self):
        self.assertRaises(AssertionError,
                          self.app_cred_api.authenticate,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_authenticate_expired(self):
        yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'],
                                           expires=yesterday)
        resp = self.app_cred_api.create_application_credential(app_cred)
        self.assertRaises(AssertionError,
                          self.app_cred_api.authenticate,
                          resp['id'],
                          resp['secret'])

    def test_authenticate_bad_secret(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        resp = self.app_cred_api.create_application_credential(app_cred)
        badpass = 'badpass'
        self.assertNotEqual(badpass, resp['secret'])
        self.assertRaises(AssertionError,
                          self.app_cred_api.authenticate,
                          resp['id'],
                          badpass)

    def test_get_delete_access_rules(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        access_rule_id = uuid.uuid4().hex
        app_cred['access_rules'] = [{
            'id': access_rule_id,
            'service': uuid.uuid4().hex,
            'path': uuid.uuid4().hex,
            'method': uuid.uuid4().hex[16:]
        }]
        self.app_cred_api.create_application_credential(app_cred)
        self.assertDictEqual(app_cred['access_rules'][0],
                             self.app_cred_api.get_access_rule(access_rule_id))
        self.app_cred_api.delete_application_credential(app_cred['id'])
        self.app_cred_api.delete_access_rule(access_rule_id)
        self.assertRaises(exception.AccessRuleNotFound,
                          self.app_cred_api.get_access_rule,
                          access_rule_id)

    def test_list_delete_access_rule_for_user(self):
        app_cred = self._new_app_cred_data(self.user_foo['id'],
                                           project_id=self.project_bar['id'])
        access_rule_id = uuid.uuid4().hex
        app_cred['access_rules'] = [{
            'id': access_rule_id,
            'service': uuid.uuid4().hex,
            'path': uuid.uuid4().hex,
            'method': uuid.uuid4().hex[16:]
        }]
        self.app_cred_api.create_application_credential(app_cred)
        self.assertEqual(1, len(self.app_cred_api.list_access_rules_for_user(
            self.user_foo['id'])))
        self.app_cred_api.delete_application_credential(app_cred['id'])
        # access rule should still exist
        self.assertEqual(1, len(self.app_cred_api.list_access_rules_for_user(
            self.user_foo['id'])))
        self.app_cred_api.delete_access_rules_for_user(self.user_foo['id'])
        self.assertEqual(0, len(self.app_cred_api.list_access_rules_for_user(
            self.user_foo['id'])))
