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

from keystone.common import provider_api
from keystone.common import sql
import keystone.conf
from keystone import exception
from keystone.identity.backends import sql_model as model
from keystone.tests import unit


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class ShadowUsersBackendTests(object):
    def test_create_nonlocal_user_unique_constraint(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_created = PROVIDERS.shadow_users_api.create_nonlocal_user(user)
        self.assertNotIn('password', user_created)
        self.assertEqual(user_created['id'], user['id'])
        self.assertEqual(user_created['domain_id'], user['domain_id'])
        self.assertEqual(user_created['name'], user['name'])
        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_user['name'] = user['name']
        self.assertRaises(exception.Conflict,
                          PROVIDERS.shadow_users_api.create_nonlocal_user,
                          new_user)

    def test_create_nonlocal_user_does_not_create_local_user(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_nonlocal_user = PROVIDERS.shadow_users_api.create_nonlocal_user(
            user
        )
        user_ref = self._get_user_ref(new_nonlocal_user['id'])
        self.assertIsNone(user_ref.local_user)

    def test_nonlocal_user_unique_user_id_constraint(self):
        user_ref = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.shadow_users_api.create_nonlocal_user(user_ref)
        # attempt to create a nonlocal_user with the same user_id
        nonlocal_user = {
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex,
            'user_id': user['id']
        }
        self.assertRaises(sql.DBDuplicateEntry, self._add_nonlocal_user,
                          nonlocal_user)

    def test_get_user(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user.pop('email')
        user.pop('password')
        user_created = PROVIDERS.shadow_users_api.create_nonlocal_user(user)
        self.assertEqual(user_created['id'], user['id'])
        user_found = PROVIDERS.shadow_users_api.get_user(user_created['id'])
        self.assertCountEqual(user_created, user_found)

    def test_create_federated_user_unique_constraint(self):
        user_dict = PROVIDERS.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user)
        user_dict = PROVIDERS.shadow_users_api.get_user(user_dict["id"])
        self.assertIsNotNone(user_dict["id"])
        self.assertRaises(exception.Conflict,
                          PROVIDERS.shadow_users_api.create_federated_user,
                          self.domain_id,
                          self.federated_user)

    def test_create_federated_user_domain(self):
        user = PROVIDERS.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user)
        self.assertEqual(user['domain_id'], self.domain_id)

    def test_create_federated_user_email(self):
        user = PROVIDERS.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user, self.email)
        self.assertEqual(user['email'], self.email)

    def test_get_federated_user(self):
        user_dict_create = PROVIDERS.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user)
        user_dict_get = PROVIDERS.shadow_users_api.get_federated_user(
            self.federated_user["idp_id"],
            self.federated_user["protocol_id"],
            self.federated_user["unique_id"])
        self.assertCountEqual(user_dict_create, user_dict_get)
        self.assertEqual(user_dict_create["id"], user_dict_get["id"])

    def test_update_federated_user_display_name(self):
        user_dict_create = PROVIDERS.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user)
        new_display_name = uuid.uuid4().hex
        PROVIDERS.shadow_users_api.update_federated_user_display_name(
            self.federated_user["idp_id"],
            self.federated_user["protocol_id"],
            self.federated_user["unique_id"],
            new_display_name)
        user_ref = PROVIDERS.shadow_users_api._get_federated_user(
            self.federated_user["idp_id"],
            self.federated_user["protocol_id"],
            self.federated_user["unique_id"])
        self.assertEqual(user_ref.federated_users[0].display_name,
                         new_display_name)
        self.assertEqual(user_dict_create["id"], user_ref.id)

    def test_set_last_active_at(self):
        self.config_fixture.config(group='security_compliance',
                                   disable_user_account_days_inactive=90)
        now = datetime.datetime.utcnow().date()
        password = uuid.uuid4().hex
        user = self._create_user(password)
        with self.make_request():
            user_auth = PROVIDERS.identity_api.authenticate(
                user_id=user['id'],
                password=password)
        user_ref = self._get_user_ref(user_auth['id'])
        self.assertGreaterEqual(now, user_ref.last_active_at)

    def test_set_last_active_at_when_config_setting_is_none(self):
        self.config_fixture.config(group='security_compliance',
                                   disable_user_account_days_inactive=None)
        password = uuid.uuid4().hex
        user = self._create_user(password)
        with self.make_request():
            user_auth = PROVIDERS.identity_api.authenticate(
                user_id=user['id'],
                password=password)
        user_ref = self._get_user_ref(user_auth['id'])
        self.assertIsNone(user_ref.last_active_at)

    def _add_nonlocal_user(self, nonlocal_user):
        with sql.session_for_write() as session:
            nonlocal_user_ref = model.NonLocalUser.from_dict(nonlocal_user)
            session.add(nonlocal_user_ref)

    def _create_user(self, password):
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': self.domain_id,
            'enabled': True,
            'password': password
        }
        return PROVIDERS.identity_api.create_user(user)

    def _get_user_ref(self, user_id):
        with sql.session_for_read() as session:
            return session.query(model.User).get(user_id)
