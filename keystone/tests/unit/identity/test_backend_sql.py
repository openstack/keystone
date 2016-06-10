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

from oslo_config import cfg

from keystone.common import sql
from keystone.common import utils
from keystone import exception
from keystone.identity.backends import base
from keystone.identity.backends import sql_model as model
from keystone.tests.unit import test_backend_sql


CONF = cfg.CONF


class DisableInactiveUserTests(test_backend_sql.SqlTests):
    def setUp(self):
        super(DisableInactiveUserTests, self).setUp()
        self.password = uuid.uuid4().hex
        self.user_dict = self._get_user_dict(self.password)
        self.max_inactive_days = 90
        self.config_fixture.config(
            group='security_compliance',
            disable_user_account_days_inactive=self.max_inactive_days)

    def test_authenticate_user_disabled_due_to_inactivity(self):
        # create user and set last_active_at beyond the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(days=self.max_inactive_days + 1))
        user = self._create_user(self.user_dict, last_active_at.date())
        self.assertRaises(exception.UserDisabled,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password=self.password)
        # verify that the user is actually disabled
        user = self.identity_api.get_user(user['id'])
        self.assertFalse(user['enabled'])
        # set the user to enabled and authenticate
        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user = self.identity_api.authenticate(context={},
                                              user_id=user['id'],
                                              password=self.password)
        self.assertTrue(user['enabled'])

    def test_authenticate_user_not_disabled_due_to_inactivity(self):
        # create user and set last_active_at just below the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(days=self.max_inactive_days - 1)).date()
        user = self._create_user(self.user_dict, last_active_at)
        user = self.identity_api.authenticate(context={},
                                              user_id=user['id'],
                                              password=self.password)
        self.assertTrue(user['enabled'])

    def test_get_user_disabled_due_to_inactivity(self):
        user = self.identity_api.create_user(self.user_dict)
        # set last_active_at just beyond the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(self.max_inactive_days + 1)).date()
        self._update_user(user['id'], last_active_at)
        # get user and verify that the user is actually disabled
        user = self.identity_api.get_user(user['id'])
        self.assertFalse(user['enabled'])
        # set enabled and test
        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user = self.identity_api.get_user(user['id'])
        self.assertTrue(user['enabled'])

    def test_get_user_not_disabled_due_to_inactivity(self):
        user = self.identity_api.create_user(self.user_dict)
        self.assertTrue(user['enabled'])
        # set last_active_at just below the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(self.max_inactive_days - 1)).date()
        self._update_user(user['id'], last_active_at)
        # get user and verify that the user is still enabled
        user = self.identity_api.get_user(user['id'])
        self.assertTrue(user['enabled'])

    def test_enabled_after_create_update_user(self):
        self.config_fixture.config(group='security_compliance',
                                   disable_user_account_days_inactive=90)
        # create user without enabled; assert enabled
        del self.user_dict['enabled']
        user = self.identity_api.create_user(self.user_dict)
        user_ref = self._get_user_ref(user['id'])
        self.assertTrue(user_ref.enabled)
        now = datetime.datetime.utcnow().date()
        self.assertGreaterEqual(now, user_ref.last_active_at)
        # set enabled and test
        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user_ref = self._get_user_ref(user['id'])
        self.assertTrue(user_ref.enabled)
        # set disabled and test
        user['enabled'] = False
        self.identity_api.update_user(user['id'], user)
        user_ref = self._get_user_ref(user['id'])
        self.assertFalse(user_ref.enabled)
        # re-enable user and test
        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user_ref = self._get_user_ref(user['id'])
        self.assertTrue(user_ref.enabled)

    def _get_user_dict(self, password):
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'enabled': True,
            'password': password
        }
        return user

    def _get_user_ref(self, user_id):
        with sql.session_for_read() as session:
            return session.query(model.User).get(user_id)

    def _create_user(self, user_dict, last_active_at):
        user_dict['id'] = uuid.uuid4().hex
        user_dict = utils.hash_user_password(user_dict)
        with sql.session_for_write() as session:
            user_ref = model.User.from_dict(user_dict)
            user_ref.last_active_at = last_active_at
            session.add(user_ref)
            return base.filter_user(user_ref.to_dict())

    def _update_user(self, user_id, last_active_at):
        with sql.session_for_write() as session:
            user_ref = session.query(model.User).get(user_id)
            user_ref.last_active_at = last_active_at
            return user_ref
