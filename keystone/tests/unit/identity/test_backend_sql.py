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
                          self.make_request(),
                          user_id=user['id'],
                          password=self.password)
        # verify that the user is actually disabled
        user = self.identity_api.get_user(user['id'])
        self.assertFalse(user['enabled'])
        # set the user to enabled and authenticate
        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user = self.identity_api.authenticate(self.make_request(),
                                              user_id=user['id'],
                                              password=self.password)
        self.assertTrue(user['enabled'])

    def test_authenticate_user_not_disabled_due_to_inactivity(self):
        # create user and set last_active_at just below the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(days=self.max_inactive_days - 1)).date()
        user = self._create_user(self.user_dict, last_active_at)
        user = self.identity_api.authenticate(self.make_request(),
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


class PasswordHistoryValidationTests(test_backend_sql.SqlTests):
    def setUp(self):
        super(PasswordHistoryValidationTests, self).setUp()
        self.passwords = [uuid.uuid4().hex,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex]
        self.max_cnt = 3
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=self.max_cnt)

    def test_validate_password_history_with_invalid_password(self):
        user = self._create_user(self.passwords[0])
        self.assertValidPasswordUpdate(user, self.passwords[1])
        # Attempt to update with the initial password
        user['password'] = self.passwords[0]
        self.assertRaises(exception.PasswordValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_validate_password_history_with_valid_password(self):
        user = self._create_user(self.passwords[0])
        self.assertValidPasswordUpdate(user, self.passwords[1])
        self.assertValidPasswordUpdate(user, self.passwords[2])
        self.assertValidPasswordUpdate(user, self.passwords[3])
        # Now you should be able to change the password to match the initial
        # password because the password history only contains password elements
        # 1, 2, 3
        self.assertValidPasswordUpdate(user, self.passwords[0])

    def test_validate_password_history_but_start_with_password_none(self):
        # Create user and confirm password is None
        user = self._create_user(None)
        user_ref = self._get_user_ref(user['id'])
        self.assertIsNone(user_ref.password)
        # Update the password
        self.assertValidPasswordUpdate(user, self.passwords[0])
        self.assertValidPasswordUpdate(user, self.passwords[1])
        # Attempt to update with a previous password
        user['password'] = self.passwords[0]
        self.assertRaises(exception.PasswordValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_validate_password_history_disabled_and_repeat_same_password(self):
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=1)
        user = self._create_user(self.passwords[0])
        # Repeatedly update the password with the same password
        self.assertValidPasswordUpdate(user, self.passwords[0])
        self.assertValidPasswordUpdate(user, self.passwords[0])

    def test_truncate_passwords(self):
        user = self._create_user(self.passwords[0])
        self._add_passwords_to_history(user, n=4)
        user_ref = self._get_user_ref(user['id'])
        self.assertEqual(
            len(user_ref.local_user.passwords), (self.max_cnt + 1))

    def test_truncate_passwords_when_max_is_default(self):
        self.max_cnt = 1
        expected_length = self.max_cnt + 1
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=self.max_cnt)
        user = self._create_user(self.passwords[0])
        self._add_passwords_to_history(user, n=4)
        user_ref = self._get_user_ref(user['id'])
        self.assertEqual(len(user_ref.local_user.passwords), expected_length)
        # Start with multiple passwords and then change max_cnt to one
        self.max_cnt = 4
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=self.max_cnt)
        self._add_passwords_to_history(user, n=self.max_cnt)
        user_ref = self._get_user_ref(user['id'])
        self.assertEqual(
            len(user_ref.local_user.passwords), (self.max_cnt + 1))
        self.max_cnt = 1
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=self.max_cnt)
        self._add_passwords_to_history(user, n=1)
        user_ref = self._get_user_ref(user['id'])
        self.assertEqual(len(user_ref.local_user.passwords), expected_length)

    def test_truncate_passwords_when_max_is_default_and_no_password(self):
        expected_length = 1
        self.max_cnt = 1
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=self.max_cnt)
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': 'default',
            'enabled': True,
        }
        user = self.identity_api.create_user(user)
        self._add_passwords_to_history(user, n=1)
        user_ref = self._get_user_ref(user['id'])
        self.assertEqual(len(user_ref.local_user.passwords), expected_length)

    def _create_user(self, password):
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': 'default',
            'enabled': True,
            'password': password
        }
        return self.identity_api.create_user(user)

    def assertValidPasswordUpdate(self, user, new_password):
        user['password'] = new_password
        self.identity_api.update_user(user['id'], user)
        self.identity_api.authenticate(self.make_request(),
                                       user_id=user['id'],
                                       password=new_password)

    def _add_passwords_to_history(self, user, n):
        for _ in range(n):
            user['password'] = uuid.uuid4().hex
            self.identity_api.update_user(user['id'], user)

    def _get_user_ref(self, user_id):
        with sql.session_for_read() as session:
            return self.identity_api._get_user(session, user_id)
