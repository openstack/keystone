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

import freezegun
import passlib.hash

from keystone.common import password_hashing
from keystone.common import provider_api
from keystone.common import resource_options
from keystone.common import sql
import keystone.conf
from keystone import exception
from keystone.identity.backends import base
from keystone.identity.backends import resource_options as iro
from keystone.identity.backends import sql_model as model
from keystone.tests.unit import test_backend_sql


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class UserPasswordCreatedAtIntTests(test_backend_sql.SqlTests):
    def config_overrides(self):
        super(UserPasswordCreatedAtIntTests, self).config_overrides()
        self.config_fixture.config(group='security_compliance',
                                   password_expires_days=1)

    def test_user_password_created_expired_at_int_matches_created_at(self):
        with sql.session_for_read() as session:
            user_ref = PROVIDERS.identity_api._get_user(
                session, self.user_foo['id']
            )
            self.assertIsNotNone(user_ref.password_ref._created_at)
            self.assertIsNotNone(user_ref.password_ref._expires_at)
            self.assertEqual(user_ref.password_ref._created_at,
                             user_ref.password_ref.created_at_int)
            self.assertEqual(user_ref.password_ref._expires_at,
                             user_ref.password_ref.expires_at_int)
            self.assertEqual(user_ref.password_ref.created_at,
                             user_ref.password_ref.created_at_int)
            self.assertEqual(user_ref.password_ref.expires_at,
                             user_ref.password_ref.expires_at_int)


class UserPasswordHashingTestsNoCompat(test_backend_sql.SqlTests):
    def config_overrides(self):
        super(UserPasswordHashingTestsNoCompat, self).config_overrides()
        self.config_fixture.config(group='identity',
                                   password_hash_algorithm='scrypt')

    def test_configured_algorithm_used(self):
        with sql.session_for_read() as session:
            user_ref = PROVIDERS.identity_api._get_user(
                session, self.user_foo['id']
            )
        self.assertEqual(
            passlib.hash.scrypt,
            password_hashing._get_hasher_from_ident(user_ref.password))


class UserResourceOptionTests(test_backend_sql.SqlTests):
    def setUp(self):
        super(UserResourceOptionTests, self).setUp()
        # RESET STATE OF REGISTRY OPTIONS
        self.addCleanup(iro.register_user_options)
        self.addCleanup(iro.USER_OPTIONS_REGISTRY._registered_options.clear)

        self.option1 = resource_options.ResourceOption('opt1', 'option1')
        self.option2 = resource_options.ResourceOption('opt2', 'option2')
        self.cleanup_instance('option1', 'option2')

        iro.USER_OPTIONS_REGISTRY._registered_options.clear()
        iro.USER_OPTIONS_REGISTRY.register_option(self.option1)
        iro.USER_OPTIONS_REGISTRY.register_option(self.option2)

    def test_user_set_option_in_resource_option(self):
        user = self._create_user(self._get_user_dict())
        opt_value = uuid.uuid4().hex
        user['options'][self.option1.option_name] = opt_value
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertEqual(opt_value,
                         new_ref['options'][self.option1.option_name])
        raw_ref = self._get_user_ref(user['id'])
        self.assertIn(self.option1.option_id, raw_ref._resource_option_mapper)
        self.assertEqual(
            opt_value,
            raw_ref._resource_option_mapper[
                self.option1.option_id].option_value)
        api_get_ref = PROVIDERS.identity_api.get_user(user['id'])
        # Ensure options are properly set in a .get_user call.
        self.assertEqual(opt_value,
                         api_get_ref['options'][self.option1.option_name])

    def test_user_add_update_delete_option_in_resource_option(self):
        user = self._create_user(self._get_user_dict())

        opt_value = uuid.uuid4().hex
        new_opt_value = uuid.uuid4().hex

        # Update user to add the new value option
        user['options'][self.option1.option_name] = opt_value
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertEqual(opt_value,
                         new_ref['options'][self.option1.option_name])

        # Update the option Value and confirm it is updated
        user['options'][self.option1.option_name] = new_opt_value
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertEqual(new_opt_value,
                         new_ref['options'][self.option1.option_name])

        # Set the option value to None, meaning delete the option
        user['options'][self.option1.option_name] = None
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertNotIn(self.option1.option_name, new_ref['options'])

    def test_user_add_delete_resource_option_existing_option_values(self):
        user = self._create_user(self._get_user_dict())

        opt_value = uuid.uuid4().hex
        opt2_value = uuid.uuid4().hex

        # Update user to add the new value option
        user['options'][self.option1.option_name] = opt_value
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertEqual(opt_value,
                         new_ref['options'][self.option1.option_name])

        # Update the option value for option 2 and confirm it is updated and
        # option1's value remains the same. Option 1 is not specified in the
        # updated user ref.
        del user['options'][self.option1.option_name]
        user['options'][self.option2.option_name] = opt2_value
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertEqual(opt_value,
                         new_ref['options'][self.option1.option_name])
        self.assertEqual(opt2_value,
                         new_ref['options'][self.option2.option_name])
        raw_ref = self._get_user_ref(user['id'])
        self.assertEqual(
            opt_value,
            raw_ref._resource_option_mapper[
                self.option1.option_id].option_value)
        self.assertEqual(
            opt2_value,
            raw_ref._resource_option_mapper[
                self.option2.option_id].option_value)

        # Set the option value to None, meaning delete the option, ensure
        # option 2 still remains and has the right value
        user['options'][self.option1.option_name] = None
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertNotIn(self.option1.option_name, new_ref['options'])
        self.assertEqual(opt2_value,
                         new_ref['options'][self.option2.option_name])
        raw_ref = self._get_user_ref(user['id'])
        self.assertNotIn(raw_ref._resource_option_mapper,
                         self.option1.option_id)
        self.assertEqual(
            opt2_value,
            raw_ref._resource_option_mapper[
                self.option2.option_id].option_value)

    def test_unregistered_resource_option_deleted(self):
        user = self._create_user(self._get_user_dict())

        opt_value = uuid.uuid4().hex
        opt2_value = uuid.uuid4().hex

        # Update user to add the new value option
        user['options'][self.option1.option_name] = opt_value
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertEqual(opt_value,
                         new_ref['options'][self.option1.option_name])

        # Update the option value for option 2 and confirm it is updated and
        # option1's value remains the same. Option 1 is not specified in the
        # updated user ref.
        del user['options'][self.option1.option_name]
        user['options'][self.option2.option_name] = opt2_value
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertEqual(opt_value,
                         new_ref['options'][self.option1.option_name])
        self.assertEqual(opt2_value,
                         new_ref['options'][self.option2.option_name])
        raw_ref = self._get_user_ref(user['id'])
        self.assertEqual(
            opt_value,
            raw_ref._resource_option_mapper[
                self.option1.option_id].option_value)
        self.assertEqual(
            opt2_value,
            raw_ref._resource_option_mapper[
                self.option2.option_id].option_value)

        # clear registered options and only re-register option1, update user
        # and confirm option2 is gone from the ref and returned dict
        iro.USER_OPTIONS_REGISTRY._registered_options.clear()
        iro.USER_OPTIONS_REGISTRY.register_option(self.option1)
        user['name'] = uuid.uuid4().hex
        new_ref = PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertNotIn(self.option2.option_name, new_ref['options'])
        self.assertEqual(opt_value,
                         new_ref['options'][self.option1.option_name])
        raw_ref = self._get_user_ref(user['id'])
        self.assertNotIn(raw_ref._resource_option_mapper,
                         self.option2.option_id)
        self.assertEqual(
            opt_value,
            raw_ref._resource_option_mapper[
                self.option1.option_id].option_value)

    def _get_user_ref(self, user_id):
        with sql.session_for_read() as session:
            return session.query(model.User).get(user_id)

    def _create_user(self, user_dict):
        user_dict['id'] = uuid.uuid4().hex
        with sql.session_for_write() as session:
            user_ref = model.User.from_dict(user_dict)
            session.add(user_ref)
            return base.filter_user(user_ref.to_dict())

    def _get_user_dict(self):
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'enabled': True,
            'password': uuid.uuid4().hex
        }
        return user


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
        with self.make_request():
            self.assertRaises(exception.UserDisabled,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password=self.password)
            # verify that the user is actually disabled
            user = PROVIDERS.identity_api.get_user(user['id'])
            self.assertFalse(user['enabled'])
            # set the user to enabled and authenticate
            user['enabled'] = True
            PROVIDERS.identity_api.update_user(user['id'], user)
            user = PROVIDERS.identity_api.authenticate(
                user_id=user['id'], password=self.password
            )
            self.assertTrue(user['enabled'])

    def test_authenticate_user_not_disabled_due_to_inactivity(self):
        # create user and set last_active_at just below the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(days=self.max_inactive_days - 1)).date()
        user = self._create_user(self.user_dict, last_active_at)
        with self.make_request():
            user = PROVIDERS.identity_api.authenticate(
                user_id=user['id'], password=self.password
            )
        self.assertTrue(user['enabled'])

    def test_get_user_disabled_due_to_inactivity(self):
        user = PROVIDERS.identity_api.create_user(self.user_dict)
        # set last_active_at just beyond the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(self.max_inactive_days + 1)).date()
        self._update_user_last_active_at(user['id'], last_active_at)
        # get user and verify that the user is actually disabled
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertFalse(user['enabled'])
        # set enabled and test
        user['enabled'] = True
        PROVIDERS.identity_api.update_user(user['id'], user)
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertTrue(user['enabled'])

    def test_get_user_not_disabled_due_to_inactivity(self):
        user = PROVIDERS.identity_api.create_user(self.user_dict)
        self.assertTrue(user['enabled'])
        # set last_active_at just below the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(self.max_inactive_days - 1)).date()
        self._update_user_last_active_at(user['id'], last_active_at)
        # get user and verify that the user is still enabled
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertTrue(user['enabled'])

    def test_enabled_after_create_update_user(self):
        self.config_fixture.config(group='security_compliance',
                                   disable_user_account_days_inactive=90)
        # create user without enabled; assert enabled
        del self.user_dict['enabled']
        user = PROVIDERS.identity_api.create_user(self.user_dict)
        user_ref = self._get_user_ref(user['id'])
        self.assertTrue(user_ref.enabled)
        now = datetime.datetime.utcnow().date()
        self.assertGreaterEqual(now, user_ref.last_active_at)
        # set enabled and test
        user['enabled'] = True
        PROVIDERS.identity_api.update_user(user['id'], user)
        user_ref = self._get_user_ref(user['id'])
        self.assertTrue(user_ref.enabled)
        # set disabled and test
        user['enabled'] = False
        PROVIDERS.identity_api.update_user(user['id'], user)
        user_ref = self._get_user_ref(user['id'])
        self.assertFalse(user_ref.enabled)
        # re-enable user and test
        user['enabled'] = True
        PROVIDERS.identity_api.update_user(user['id'], user)
        user_ref = self._get_user_ref(user['id'])
        self.assertTrue(user_ref.enabled)

    def test_ignore_user_inactivity(self):
        self.user_dict['options'] = {'ignore_user_inactivity': True}
        user = PROVIDERS.identity_api.create_user(
            self.user_dict)
        # set last_active_at just beyond the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(self.max_inactive_days + 1)).date()
        self._update_user_last_active_at(user['id'], last_active_at)
        # get user and verify that the user is not disabled
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertTrue(user['enabled'])

    def test_ignore_user_inactivity_with_user_disabled(self):
        user = PROVIDERS.identity_api.create_user(
            self.user_dict)
        # set last_active_at just beyond the max
        last_active_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(self.max_inactive_days + 1)).date()
        self._update_user_last_active_at(user['id'], last_active_at)
        # get user and verify that the user is disabled
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertFalse(user['enabled'])
        # update disabled user with ignore_user_inactivity to true
        user['options'] = {'ignore_user_inactivity': True}
        user = PROVIDERS.identity_api.update_user(
            user['id'], user)
        # user is not enabled
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertFalse(user['enabled'])
        # Manually set enabled and test
        user['enabled'] = True
        PROVIDERS.identity_api.update_user(user['id'], user)
        user = PROVIDERS.identity_api.get_user(user['id'])
        self.assertTrue(user['enabled'])

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
        with sql.session_for_write() as session:
            user_ref = model.User.from_dict(user_dict)
            user_ref.last_active_at = last_active_at
            session.add(user_ref)
            return base.filter_user(user_ref.to_dict())

    def _update_user_last_active_at(self, user_id, last_active_at):
        with sql.session_for_write() as session:
            user_ref = session.query(model.User).get(user_id)
            user_ref.last_active_at = last_active_at
            return user_ref


class PasswordHistoryValidationTests(test_backend_sql.SqlTests):
    def setUp(self):
        super(PasswordHistoryValidationTests, self).setUp()
        self.max_cnt = 3
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=self.max_cnt)

    def test_validate_password_history_with_invalid_password(self):
        password = uuid.uuid4().hex
        user = self._create_user(password)
        # Attempt to change to the same password
        with self.make_request():
            self.assertRaises(exception.PasswordValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=user['id'],
                              original_password=password,
                              new_password=password)
            # Attempt to change to a unique password
            new_password = uuid.uuid4().hex
            self.assertValidChangePassword(user['id'], password, new_password)
            # Attempt to change back to the initial password
            self.assertRaises(exception.PasswordValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=user['id'],
                              original_password=new_password,
                              new_password=password)

    def test_validate_password_history_with_valid_password(self):
        passwords = [uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex,
                     uuid.uuid4().hex]
        user = self._create_user(passwords[0])
        self.assertValidChangePassword(user['id'], passwords[0], passwords[1])
        self.assertValidChangePassword(user['id'], passwords[1], passwords[2])
        self.assertValidChangePassword(user['id'], passwords[2], passwords[3])
        # Now you should be able to change the password to match the initial
        # password because the password history only contains password elements
        # 1, 2, 3
        self.assertValidChangePassword(user['id'], passwords[3], passwords[0])

    def test_validate_password_history_with_valid_password_only_once(self):
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=1)
        passwords = [uuid.uuid4().hex, uuid.uuid4().hex]
        user = self._create_user(passwords[0])
        self.assertValidChangePassword(user['id'], passwords[0], passwords[1])
        self.assertValidChangePassword(user['id'], passwords[1], passwords[0])

    def test_validate_password_history_but_start_with_password_none(self):
        passwords = [uuid.uuid4().hex, uuid.uuid4().hex]
        # Create user and confirm password is None
        user = self._create_user(None)
        user_ref = self._get_user_ref(user['id'])
        self.assertIsNone(user_ref.password)
        # Admin password reset
        user['password'] = passwords[0]
        PROVIDERS.identity_api.update_user(user['id'], user)
        # Self-service change password
        self.assertValidChangePassword(user['id'], passwords[0], passwords[1])
        # Attempt to update with a previous password
        with self.make_request():
            self.assertRaises(exception.PasswordValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=user['id'],
                              original_password=passwords[1],
                              new_password=passwords[0])

    def test_disable_password_history_and_repeat_same_password(self):
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=0)
        password = uuid.uuid4().hex
        user = self._create_user(password)
        # Repeatedly change password with the same password
        self.assertValidChangePassword(user['id'], password, password)
        self.assertValidChangePassword(user['id'], password, password)

    def test_admin_password_reset_is_not_validated_by_password_history(self):
        passwords = [uuid.uuid4().hex, uuid.uuid4().hex]
        user = self._create_user(passwords[0])
        # Attempt to change password to a unique password
        user['password'] = passwords[1]
        with self.make_request():
            PROVIDERS.identity_api.update_user(user['id'], user)
            PROVIDERS.identity_api.authenticate(
                user_id=user['id'], password=passwords[1]
            )
            # Attempt to change password with the same password
            user['password'] = passwords[1]
            PROVIDERS.identity_api.update_user(user['id'], user)
            PROVIDERS.identity_api.authenticate(
                user_id=user['id'], password=passwords[1]
            )
            # Attempt to change password with the initial password
            user['password'] = passwords[0]
            PROVIDERS.identity_api.update_user(user['id'], user)
            PROVIDERS.identity_api.authenticate(
                user_id=user['id'], password=passwords[0]
            )

    def test_truncate_passwords(self):
        user = self._create_user(uuid.uuid4().hex)
        self._add_passwords_to_history(user, n=4)
        user_ref = self._get_user_ref(user['id'])
        self.assertEqual(
            len(user_ref.local_user.passwords), (self.max_cnt + 1))

    def test_truncate_passwords_when_max_is_default(self):
        self.max_cnt = 1
        expected_length = self.max_cnt + 1
        self.config_fixture.config(group='security_compliance',
                                   unique_last_password_count=self.max_cnt)
        user = self._create_user(uuid.uuid4().hex)
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
        user = PROVIDERS.identity_api.create_user(user)
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
        return PROVIDERS.identity_api.create_user(user)

    def assertValidChangePassword(self, user_id, password, new_password):
        with self.make_request():
            PROVIDERS.identity_api.change_password(
                user_id=user_id, original_password=password,
                new_password=new_password
            )
            PROVIDERS.identity_api.authenticate(
                user_id=user_id, password=new_password
            )

    def _add_passwords_to_history(self, user, n):
        for _ in range(n):
            user['password'] = uuid.uuid4().hex
            PROVIDERS.identity_api.update_user(user['id'], user)

    def _get_user_ref(self, user_id):
        with sql.session_for_read() as session:
            return PROVIDERS.identity_api._get_user(session, user_id)


class LockingOutUserTests(test_backend_sql.SqlTests):
    def setUp(self):
        super(LockingOutUserTests, self).setUp()
        self.config_fixture.config(
            group='security_compliance',
            lockout_failure_attempts=6)
        self.config_fixture.config(
            group='security_compliance',
            lockout_duration=5)
        # create user
        self.password = uuid.uuid4().hex
        user_dict = {
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'enabled': True,
            'password': self.password
        }
        self.user = PROVIDERS.identity_api.create_user(user_dict)

    def test_locking_out_user_after_max_failed_attempts(self):
        with self.make_request():
            # authenticate with wrong password
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=self.user['id'],
                              password=uuid.uuid4().hex)
            # authenticate with correct password
            PROVIDERS.identity_api.authenticate(
                user_id=self.user['id'],
                password=self.password
            )
            # test locking out user after max failed attempts
            self._fail_auth_repeatedly(self.user['id'])
            self.assertRaises(exception.Unauthorized,
                              PROVIDERS.identity_api.authenticate,
                              user_id=self.user['id'],
                              password=uuid.uuid4().hex)

    def test_lock_out_for_ignored_user(self):
        # mark the user as exempt from failed password attempts
        # ignore user and reset password, password not expired
        self.user['options'][iro.IGNORE_LOCKOUT_ATTEMPT_OPT.option_name] = True
        PROVIDERS.identity_api.update_user(self.user['id'], self.user)

        # fail authentication repeatedly the max number of times
        self._fail_auth_repeatedly(self.user['id'])
        # authenticate with wrong password, account should not be locked
        with self.make_request():
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=self.user['id'],
                              password=uuid.uuid4().hex)
            # authenticate with correct password, account should not be locked
            PROVIDERS.identity_api.authenticate(
                user_id=self.user['id'],
                password=self.password
            )

    def test_set_enabled_unlocks_user(self):
        with self.make_request():
            # lockout user
            self._fail_auth_repeatedly(self.user['id'])
            self.assertRaises(exception.Unauthorized,
                              PROVIDERS.identity_api.authenticate,
                              user_id=self.user['id'],
                              password=uuid.uuid4().hex)
            # set enabled, user should be unlocked
            self.user['enabled'] = True
            PROVIDERS.identity_api.update_user(self.user['id'], self.user)
            user_ret = PROVIDERS.identity_api.authenticate(
                user_id=self.user['id'],
                password=self.password
            )
            self.assertTrue(user_ret['enabled'])

    def test_lockout_duration(self):
        # freeze time
        with freezegun.freeze_time(datetime.datetime.utcnow()) as frozen_time:
            with self.make_request():
                # lockout user
                self._fail_auth_repeatedly(self.user['id'])
                self.assertRaises(exception.Unauthorized,
                                  PROVIDERS.identity_api.authenticate,
                                  user_id=self.user['id'],
                                  password=uuid.uuid4().hex)
                # freeze time past the duration, user should be unlocked and
                # failed auth count should get reset
                frozen_time.tick(delta=datetime.timedelta(
                    seconds=CONF.security_compliance.lockout_duration + 1))
                PROVIDERS.identity_api.authenticate(
                    user_id=self.user['id'],
                    password=self.password
                )
                # test failed auth count was reset by authenticating with the
                # wrong password, should raise an assertion error and not
                # account locked
                self.assertRaises(AssertionError,
                                  PROVIDERS.identity_api.authenticate,
                                  user_id=self.user['id'],
                                  password=uuid.uuid4().hex)

    def test_lockout_duration_failed_auth_cnt_resets(self):
        # freeze time
        with freezegun.freeze_time(datetime.datetime.utcnow()) as frozen_time:
            with self.make_request():
                # lockout user
                self._fail_auth_repeatedly(self.user['id'])
                self.assertRaises(exception.Unauthorized,
                                  PROVIDERS.identity_api.authenticate,
                                  user_id=self.user['id'],
                                  password=uuid.uuid4().hex)
                # freeze time past the duration, failed_auth_cnt should reset
                frozen_time.tick(delta=datetime.timedelta(
                    seconds=CONF.security_compliance.lockout_duration + 1))
                # repeat failed auth the max times
                self._fail_auth_repeatedly(self.user['id'])
                # test user account is locked
                self.assertRaises(exception.Unauthorized,
                                  PROVIDERS.identity_api.authenticate,
                                  user_id=self.user['id'],
                                  password=uuid.uuid4().hex)

    def _fail_auth_repeatedly(self, user_id):
        wrong_password = uuid.uuid4().hex
        for _ in range(CONF.security_compliance.lockout_failure_attempts):
            with self.make_request():
                self.assertRaises(AssertionError,
                                  PROVIDERS.identity_api.authenticate,
                                  user_id=user_id,
                                  password=wrong_password)


class PasswordExpiresValidationTests(test_backend_sql.SqlTests):
    def setUp(self):
        super(PasswordExpiresValidationTests, self).setUp()
        self.password = uuid.uuid4().hex
        self.user_dict = self._get_test_user_dict(self.password)
        self.config_fixture.config(
            group='security_compliance',
            password_expires_days=90)

    def test_authenticate_with_expired_password(self):
        # set password created_at so that the password will expire
        password_created_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(
                days=CONF.security_compliance.password_expires_days + 1)
        )
        user = self._create_user(self.user_dict, password_created_at)
        # test password is expired
        with self.make_request():
            self.assertRaises(exception.PasswordExpired,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password=self.password)

    def test_authenticate_with_non_expired_password(self):
        # set password created_at so that the password will not expire
        password_created_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(
                days=CONF.security_compliance.password_expires_days - 1)
        )
        user = self._create_user(self.user_dict, password_created_at)
        # test password is not expired
        with self.make_request():
            PROVIDERS.identity_api.authenticate(
                user_id=user['id'], password=self.password
            )

    def test_authenticate_with_expired_password_for_ignore_user_option(self):
        # set user to have the 'ignore_password_expiry' option set to False
        self.user_dict.setdefault('options', {})[
            iro.IGNORE_PASSWORD_EXPIRY_OPT.option_name] = False
        # set password created_at so that the password will expire
        password_created_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(
                days=CONF.security_compliance.password_expires_days + 1)
        )
        user = self._create_user(self.user_dict, password_created_at)
        with self.make_request():
            self.assertRaises(exception.PasswordExpired,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password=self.password)

            # update user to explicitly have the expiry option to True
            user['options'][
                iro.IGNORE_PASSWORD_EXPIRY_OPT.option_name] = True
            user = PROVIDERS.identity_api.update_user(
                user['id'], user
            )
            # test password is not expired due to ignore option
            PROVIDERS.identity_api.authenticate(
                user_id=user['id'], password=self.password
            )

    def _get_test_user_dict(self, password):
        test_user_dict = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'enabled': True,
            'password': password
        }
        return test_user_dict

    def _create_user(self, user_dict, password_created_at):
        # Bypass business logic and go straight for the identity driver
        # (SQL in this case)
        driver = PROVIDERS.identity_api.driver
        driver.create_user(user_dict['id'], user_dict)
        with sql.session_for_write() as session:
            user_ref = session.query(model.User).get(user_dict['id'])
            user_ref.password_ref.created_at = password_created_at
            user_ref.password_ref.expires_at = (
                user_ref._get_password_expires_at(password_created_at))
            return base.filter_user(user_ref.to_dict())


class MinimumPasswordAgeTests(test_backend_sql.SqlTests):
    def setUp(self):
        super(MinimumPasswordAgeTests, self).setUp()
        self.config_fixture.config(
            group='security_compliance',
            minimum_password_age=1)
        self.initial_password = uuid.uuid4().hex
        self.user = self._create_new_user(self.initial_password)

    def test_user_cannot_change_password_before_min_age(self):
        # user can change password after create
        new_password = uuid.uuid4().hex
        self.assertValidChangePassword(self.user['id'], self.initial_password,
                                       new_password)
        # user cannot change password before min age
        with self.make_request():
            self.assertRaises(exception.PasswordAgeValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=self.user['id'],
                              original_password=new_password,
                              new_password=uuid.uuid4().hex)

    def test_user_can_change_password_after_min_age(self):
        # user can change password after create
        new_password = uuid.uuid4().hex
        self.assertValidChangePassword(self.user['id'], self.initial_password,
                                       new_password)
        # set password_created_at so that the min password age has past
        password_created_at = (
            datetime.datetime.utcnow() -
            datetime.timedelta(
                days=CONF.security_compliance.minimum_password_age + 1))
        self._update_password_created_at(self.user['id'], password_created_at)
        # user can change their password after min password age has past
        self.assertValidChangePassword(self.user['id'], new_password,
                                       uuid.uuid4().hex)

    def test_user_can_change_password_after_admin_reset(self):
        # user can change password after create
        new_password = uuid.uuid4().hex
        self.assertValidChangePassword(self.user['id'], self.initial_password,
                                       new_password)
        # user cannot change password before min age

        with self.make_request():
            self.assertRaises(exception.PasswordAgeValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=self.user['id'],
                              original_password=new_password,
                              new_password=uuid.uuid4().hex)
        # admin reset
        new_password = uuid.uuid4().hex
        self.user['password'] = new_password
        PROVIDERS.identity_api.update_user(self.user['id'], self.user)
        # user can change password after admin reset
        self.assertValidChangePassword(self.user['id'], new_password,
                                       uuid.uuid4().hex)

    def assertValidChangePassword(self, user_id, password, new_password):
        with self.make_request():
            PROVIDERS.identity_api.change_password(
                user_id=user_id, original_password=password,
                new_password=new_password
            )
            PROVIDERS.identity_api.authenticate(
                user_id=user_id, password=new_password
            )

    def _create_new_user(self, password):
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'enabled': True,
            'password': password
        }
        return PROVIDERS.identity_api.create_user(user)

    def _update_password_created_at(self, user_id, password_create_at):
        # User instance has an attribute password_ref. This attribute is used
        # in authentication. It always points to the last created password. The
        # order of passwords is determined by `created_at` field.
        # By changing `created_at`, this method interferes with password_ref
        # behaviour, making it return not last value. That's why all passwords
        # except the latest, need to have `created_at` slightly less than
        # the latest password.
        with sql.session_for_write() as session:
            user_ref = session.query(model.User).get(user_id)
            latest_password = user_ref.password_ref
            slightly_less = datetime.timedelta(minutes=1)
            for password_ref in user_ref.local_user.passwords:
                password_ref.created_at = password_create_at - slightly_less
            latest_password.created_at = password_create_at


class ChangePasswordRequiredAfterFirstUse(test_backend_sql.SqlTests):
    def _create_user(self, password, change_password_upon_first_use):
        self.config_fixture.config(
            group='security_compliance',
            change_password_upon_first_use=change_password_upon_first_use)
        user_dict = {
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'enabled': True,
            'password': password
        }
        return PROVIDERS.identity_api.create_user(user_dict)

    def assertPasswordIsExpired(self, user_id, password):
        with self.make_request():
            self.assertRaises(exception.PasswordExpired,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user_id,
                              password=password)

    def assertPasswordIsNotExpired(self, user_id, password):
        with self.make_request():
            PROVIDERS.identity_api.authenticate(
                user_id=user_id, password=password
            )

    def test_password_expired_after_create(self):
        # create user, password expired
        initial_password = uuid.uuid4().hex
        user = self._create_user(initial_password, True)
        self.assertPasswordIsExpired(user['id'], initial_password)
        # change password (self-service), password not expired
        new_password = uuid.uuid4().hex
        with self.make_request():
            PROVIDERS.identity_api.change_password(
                user['id'], initial_password, new_password
            )
        self.assertPasswordIsNotExpired(user['id'], new_password)

    def test_password_expired_after_reset(self):
        # create user with feature disabled, password not expired
        initial_password = uuid.uuid4().hex
        user = self._create_user(initial_password, False)
        self.assertPasswordIsNotExpired(user['id'], initial_password)
        # enable change_password_upon_first_use
        self.config_fixture.config(
            group='security_compliance',
            change_password_upon_first_use=True)
        # admin reset, password expired
        admin_password = uuid.uuid4().hex
        user['password'] = admin_password
        PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertPasswordIsExpired(user['id'], admin_password)
        # change password (self-service), password not expired
        new_password = uuid.uuid4().hex
        with self.make_request():
            PROVIDERS.identity_api.change_password(
                user['id'], admin_password, new_password
            )
        self.assertPasswordIsNotExpired(user['id'], new_password)

    def test_password_not_expired_when_feature_disabled(self):
        # create user with feature disabled
        initial_password = uuid.uuid4().hex
        user = self._create_user(initial_password, False)
        self.assertPasswordIsNotExpired(user['id'], initial_password)
        # admin reset
        admin_password = uuid.uuid4().hex
        user['password'] = admin_password
        PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertPasswordIsNotExpired(user['id'], admin_password)

    def test_password_not_expired_for_ignore_user(self):
        # create user with feature disabled, password not expired
        initial_password = uuid.uuid4().hex
        user = self._create_user(initial_password, False)
        self.assertPasswordIsNotExpired(user['id'], initial_password)
        # enable change_password_upon_first_use
        self.config_fixture.config(
            group='security_compliance',
            change_password_upon_first_use=True)
        # ignore user and reset password, password not expired
        user['options'][iro.IGNORE_CHANGE_PASSWORD_OPT.option_name] = True
        admin_password = uuid.uuid4().hex
        user['password'] = admin_password
        PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertPasswordIsNotExpired(user['id'], admin_password)
        # set ignore user to false and reset password, password is expired
        user['options'][iro.IGNORE_CHANGE_PASSWORD_OPT.option_name] = False
        admin_password = uuid.uuid4().hex
        user['password'] = admin_password
        PROVIDERS.identity_api.update_user(user['id'], user)
        self.assertPasswordIsExpired(user['id'], admin_password)
