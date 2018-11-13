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

import uuid

from keystone.common import driver_hints
from keystone import exception


class IdentityDriverTests(object):
    driver = None  # subclasses must override driver to the actual driver.

    # subclasses that don't allow name updates must set this to False.
    allows_name_update = True

    # subclasses that don't allow self-service password changes must set this
    # to False.
    allows_self_service_change_password = True

    # Subclasses must override this to indicate whether it's domain-aware or
    # not.
    expected_is_domain_aware = True

    # Subclasses must override this to the expected default assignment driver.
    expected_default_assignment_driver = 'sql'

    # Subclasses must override this to the expected is_sql value.
    expected_is_sql = False

    # Subclasses must override this to the expected expected_generates_uuids
    # value.
    expected_generates_uuids = True

    def create_user(self, domain_id=None, **kwargs):
        """Get a user for the test.

        Subclasses can override this to provide their own way to provide a user
        for the test. By default, driver.create_user is used. For drivers that
        don't support create_user, this may go directly to the backend, or
        maybe it gets a user from a set of pre-created users.
        """
        user_id = uuid.uuid4().hex
        user = {
            'id': user_id,
            'name': uuid.uuid4().hex,
            'enabled': True,
        }
        if self.driver.is_domain_aware():
            user['domain_id'] = domain_id or uuid.uuid4().hex
        user.update(kwargs)
        return self.driver.create_user(user_id, user)

    def create_group(self, domain_id=None):
        """Get a group for the test.

        Similar to :meth:`~.create_user`, subclasses can override this to
        provide their own way to provide a group for the test.
        """
        group_id = uuid.uuid4().hex
        group = {
            'id': group_id,
            'name': uuid.uuid4().hex,
        }
        if self.driver.is_domain_aware():
            group['domain_id'] = domain_id or uuid.uuid4().hex
        return self.driver.create_group(group_id, group)

    def test_is_domain_aware(self):
        self.assertIs(self.expected_is_domain_aware,
                      self.driver.is_domain_aware())

    def test_is_sql(self):
        self.assertIs(self.expected_is_sql, self.driver.is_sql)

    def test_generates_uuids(self):
        self.assertIs(self.expected_generates_uuids,
                      self.driver.generates_uuids())

    def test_create_user(self):
        # Don't use self.create_user since this needs to test the driver
        # interface and create_user might not use the driver.
        user_id = uuid.uuid4().hex
        user = {
            'id': user_id,
            'name': uuid.uuid4().hex,
            'enabled': True
        }
        if self.driver.is_domain_aware():
            user['domain_id'] = uuid.uuid4().hex
        ret = self.driver.create_user(user_id, user)
        self.assertEqual(user_id, ret['id'])

    def test_create_user_all_attributes(self):
        user_id = uuid.uuid4().hex
        user = {
            'id': user_id,
            'name': uuid.uuid4().hex,
            'password': uuid.uuid4().hex,
            'enabled': True,
            'default_project_id': uuid.uuid4().hex,
            'password_expires_at': None,
            'options': {}
        }
        if self.driver.is_domain_aware():
            user['domain_id'] = uuid.uuid4().hex
        ret = self.driver.create_user(user_id, user)
        exp_user = user.copy()
        del exp_user['password']
        self.assertEqual(exp_user, ret)

    def test_create_user_same_id_exc(self):
        user_id = uuid.uuid4().hex
        user = {
            'id': user_id,
            'name': uuid.uuid4().hex,
            'enabled': True,
        }
        if self.driver.is_domain_aware():
            user['domain_id'] = uuid.uuid4().hex
        self.driver.create_user(user_id, user)
        self.assertRaises(exception.Conflict,
                          self.driver.create_user, user_id, user)

    def test_create_user_same_name_and_domain_exc(self):
        user1_id = uuid.uuid4().hex
        name = uuid.uuid4().hex
        domain_id = uuid.uuid4().hex
        user = {
            'id': user1_id,
            'name': name,
            'enabled': True,
        }
        if self.driver.is_domain_aware():
            user['domain_id'] = domain_id
        self.driver.create_user(user1_id, user)

        user2_id = uuid.uuid4().hex
        user = {
            'id': user2_id,
            'name': name,
            'enabled': True,
        }
        if self.driver.is_domain_aware():
            user['domain_id'] = domain_id
        self.assertRaises(exception.Conflict,
                          self.driver.create_user, user2_id, user)

    def test_list_users_no_users(self):
        hints = driver_hints.Hints()
        self.assertEqual([], self.driver.list_users(hints))

    def test_list_users_when_users(self):
        user = self.create_user()

        hints = driver_hints.Hints()
        users = self.driver.list_users(hints)
        self.assertEqual([user['id']], [u['id'] for u in users])

    def test_get_user(self):
        user = self.create_user()

        actual_user = self.driver.get_user(user['id'])
        self.assertEqual(user['id'], actual_user['id'])

    def test_get_user_no_user_exc(self):
        self.assertRaises(exception.UserNotFound,
                          self.driver.get_user, uuid.uuid4().hex)

    def test_get_user_by_name(self):
        domain_id = uuid.uuid4().hex
        user = self.create_user(domain_id=domain_id)

        actual_user = self.driver.get_user_by_name(user['name'], domain_id)
        self.assertEqual(user['id'], actual_user['id'])

    def test_get_user_by_name_no_user_exc(self):
        # When the user doesn't exist, UserNotFound is raised.
        self.assertRaises(
            exception.UserNotFound, self.driver.get_user_by_name,
            user_name=uuid.uuid4().hex, domain_id=uuid.uuid4().hex)

    def test_update_user(self):
        user = self.create_user()

        user_mod = {'enabled': False}
        actual_user = self.driver.update_user(user['id'], user_mod)
        self.assertEqual(user['id'], actual_user['id'])
        self.assertIs(False, actual_user['enabled'])

    def test_update_user_remove_optional_attribute(self):
        # When the attribute has a value of None it's supposed to be removed.
        user = self.create_user(default_project_id=uuid.uuid4().hex)
        self.assertIn('default_project_id', user)

        user_mod = {'default_project_id': None}
        actual_user = self.driver.update_user(user['id'], user_mod)
        self.assertNotIn('default_project_id', actual_user)

    def test_update_user_same_name_exc(self):
        # For drivers that allow name update, if the name of a user is changed
        # to the same as another user in the same domain, Conflict is raised.

        if not self.allows_name_update:
            self.skipTest("Backend doesn't allow name update.")

        domain_id = uuid.uuid4().hex
        user1 = self.create_user(domain_id=domain_id)
        user2 = self.create_user(domain_id=domain_id)

        user_mod = {'name': user2['name']}
        self.assertRaises(exception.Conflict, self.driver.update_user,
                          user1['id'], user_mod)

    def test_update_user_no_user_exc(self):
        user_id = uuid.uuid4().hex
        user_mod = {'enabled': False}
        self.assertRaises(exception.UserNotFound,
                          self.driver.update_user, user_id, user_mod)

    def test_update_user_name_not_allowed_exc(self):
        # For drivers that do not allow name update, attempting to change the
        # name causes an exception.

        if self.allows_name_update:
            self.skipTest("Backend allows name update.")

        user = self.create_user()
        user_mod = {'name': uuid.uuid4().hex}
        self.assertRaises(exception.Conflict, self.driver.update_user,
                          user['id'], user_mod)

    def test_change_password(self):
        if not self.allows_self_service_change_password:
            self.skipTest("Backend doesn't allow change password.")
        # create user
        password = uuid.uuid4().hex
        domain_id = uuid.uuid4().hex
        user = self.create_user(domain_id=domain_id, password=password)
        # change password
        new_password = uuid.uuid4().hex
        self.driver.change_password(user['id'], new_password)
        self.driver.authenticate(user['id'], new_password)

    def test_delete_user(self):
        user = self.create_user()

        self.driver.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound, self.driver.get_user,
                          user['id'])

    def test_delete_user_no_user_exc(self):
        # When the user doesn't exist, UserNotFound is raised.
        self.assertRaises(exception.UserNotFound, self.driver.delete_user,
                          user_id=uuid.uuid4().hex)

    def test_create_group(self):
        group_id = uuid.uuid4().hex
        group = {
            'id': group_id,
            'name': uuid.uuid4().hex,
        }
        if self.driver.is_domain_aware():
            group['domain_id'] = uuid.uuid4().hex
        new_group = self.driver.create_group(group_id, group)
        self.assertEqual(group_id, new_group['id'])

    def test_create_group_all_attrs(self):
        group_id = uuid.uuid4().hex
        group = {
            'id': group_id,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        if self.driver.is_domain_aware():
            group['domain_id'] = uuid.uuid4().hex
        new_group = self.driver.create_group(group_id, group)
        self.assertEqual(group, new_group)

    def test_create_group_duplicate_exc(self):
        group1_id = uuid.uuid4().hex
        name = uuid.uuid4().hex
        domain = uuid.uuid4().hex
        group1 = {
            'id': group1_id,
            'name': name,
        }
        if self.driver.is_domain_aware():
            group1['domain_id'] = domain
        self.driver.create_group(group1_id, group1)

        group2_id = uuid.uuid4().hex
        group2 = {
            'id': group2_id,
            'name': name,
        }
        if self.driver.is_domain_aware():
            group2['domain_id'] = domain
        self.assertRaises(exception.Conflict, self.driver.create_group,
                          group2_id, group2)

    def test_get_group(self):
        group = self.create_group()

        actual_group = self.driver.get_group(group['id'])
        self.assertEqual(group['id'], actual_group['id'])

    def test_get_group_no_group_exc(self):
        # When the group doesn't exist, get_group raises GroupNotFound.
        self.assertRaises(exception.GroupNotFound, self.driver.get_group,
                          group_id=uuid.uuid4().hex)

    def test_get_group_by_name(self):
        domain_id = uuid.uuid4().hex
        group = self.create_group(domain_id=domain_id)

        actual_group = self.driver.get_group_by_name(group['name'], domain_id)
        self.assertEqual(group['id'], actual_group['id'])

    def test_get_group_by_name_no_user_exc(self):
        # When the group doesn't exist, get_group raises GroupNotFound.
        self.assertRaises(
            exception.GroupNotFound, self.driver.get_group_by_name,
            group_name=uuid.uuid4().hex, domain_id=uuid.uuid4().hex)

    def test_update_group(self):
        group = self.create_group()

        new_description = uuid.uuid4().hex
        group_mod = {'description': new_description}
        actual_group = self.driver.update_group(group['id'], group_mod)
        self.assertEqual(new_description, actual_group['description'])

    def test_update_group_no_group(self):
        # When the group doesn't exist, GroupNotFound is raised.
        group_mod = {'description': uuid.uuid4().hex}
        self.assertRaises(exception.GroupNotFound, self.driver.update_group,
                          group_id=uuid.uuid4().hex, group=group_mod)

    def test_update_group_name_already_exists(self):
        # For drivers that support renaming, when the group is renamed to a
        # name that already exists, Conflict is raised.

        if not self.allows_name_update:
            self.skipTest("driver doesn't allow name update")

        domain_id = uuid.uuid4().hex
        group1 = self.create_group(domain_id=domain_id)
        group2 = self.create_group(domain_id=domain_id)

        group_mod = {'name': group1['name']}
        self.assertRaises(exception.Conflict, self.driver.update_group,
                          group2['id'], group_mod)

    def test_update_group_name_not_allowed(self):
        # For drivers that do not support renaming, when the group is attempted
        # to be renamed ValidationError is raised.

        if self.allows_name_update:
            self.skipTest("driver allows name update")

        group = self.create_group()

        group_mod = {'name': uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError, self.driver.update_group,
                          group['id'], group_mod)

    def test_delete_group(self):
        group = self.create_group()
        self.driver.delete_group(group['id'])
        self.assertRaises(exception.GroupNotFound, self.driver.get_group,
                          group['id'])

    def test_delete_group_doesnt_exist_exc(self):
        self.assertRaises(exception.GroupNotFound, self.driver.delete_group,
                          group_id=uuid.uuid4().hex)

    def test_list_groups_no_groups(self):
        groups = self.driver.list_groups(driver_hints.Hints())
        self.assertEqual([], groups)

    def test_list_groups_one_group(self):
        group = self.create_group()
        groups = self.driver.list_groups(driver_hints.Hints())
        self.assertEqual(group['id'], groups[0]['id'])

    def test_add_user_to_group(self):
        user = self.create_user()
        group = self.create_group()

        self.driver.add_user_to_group(user['id'], group['id'])

        # No assert since if doesn't raise, then successful.
        self.driver.check_user_in_group(user['id'], group['id'])

    def test_add_user_to_group_no_user_exc(self):
        group = self.create_group()

        user_id = uuid.uuid4().hex
        self.assertRaises(exception.UserNotFound,
                          self.driver.add_user_to_group, user_id, group['id'])

    def test_add_user_to_group_no_group_exc(self):
        user = self.create_user()

        group_id = uuid.uuid4().hex
        self.assertRaises(exception.GroupNotFound,
                          self.driver.add_user_to_group, user['id'], group_id)

    def test_check_user_in_group(self):
        user = self.create_user()
        group = self.create_group()
        self.driver.add_user_to_group(user['id'], group['id'])

        # No assert since if doesn't raise, then successful.
        self.driver.check_user_in_group(user['id'], group['id'])

    def test_check_user_in_group_user_not_in_group_exc(self):
        user = self.create_user()
        group = self.create_group()

        self.assertRaises(exception.NotFound, self.driver.check_user_in_group,
                          user['id'], group['id'])

    def test_check_user_in_group_user_doesnt_exist_exc(self):
        # When the user doesn't exist, UserNotFound is raised.
        group = self.create_group()

        user_id = uuid.uuid4().hex
        self.assertRaises(
            exception.UserNotFound, self.driver.check_user_in_group, user_id,
            group['id'])

    def test_check_user_in_group_group_doesnt_exist_exc(self):
        # When the group doesn't exist, UserNotFound is raised.
        user = self.create_user()

        group_id = uuid.uuid4().hex
        self.assertRaises(
            exception.GroupNotFound, self.driver.check_user_in_group,
            user['id'], group_id)

    def test_list_users_in_group_no_users(self):
        group = self.create_group()

        users = self.driver.list_users_in_group(group['id'],
                                                driver_hints.Hints())
        self.assertEqual([], users)

    def test_list_users_in_group_user(self):
        group = self.create_group()
        user = self.create_user()
        self.driver.add_user_to_group(user['id'], group['id'])

        users = self.driver.list_users_in_group(group['id'],
                                                driver_hints.Hints())
        self.assertEqual([user['id']], [u['id'] for u in users])

    def test_list_users_in_group_no_group(self):
        group_id = uuid.uuid4().hex
        self.assertRaises(
            exception.GroupNotFound, self.driver.list_users_in_group, group_id,
            driver_hints.Hints())

    def test_list_groups_for_user_no_groups(self):
        user = self.create_user()

        groups = self.driver.list_groups_for_user(user['id'],
                                                  driver_hints.Hints())
        self.assertEqual([], groups)

    def test_list_groups_for_user_group(self):
        user = self.create_user()
        group = self.create_group()
        self.driver.add_user_to_group(user['id'], group['id'])

        groups = self.driver.list_groups_for_user(user['id'],
                                                  driver_hints.Hints())
        self.assertEqual([group['id']], [g['id'] for g in groups])

    def test_list_groups_for_user_no_user(self):
        user_id = uuid.uuid4().hex
        self.assertRaises(
            exception.UserNotFound, self.driver.list_groups_for_user,
            user_id, driver_hints.Hints())

    def test_remove_user_from_group(self):
        user = self.create_user()
        group = self.create_group()
        self.driver.add_user_to_group(user['id'], group['id'])

        self.driver.remove_user_from_group(user['id'], group['id'])

        self.assertRaises(exception.NotFound, self.driver.check_user_in_group,
                          user['id'], group['id'])

    def test_remove_user_from_group_not_in_group(self):
        user = self.create_user()
        group = self.create_group()

        # FIXME(blk-u): ldap is returning UserNotFound rather than NotFound,
        # fix this.
        self.assertRaises(
            exception.NotFound, self.driver.remove_user_from_group, user['id'],
            group['id'])

    def test_remove_user_from_group_no_user(self):
        group = self.create_group()

        user_id = uuid.uuid4().hex
        self.assertRaises(
            exception.UserNotFound, self.driver.remove_user_from_group,
            user_id, group['id'])

    def test_remove_user_from_group_no_group(self):
        user = self.create_user()

        group_id = uuid.uuid4().hex
        self.assertRaises(
            exception.GroupNotFound, self.driver.remove_user_from_group,
            user['id'], group_id)

    def test_authenticate(self):
        password = uuid.uuid4().hex
        user = self.create_user(password=password)

        actual_user = self.driver.authenticate(user['id'], password)
        self.assertEqual(user['id'], actual_user['id'])

    def test_authenticate_wrong_password(self):
        user = self.create_user(password=uuid.uuid4().hex)

        password = uuid.uuid4().hex
        self.assertRaises(AssertionError, self.driver.authenticate, user['id'],
                          password)

    def test_authenticate_no_user(self):
        user_id = uuid.uuid4().hex
        password = uuid.uuid4().hex
        self.assertRaises(AssertionError, self.driver.authenticate, user_id,
                          password)
