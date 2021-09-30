# Copyright 2012 OpenStack Foundation
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

import uuid

from testtools import matchers

from keystone.common import driver_hints
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import filtering


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class IdentityTests(object):

    def _get_domain_fixture(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        return domain

    def _set_domain_scope(self, domain_id):
        # We only provide a domain scope if we have multiple drivers
        if CONF.identity.domain_specific_drivers_enabled:
            return domain_id

    def test_authenticate_bad_user(self):
        with self.make_request():
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=uuid.uuid4().hex,
                              password=self.user_foo['password'])

    def test_authenticate_bad_password(self):
        with self.make_request():
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=self.user_foo['id'],
                              password=uuid.uuid4().hex)

    def test_authenticate(self):
        with self.make_request():
            user_ref = PROVIDERS.identity_api.authenticate(
                user_id=self.user_sna['id'],
                password=self.user_sna['password'])
            # NOTE(termie): the password field is left in user_sna to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_sna.pop('password')
        self.user_sna['enabled'] = True
        self.assertUserDictEqual(self.user_sna, user_ref)

    def test_authenticate_and_get_roles_no_metadata(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        # Remove user id. It is ignored by create_user() and will break the
        # subset test below.
        del user['id']

        new_user = PROVIDERS.identity_api.create_user(user)

        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)

        PROVIDERS.assignment_api.add_role_to_user_and_project(
            new_user['id'], self.project_baz['id'], role_member['id']
        )
        with self.make_request():
            user_ref = PROVIDERS.identity_api.authenticate(
                user_id=new_user['id'],
                password=user['password'])
        self.assertNotIn('password', user_ref)
        # NOTE(termie): the password field is left in user_sna to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        user.pop('password')
        self.assertLessEqual(user.items(), user_ref.items())
        role_list = PROVIDERS.assignment_api.get_roles_for_user_and_project(
            new_user['id'], self.project_baz['id'])
        self.assertEqual(1, len(role_list))
        self.assertIn(role_member['id'], role_list)

    def test_authenticate_if_no_password_set(self):
        id_ = uuid.uuid4().hex
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        PROVIDERS.identity_api.create_user(user)

        with self.make_request():
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=id_,
                              password='password')

    def test_create_unicode_user_name(self):
        unicode_name = u'name \u540d\u5b57'
        user = unit.new_user_ref(name=unicode_name,
                                 domain_id=CONF.identity.default_domain_id)
        ref = PROVIDERS.identity_api.create_user(user)
        self.assertEqual(unicode_name, ref['name'])

    def test_get_user(self):
        user_ref = PROVIDERS.identity_api.get_user(self.user_foo['id'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        # NOTE(edmondsw): check that options is set, even if it's just an
        # empty dict, because otherwise auth will blow up for whatever
        # case misses this.
        self.assertIn('options', user_ref)
        self.assertDictEqual(self.user_foo, user_ref)

    def test_get_user_returns_required_attributes(self):
        user_ref = PROVIDERS.identity_api.get_user(self.user_foo['id'])
        self.assertIn('id', user_ref)
        self.assertIn('name', user_ref)
        self.assertIn('enabled', user_ref)
        self.assertIn('password_expires_at', user_ref)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        PROVIDERS.identity_api.create_user(user)
        ref = PROVIDERS.identity_api.get_user_by_name(
            user['name'], user['domain_id']
        )
        # cache the result.
        PROVIDERS.identity_api.get_user(ref['id'])
        # delete bypassing identity api
        domain_id, driver, entity_id = (
            PROVIDERS.identity_api._get_domain_driver_and_entity_id(ref['id']))
        driver.delete_user(entity_id)

        self.assertDictEqual(ref, PROVIDERS.identity_api.get_user(ref['id']))
        PROVIDERS.identity_api.get_user.invalidate(
            PROVIDERS.identity_api, ref['id']
        )
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user, ref['id'])
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        ref = PROVIDERS.identity_api.get_user_by_name(
            user['name'], user['domain_id']
        )
        user['description'] = uuid.uuid4().hex
        # cache the result.
        PROVIDERS.identity_api.get_user(ref['id'])
        # update using identity api and get back updated user.
        user_updated = PROVIDERS.identity_api.update_user(ref['id'], user)
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user(ref['id']).items(),
            user_updated.items()
        )
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user_by_name(
                ref['name'], ref['domain_id']).items(),
            user_updated.items()
        )

    def test_get_user_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user,
                          uuid.uuid4().hex)

    def test_get_user_by_name(self):
        user_ref = PROVIDERS.identity_api.get_user_by_name(
            self.user_foo['name'], CONF.identity.default_domain_id)
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(self.user_foo, user_ref)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user_by_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        PROVIDERS.identity_api.create_user(user)
        ref = PROVIDERS.identity_api.get_user_by_name(
            user['name'], user['domain_id']
        )
        # delete bypassing the identity api.
        domain_id, driver, entity_id = (
            PROVIDERS.identity_api._get_domain_driver_and_entity_id(ref['id']))
        driver.delete_user(entity_id)

        self.assertDictEqual(ref, PROVIDERS.identity_api.get_user_by_name(
            user['name'], CONF.identity.default_domain_id))
        PROVIDERS.identity_api.get_user_by_name.invalidate(
            PROVIDERS.identity_api,
            user['name'],
            CONF.identity.default_domain_id
        )
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user_by_name,
                          user['name'], CONF.identity.default_domain_id)
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        ref = PROVIDERS.identity_api.get_user_by_name(
            user['name'], user['domain_id']
        )
        user['description'] = uuid.uuid4().hex
        user_updated = PROVIDERS.identity_api.update_user(ref['id'], user)
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user(ref['id']).items(),
            user_updated.items()
        )
        self.assertLessEqual(
            PROVIDERS.identity_api.get_user_by_name(
                ref['name'],
                ref['domain_id']
            ).items(),
            user_updated.items()
        )

    def test_get_user_by_name_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    def test_create_duplicate_user_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        self.assertRaises(exception.Conflict,
                          PROVIDERS.identity_api.create_user,
                          user)

    def test_create_duplicate_user_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        user1 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user2 = unit.new_user_ref(name=user1['name'],
                                  domain_id=new_domain['id'])

        PROVIDERS.identity_api.create_user(user1)
        PROVIDERS.identity_api.create_user(user2)

    def test_move_user_between_domains(self):
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        user = unit.new_user_ref(domain_id=domain1['id'])
        user = PROVIDERS.identity_api.create_user(user)
        user['domain_id'] = domain2['id']
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.identity_api.update_user, user['id'], user)

    def test_rename_duplicate_user_name_fails(self):
        user1 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user2 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        PROVIDERS.identity_api.create_user(user1)
        user2 = PROVIDERS.identity_api.create_user(user2)
        user2['name'] = user1['name']
        self.assertRaises(exception.Conflict,
                          PROVIDERS.identity_api.update_user,
                          user2['id'],
                          user2)

    def test_update_user_id_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        original_id = user['id']
        user['id'] = 'fake2'
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.identity_api.update_user,
                          original_id,
                          user)
        user_ref = PROVIDERS.identity_api.get_user(original_id)
        self.assertEqual(original_id, user_ref['id'])
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user,
                          'fake2')

    def test_delete_user_with_group_project_domain_links(self):
        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], project_id=project1['id'], role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user1['id'], domain_id=domain1['id'], role_id=role1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user1['id'], group_id=group1['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        PROVIDERS.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        PROVIDERS.identity_api.delete_user(user1['id'])
        self.assertRaises(exception.NotFound,
                          PROVIDERS.identity_api.check_user_in_group,
                          user1['id'],
                          group1['id'])

    def test_delete_group_with_user_project_domain_links(self):
        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = PROVIDERS.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)

        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], project_id=project1['id'],
            role_id=role1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=domain1['id'], role_id=role1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user_id=user1['id'], group_id=group1['id']
        )
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = PROVIDERS.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        PROVIDERS.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        PROVIDERS.identity_api.delete_group(group1['id'])
        PROVIDERS.identity_api.get_user(user1['id'])

    def test_update_user_returns_not_found(self):
        user_id = uuid.uuid4().hex
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.update_user,
                          user_id,
                          {'id': user_id,
                           'domain_id': CONF.identity.default_domain_id})

    def test_delete_user_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.delete_user,
                          uuid.uuid4().hex)

    def test_create_user_with_long_password(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 password='a' * 2000)
        # success create a user with long password
        PROVIDERS.identity_api.create_user(user)

    def test_create_user_missed_password(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        PROVIDERS.identity_api.get_user(user['id'])
        # Make sure  the user is not allowed to login
        # with a password that  is empty string or None
        with self.make_request():
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password='')
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password=None)

    def test_create_user_none_password(self):
        user = unit.new_user_ref(password=None,
                                 domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        PROVIDERS.identity_api.get_user(user['id'])
        # Make sure  the user is not allowed to login
        # with a password that  is empty string or None
        with self.make_request():
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password='')
            self.assertRaises(AssertionError,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user['id'],
                              password=None)

    def test_list_users(self):
        users = PROVIDERS.identity_api.list_users(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(len(default_fixtures.USERS), len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['name'])['id']
                                for user in default_fixtures.USERS)
        for user_ref in users:
            self.assertNotIn('password', user_ref)
        self.assertEqual(expected_user_ids, user_ids)

    def _build_hints(self, hints, filters, fed_dict):
        for key in filters:
            hints.add_filter(key,
                             fed_dict[key],
                             comparator='equals')
        return hints

    def _build_fed_resource(self):
        # create one test mapping, two idps and two protocols for federation
        # test.
        new_mapping = unit.new_mapping_ref()
        PROVIDERS.federation_api.create_mapping(new_mapping['id'], new_mapping)
        for idp_id, protocol_id in [('ORG_IDP', 'saml2'),
                                    ('myidp', 'mapped')]:
            new_idp = unit.new_identity_provider_ref(idp_id=idp_id,
                                                     domain_id='default')
            new_protocol = unit.new_protocol_ref(protocol_id=protocol_id,
                                                 idp_id=idp_id,
                                                 mapping_id=new_mapping['id'])

            PROVIDERS.federation_api.create_idp(new_idp['id'], new_idp)
            PROVIDERS.federation_api.create_protocol(new_idp['id'],
                                                     new_protocol['id'],
                                                     new_protocol)

    def _test_list_users_with_attribute(self, filters, fed_dict):
        self._build_fed_resource()
        domain = self._get_domain_fixture()
        # Call list_users while no match exists for the federated user
        hints = driver_hints.Hints()
        hints = self._build_hints(hints, filters, fed_dict)
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual(0, len(users))

        # list_users with a new relational user and federated user
        hints = self._build_hints(hints, filters, fed_dict)
        PROVIDERS.shadow_users_api.create_federated_user(
            domain['id'], fed_dict
        )
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual(1, len(users))

        # create another federated user that shouldnt be matched and ensure
        # that still only one match is found
        hints = self._build_hints(hints, filters, fed_dict)
        fed_dict2 = unit.new_federated_user_ref()
        fed_dict2['idp_id'] = 'myidp'
        fed_dict2['protocol_id'] = 'mapped'
        PROVIDERS.shadow_users_api.create_federated_user(
            domain['id'], fed_dict2
        )
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual(1, len(users))

        # create another federated user that should also be matched and ensure
        # that there are now two matches in the users list. Unless there is a
        # unique id in the filter since unique_ids must be unique and would
        # therefore cause a duplicate error.
        hints = self._build_hints(hints, filters, fed_dict)
        if not any('unique_id' in x['name'] for x in hints.filters):
            hints = self._build_hints(hints, filters, fed_dict)
            fed_dict3 = unit.new_federated_user_ref()
            # check which filters are here and create another match
            for filters_ in hints.filters:
                if filters_['name'] == 'idp_id':
                    fed_dict3['idp_id'] = fed_dict['idp_id']
                elif filters_['name'] == 'protocol_id':
                    fed_dict3['protocol_id'] = fed_dict['protocol_id']
            PROVIDERS.shadow_users_api.create_federated_user(
                domain['id'], fed_dict3
            )
            users = PROVIDERS.identity_api.list_users(hints=hints)
            self.assertEqual(2, len(users))

    def test_list_users_with_unique_id(self):
        federated_dict = unit.new_federated_user_ref()
        filters = ['unique_id']
        self._test_list_users_with_attribute(filters, federated_dict)

    def test_list_users_with_idp_id(self):
        federated_dict = unit.new_federated_user_ref()
        filters = ['idp_id']
        self._test_list_users_with_attribute(filters, federated_dict)

    def test_list_users_with_protocol_id(self):
        federated_dict = unit.new_federated_user_ref()
        filters = ['protocol_id']
        self._test_list_users_with_attribute(filters, federated_dict)

    def test_list_users_with_unique_id_and_idp_id(self):
        federated_dict = unit.new_federated_user_ref()
        filters = ['unique_id', 'idp_id']
        self._test_list_users_with_attribute(filters, federated_dict)

    def test_list_users_with_unique_id_and_protocol_id(self):
        federated_dict = unit.new_federated_user_ref()
        filters = ['unique_id', 'protocol_id']
        self._test_list_users_with_attribute(filters, federated_dict)

    def test_list_users_with_idp_id_protocol_id(self):
        federated_dict = unit.new_federated_user_ref()
        filters = ['idp_id', 'protocol_id']
        self._test_list_users_with_attribute(filters, federated_dict)

    def test_list_users_with_all_federated_attributes(self):
        federated_dict = unit.new_federated_user_ref()
        filters = ['unique_id', 'idp_id', 'protocol_id']
        self._test_list_users_with_attribute(filters, federated_dict)

    def test_list_users_with_name(self):
        self._build_fed_resource()
        federated_dict_1 = unit.new_federated_user_ref(
            display_name='test1@federation.org')
        federated_dict_2 = unit.new_federated_user_ref(
            display_name='test2@federation.org')
        domain = self._get_domain_fixture()

        hints = driver_hints.Hints()
        hints.add_filter('name', 'test1@federation.org')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(0, len(users))

        self.shadow_users_api.create_federated_user(domain['id'],
                                                    federated_dict_1)
        self.shadow_users_api.create_federated_user(domain['id'],
                                                    federated_dict_2)
        hints = driver_hints.Hints()
        hints.add_filter('name', 'test1@federation.org')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(1, len(users))

        hints = driver_hints.Hints()
        hints.add_filter('name', 'test1@federation.org')
        hints.add_filter('idp_id', 'ORG_IDP')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(1, len(users))

    def test_list_groups(self):
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = PROVIDERS.identity_api.create_group(group2)
        groups = PROVIDERS.identity_api.list_groups(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(2, len(groups))
        group_ids = []
        for group in groups:
            group_ids.append(group.get('id'))
        self.assertIn(group1['id'], group_ids)
        self.assertIn(group2['id'], group_ids)

    def test_create_user_doesnt_modify_passed_in_dict(self):
        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        original_user = new_user.copy()
        PROVIDERS.identity_api.create_user(new_user)
        self.assertDictEqual(original_user, new_user)

    def test_update_user_enable(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

        user['enabled'] = False
        PROVIDERS.identity_api.update_user(user['id'], user)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        # If not present, enabled field should not be updated
        del user['enabled']
        PROVIDERS.identity_api.update_user(user['id'], user)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        self.assertFalse(user_ref['enabled'])

        user['enabled'] = True
        PROVIDERS.identity_api.update_user(user['id'], user)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        del user['enabled']
        PROVIDERS.identity_api.update_user(user['id'], user)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

    def test_update_user_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        self.assertEqual(user['name'], user_ref['name'])

        changed_name = user_ref['name'] + '_changed'
        user_ref['name'] = changed_name
        updated_user = PROVIDERS.identity_api.update_user(
            user_ref['id'], user_ref
        )

        # NOTE(dstanek): the SQL backend adds an 'extra' field containing a
        #                dictionary of the extra fields in addition to the
        #                fields in the object. For the details see:
        #                SqlIdentity.test_update_project_returns_extra
        updated_user.pop('extra', None)

        self.assertDictEqual(user_ref, updated_user)

        user_ref = PROVIDERS.identity_api.get_user(user_ref['id'])
        self.assertEqual(changed_name, user_ref['name'])

    def test_add_user_to_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )
        groups = PROVIDERS.identity_api.list_groups_for_user(new_user['id'])

        found = False
        for x in groups:
            if (x['id'] == new_group['id']):
                found = True
        self.assertTrue(found)

    def test_add_user_to_group_returns_not_found(self):
        domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.add_user_to_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.add_user_to_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.NotFound,
                          PROVIDERS.identity_api.add_user_to_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_check_user_in_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )
        PROVIDERS.identity_api.check_user_in_group(
            new_user['id'], new_group['id']
        )

    def test_check_user_not_in_group(self):
        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = PROVIDERS.identity_api.create_group(new_group)

        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_user = PROVIDERS.identity_api.create_user(new_user)

        self.assertRaises(exception.NotFound,
                          PROVIDERS.identity_api.check_user_in_group,
                          new_user['id'],
                          new_group['id'])

    def test_check_user_in_group_returns_not_found(self):
        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_user = PROVIDERS.identity_api.create_user(new_user)

        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = PROVIDERS.identity_api.create_group(new_group)

        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.check_user_in_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.check_user_in_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.NotFound,
                          PROVIDERS.identity_api.check_user_in_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_list_users_in_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        # Make sure we get an empty list back on a new group, not an error.
        user_refs = PROVIDERS.identity_api.list_users_in_group(new_group['id'])
        self.assertEqual([], user_refs)
        # Make sure we get the correct users back once they have been added
        # to the group.
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )
        user_refs = PROVIDERS.identity_api.list_users_in_group(new_group['id'])
        found = False
        for x in user_refs:
            if (x['id'] == new_user['id']):
                found = True
            self.assertNotIn('password', x)
        self.assertTrue(found)

    def test_list_users_in_group_returns_not_found(self):
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.list_users_in_group,
                          uuid.uuid4().hex)

    def test_list_groups_for_user(self):
        domain = self._get_domain_fixture()
        test_groups = []
        test_users = []
        GROUP_COUNT = 3
        USER_COUNT = 2

        for x in range(0, USER_COUNT):
            new_user = unit.new_user_ref(domain_id=domain['id'])
            new_user = PROVIDERS.identity_api.create_user(new_user)
            test_users.append(new_user)
        positive_user = test_users[0]
        negative_user = test_users[1]

        for x in range(0, USER_COUNT):
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                test_users[x]['id'])
            self.assertEqual(0, len(group_refs))

        for x in range(0, GROUP_COUNT):
            before_count = x
            after_count = x + 1
            new_group = unit.new_group_ref(domain_id=domain['id'])
            new_group = PROVIDERS.identity_api.create_group(new_group)
            test_groups.append(new_group)

            # add the user to the group and ensure that the
            # group count increases by one for each
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(before_count, len(group_refs))
            PROVIDERS.identity_api.add_user_to_group(
                positive_user['id'],
                new_group['id'])
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(after_count, len(group_refs))

            # Make sure the group count for the unrelated user did not change
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEqual(0, len(group_refs))

    def test_remove_user_from_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        PROVIDERS.identity_api.add_user_to_group(
            new_user['id'], new_group['id']
        )
        groups = PROVIDERS.identity_api.list_groups_for_user(new_user['id'])
        self.assertIn(new_group['id'], [x['id'] for x in groups])
        PROVIDERS.identity_api.remove_user_from_group(
            new_user['id'], new_group['id']
        )
        groups = PROVIDERS.identity_api.list_groups_for_user(new_user['id'])
        self.assertNotIn(new_group['id'], [x['id'] for x in groups])

    def test_remove_user_from_group_returns_not_found(self):
        domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = PROVIDERS.identity_api.create_user(new_user)
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.remove_user_from_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.NotFound,
                          PROVIDERS.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_group_crud(self):
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        group = unit.new_group_ref(domain_id=domain['id'])
        group = PROVIDERS.identity_api.create_group(group)
        group_ref = PROVIDERS.identity_api.get_group(group['id'])
        self.assertLessEqual(group.items(), group_ref.items())

        group['name'] = uuid.uuid4().hex
        PROVIDERS.identity_api.update_group(group['id'], group)
        group_ref = PROVIDERS.identity_api.get_group(group['id'])
        self.assertLessEqual(group.items(), group_ref.items())

        PROVIDERS.identity_api.delete_group(group['id'])
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.get_group,
                          group['id'])

    def test_create_group_name_with_trailing_whitespace(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_name = group['name'] = (group['name'] + '    ')
        group_returned = PROVIDERS.identity_api.create_group(group)
        self.assertEqual(group_returned['name'], group_name.strip())

    def test_update_group_name_with_trailing_whitespace(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_create = PROVIDERS.identity_api.create_group(group)
        group_name = group['name'] = (group['name'] + '    ')
        group_update = PROVIDERS.identity_api.update_group(
            group_create['id'], group
        )
        self.assertEqual(group_update['id'], group_create['id'])
        self.assertEqual(group_update['name'], group_name.strip())

    def test_get_group_by_name(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_name = group['name']
        group = PROVIDERS.identity_api.create_group(group)
        spoiler = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        PROVIDERS.identity_api.create_group(spoiler)

        group_ref = PROVIDERS.identity_api.get_group_by_name(
            group_name, CONF.identity.default_domain_id)
        self.assertDictEqual(group, group_ref)

    def test_get_group_by_name_returns_not_found(self):
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.get_group_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_group_crud(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        # cache the result
        group_ref = PROVIDERS.identity_api.get_group(group['id'])
        # delete the group bypassing identity api.
        domain_id, driver, entity_id = (
            PROVIDERS.identity_api._get_domain_driver_and_entity_id(
                group['id']
            )
        )
        driver.delete_group(entity_id)

        self.assertEqual(
            group_ref, PROVIDERS.identity_api.get_group(group['id'])
        )
        PROVIDERS.identity_api.get_group.invalidate(
            PROVIDERS.identity_api, group['id']
        )
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.get_group, group['id'])

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)
        # cache the result
        PROVIDERS.identity_api.get_group(group['id'])
        group['name'] = uuid.uuid4().hex
        group_ref = PROVIDERS.identity_api.update_group(group['id'], group)
        # after updating through identity api, get updated group
        self.assertLessEqual(
            PROVIDERS.identity_api.get_group(group['id']).items(),
            group_ref.items()
        )

    def test_create_duplicate_group_name_fails(self):
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id,
                                    name=group1['name'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        self.assertRaises(exception.Conflict,
                          PROVIDERS.identity_api.create_group,
                          group2)

    def test_create_duplicate_group_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(new_domain['id'], new_domain)
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=new_domain['id'],
                                    name=group1['name'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = PROVIDERS.identity_api.create_group(group2)

    def test_move_group_between_domains(self):
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        group = unit.new_group_ref(domain_id=domain1['id'])
        group = PROVIDERS.identity_api.create_group(group)
        group['domain_id'] = domain2['id']
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.identity_api.update_group,
                          group['id'], group)

    def test_user_crud(self):
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        del user_dict['id']
        user = PROVIDERS.identity_api.create_user(user_dict)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertLessEqual(user_dict.items(), user_ref_dict.items())

        user_dict['password'] = uuid.uuid4().hex
        PROVIDERS.identity_api.update_user(user['id'], user_dict)
        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertLessEqual(user_dict.items(), user_ref_dict.items())

        PROVIDERS.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user,
                          user['id'])

    def test_arbitrary_attributes_are_returned_from_create_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        user = PROVIDERS.identity_api.create_user(user_data)

        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_arbitrary_attributes_are_returned_from_get_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        user_data = PROVIDERS.identity_api.create_user(user_data)

        user = PROVIDERS.identity_api.get_user(user_data['id'])
        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_new_arbitrary_attributes_are_returned_from_update_user(self):
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)

        user = PROVIDERS.identity_api.create_user(user_data)
        attr_value = uuid.uuid4().hex
        user['arbitrary_attr'] = attr_value
        updated_user = PROVIDERS.identity_api.update_user(user['id'], user)

        self.assertEqual(attr_value, updated_user['arbitrary_attr'])

    def test_updated_arbitrary_attributes_are_returned_from_update_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        new_attr_value = uuid.uuid4().hex
        user = PROVIDERS.identity_api.create_user(user_data)
        user['arbitrary_attr'] = new_attr_value
        updated_user = PROVIDERS.identity_api.update_user(user['id'], user)

        self.assertEqual(new_attr_value, updated_user['arbitrary_attr'])

    def test_user_update_and_user_get_return_same_response(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user = PROVIDERS.identity_api.create_user(user)

        updated_user = {'enabled': False}
        updated_user_ref = PROVIDERS.identity_api.update_user(
            user['id'], updated_user)

        # SQL backend adds 'extra' field
        updated_user_ref.pop('extra', None)

        self.assertIs(False, updated_user_ref['enabled'])

        user_ref = PROVIDERS.identity_api.get_user(user['id'])
        self.assertDictEqual(updated_user_ref, user_ref)

    @unit.skip_if_no_multiple_domains_support
    def test_list_domains_filtered_and_limited(self):
        # The test is designed for multiple domains only
        def create_domains(domain_count, domain_name_prefix):
            for _ in range(domain_count):
                domain_name = '%s-%s' % (domain_name_prefix, uuid.uuid4().hex)
                domain = unit.new_domain_ref(name=domain_name)
                self.domain_list[domain_name] = \
                    PROVIDERS.resource_api.create_domain(domain['id'], domain)

        def clean_up_domains():
            for _, domain in self.domain_list.items():
                domain['enabled'] = False
                PROVIDERS.resource_api.update_domain(domain['id'], domain)
                PROVIDERS.resource_api.delete_domain(domain['id'])

        self.domain_list = {}
        create_domains(2, 'domaingroup1')
        create_domains(3, 'domaingroup2')

        self.addCleanup(clean_up_domains)
        unfiltered_domains = PROVIDERS.resource_api.list_domains()

        # Should get back just 4 entities
        self.config_fixture.config(list_limit=4)
        hints = driver_hints.Hints()
        entities = PROVIDERS.resource_api.list_domains(hints=hints)
        self.assertThat(entities, matchers.HasLength(hints.limit['limit']))
        self.assertTrue(hints.limit['truncated'])

        # Get one exact item from the list
        hints = driver_hints.Hints()
        hints.add_filter('name', unfiltered_domains[3]['name'])
        entities = PROVIDERS.resource_api.list_domains(hints=hints)
        self.assertThat(entities, matchers.HasLength(1))
        self.assertEqual(entities[0], unfiltered_domains[3])

        # Get 2 entries
        hints = driver_hints.Hints()
        hints.add_filter('name', 'domaingroup1', comparator='startswith')
        entities = PROVIDERS.resource_api.list_domains(hints=hints)
        self.assertThat(entities, matchers.HasLength(2))
        self.assertThat(entities[0]['name'],
                        matchers.StartsWith('domaingroup1'))
        self.assertThat(entities[1]['name'],
                        matchers.StartsWith('domaingroup1'))

    @unit.skip_if_no_multiple_domains_support
    def test_list_limit_for_domains(self):
        def create_domains(count):
            for _ in range(count):
                domain = unit.new_domain_ref()
                self.domain_list.append(
                    PROVIDERS.resource_api.create_domain(domain['id'], domain))

        def clean_up_domains():
            for domain in self.domain_list:
                PROVIDERS.resource_api.update_domain(
                    domain['id'], {'enabled': False})
                PROVIDERS.resource_api.delete_domain(domain['id'])

        self.domain_list = []
        create_domains(6)
        self.addCleanup(clean_up_domains)

        for x in range(1, 7):
            self.config_fixture.config(group='resource', list_limit=x)
            hints = driver_hints.Hints()
            entities = PROVIDERS.resource_api.list_domains(hints=hints)
            self.assertThat(entities, matchers.HasLength(hints.limit['limit']))


class FilterTests(filtering.FilterTests):
    def test_list_entities_filtered(self):
        for entity in ['user', 'group', 'project']:
            # Create 20 entities
            entity_list = self._create_test_data(entity, 20)

            # Try filtering to get one an exact item out of the list
            hints = driver_hints.Hints()
            hints.add_filter('name', entity_list[10]['name'])
            entities = self._list_entities(entity)(hints=hints)
            self.assertEqual(1, len(entities))
            self.assertEqual(entity_list[10]['id'], entities[0]['id'])
            # Check the driver has removed the filter from the list hints
            self.assertFalse(hints.get_exact_filter_by_name('name'))
            self._delete_test_data(entity, entity_list)

    def test_list_users_inexact_filtered(self):
        # Create 20 users, some with specific names. We set the names at create
        # time (rather than updating them), since the LDAP driver does not
        # support name updates.
        user_name_data = {
            # user index: name for user
            5: 'The',
            6: 'The Ministry',
            7: 'The Ministry of',
            8: 'The Ministry of Silly',
            9: 'The Ministry of Silly Walks',
            # ...and one for useful case insensitivity testing
            10: 'The ministry of silly walks OF'
        }
        user_list = self._create_test_data(
            'user', 20, domain_id=CONF.identity.default_domain_id,
            name_dict=user_name_data)

        hints = driver_hints.Hints()
        hints.add_filter('name', 'ministry', comparator='contains')
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual(5, len(users))
        self._match_with_list(users, user_list,
                              list_start=6, list_end=11)
        # TODO(henry-nash) Check inexact filter has been removed.

        hints = driver_hints.Hints()
        hints.add_filter('name', 'The', comparator='startswith')
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual(6, len(users))
        self._match_with_list(users, user_list,
                              list_start=5, list_end=11)
        # TODO(henry-nash) Check inexact filter has been removed.

        hints = driver_hints.Hints()
        hints.add_filter('name', 'of', comparator='endswith')
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual(2, len(users))
        # We can't assume we will get back the users in any particular order
        self.assertIn(user_list[7]['id'], [users[0]['id'], users[1]['id']])
        self.assertIn(user_list[10]['id'], [users[0]['id'], users[1]['id']])
        # TODO(henry-nash) Check inexact filter has been removed.

        # TODO(henry-nash): Add some case sensitive tests.  However,
        # these would be hard to validate currently, since:
        #
        # For SQL, the issue is that MySQL 0.7, by default, is installed in
        # case insensitive mode (which is what is run by default for our
        # SQL backend tests).  For production deployments. OpenStack
        # assumes a case sensitive database.  For these tests, therefore, we
        # need to be able to check the sensitivity of the database so as to
        # know whether to run case sensitive tests here.
        #
        # For LDAP/AD, although dependent on the schema being used, attributes
        # are typically configured to be case aware, but not case sensitive.

        self._delete_test_data('user', user_list)

    def _groups_for_user_data(self):
        number_of_groups = 10
        group_name_data = {
            # entity index: name for entity
            5: 'The',
            6: 'The Ministry',
            9: 'The Ministry of Silly Walks',
        }
        group_list = self._create_test_data(
            'group', number_of_groups,
            domain_id=CONF.identity.default_domain_id,
            name_dict=group_name_data)
        user_list = self._create_test_data('user', 2)

        for group in range(7):
            # Create membership, including with two out of the three groups
            # with well know names
            PROVIDERS.identity_api.add_user_to_group(
                user_list[0]['id'], group_list[group]['id']
            )
        # ...and some spoiler memberships
        for group in range(7, number_of_groups):
            PROVIDERS.identity_api.add_user_to_group(
                user_list[1]['id'], group_list[group]['id']
            )

        return group_list, user_list

    def test_groups_for_user_inexact_filtered(self):
        """Test use of filtering doesn't break groups_for_user listing.

        Some backends may use filtering to achieve the list of groups for a
        user, so test that it can combine a second filter.

        Test Plan:

        - Create 10 groups, some with names we can filter on
        - Create 2 users
        - Assign 1 of those users to most of the groups, including some of the
          well known named ones
        - Assign the other user to other groups as spoilers
        - Ensure that when we list groups for users with a filter on the group
          name, both restrictions have been enforced on what is returned.

        """
        group_list, user_list = self._groups_for_user_data()

        hints = driver_hints.Hints()
        hints.add_filter('name', 'Ministry', comparator='contains')
        groups = PROVIDERS.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back one group, since of the two that contain
        # 'Ministry' the user only belongs to one.
        self.assertThat(len(groups), matchers.Equals(1))
        self.assertEqual(group_list[6]['id'], groups[0]['id'])

        hints = driver_hints.Hints()
        hints.add_filter('name', 'The', comparator='startswith')
        groups = PROVIDERS.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back 2 out of the 3 groups that start with 'The'
        # hence showing that both "filters" have been applied
        self.assertThat(len(groups), matchers.Equals(2))
        self.assertIn(group_list[5]['id'], [groups[0]['id'], groups[1]['id']])
        self.assertIn(group_list[6]['id'], [groups[0]['id'], groups[1]['id']])

        hints.add_filter('name', 'The', comparator='endswith')
        groups = PROVIDERS.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back one group since it is the only one that
        # ends with 'The'
        self.assertThat(len(groups), matchers.Equals(1))
        self.assertEqual(group_list[5]['id'], groups[0]['id'])

        self._delete_test_data('user', user_list)
        self._delete_test_data('group', group_list)

    def test_groups_for_user_exact_filtered(self):
        """Test exact filters doesn't break groups_for_user listing."""
        group_list, user_list = self._groups_for_user_data()
        hints = driver_hints.Hints()
        hints.add_filter('name', 'The Ministry', comparator='equals')
        groups = PROVIDERS.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back 1 out of the 3 groups with name 'The
        # Ministry' hence showing that both "filters" have been applied.
        self.assertEqual(1, len(groups))
        self.assertEqual(group_list[6]['id'], groups[0]['id'])
        self._delete_test_data('user', user_list)
        self._delete_test_data('group', group_list)

    def _get_user_name_field_size(self):
        """Return the size of the user name field for the backend.

        Subclasses can override this method to indicate that the user name
        field is limited in length. The user name is the field used in the test
        that validates that a filter value works even if it's longer than a
        field.

        If the backend doesn't limit the value length then return None.

        """
        return None

    def test_filter_value_wider_than_field(self):
        # If a filter value is given that's larger than the field in the
        # backend then no values are returned.

        user_name_field_size = self._get_user_name_field_size()

        if user_name_field_size is None:
            # The backend doesn't limit the size of the user name, so pass this
            # test.
            return

        # Create some users just to make sure would return something if the
        # filter was ignored.
        self._create_test_data('user', 2)

        hints = driver_hints.Hints()
        value = 'A' * (user_name_field_size + 1)
        hints.add_filter('name', value)
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual([], users)

    def _list_users_in_group_data(self):
        number_of_users = 10
        user_name_data = {
            1: 'Arthur Conan Doyle',
            3: 'Arthur Rimbaud',
            9: 'Arthur Schopenhauer',
        }
        user_list = self._create_test_data(
            'user', number_of_users,
            domain_id=CONF.identity.default_domain_id,
            name_dict=user_name_data)
        group = self._create_one_entity(
            'group', CONF.identity.default_domain_id, 'Great Writers')
        for i in range(7):
            PROVIDERS.identity_api.add_user_to_group(
                user_list[i]['id'], group['id']
            )

        return user_list, group

    def test_list_users_in_group_inexact_filtered(self):
        user_list, group = self._list_users_in_group_data()

        hints = driver_hints.Hints()
        hints.add_filter('name', 'Arthur', comparator='contains')
        users = PROVIDERS.identity_api.list_users_in_group(
            group['id'], hints=hints
        )
        self.assertThat(len(users), matchers.Equals(2))
        self.assertIn(user_list[1]['id'], [users[0]['id'], users[1]['id']])
        self.assertIn(user_list[3]['id'], [users[0]['id'], users[1]['id']])

        hints = driver_hints.Hints()
        hints.add_filter('name', 'Arthur', comparator='startswith')
        users = PROVIDERS.identity_api.list_users_in_group(
            group['id'], hints=hints
        )
        self.assertThat(len(users), matchers.Equals(2))
        self.assertIn(user_list[1]['id'], [users[0]['id'], users[1]['id']])
        self.assertIn(user_list[3]['id'], [users[0]['id'], users[1]['id']])

        hints = driver_hints.Hints()
        hints.add_filter('name', 'Doyle', comparator='endswith')
        users = PROVIDERS.identity_api.list_users_in_group(
            group['id'], hints=hints
        )
        self.assertThat(len(users), matchers.Equals(1))
        self.assertEqual(user_list[1]['id'], users[0]['id'])

        self._delete_test_data('user', user_list)
        self._delete_entity('group')(group['id'])

    def test_list_users_in_group_exact_filtered(self):
        hints = driver_hints.Hints()
        user_list, group = self._list_users_in_group_data()
        hints.add_filter('name', 'Arthur Rimbaud', comparator='equals')
        users = PROVIDERS.identity_api.list_users_in_group(
            group['id'], hints=hints
        )
        self.assertEqual(1, len(users))
        self.assertEqual(user_list[3]['id'], users[0]['id'])
        self._delete_test_data('user', user_list)
        self._delete_entity('group')(group['id'])


class LimitTests(filtering.FilterTests):
    ENTITIES = ['user', 'group', 'project']

    def setUp(self):
        """Setup for Limit Test Cases."""
        self.entity_lists = {}

        for entity in self.ENTITIES:
            # Create 20 entities
            self.entity_lists[entity] = self._create_test_data(entity, 20)
        self.addCleanup(self.clean_up_entities)

    def clean_up_entities(self):
        """Clean up entity test data from Limit Test Cases."""
        for entity in self.ENTITIES:
            self._delete_test_data(entity, self.entity_lists[entity])
        del self.entity_lists

    def _test_list_entity_filtered_and_limited(self, entity):
        self.config_fixture.config(list_limit=10)
        # Should get back just 10 entities
        hints = driver_hints.Hints()
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))
        self.assertTrue(hints.limit['truncated'])

        # Override with driver specific limit
        if entity == 'project':
            self.config_fixture.config(group='resource', list_limit=5)
        else:
            self.config_fixture.config(group='identity', list_limit=5)

        # Should get back just 5 users
        hints = driver_hints.Hints()
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))

        # Finally, let's pretend we want to get the full list of entities,
        # even with the limits set, as part of some internal calculation.
        # Calling the API without a hints list should achieve this, and
        # return at least the 20 entries we created (there may be other
        # entities lying around created by other tests/setup).
        entities = self._list_entities(entity)()
        self.assertGreaterEqual(len(entities), 20)
        self._match_with_list(self.entity_lists[entity], entities)

    def test_list_users_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('user')

    def test_list_groups_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('group')

    def test_list_projects_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('project')
