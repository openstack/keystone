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

import datetime
from unittest import mock
import uuid

import fixtures
import freezegun
import http.client
from oslo_db import exception as oslo_db_exception
from oslo_log import log
from testtools import matchers

from keystone.common import provider_api
from keystone.common import sql
import keystone.conf
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone.identity.backends import base as identity_base
from keystone.identity.backends import resource_options as options
from keystone.identity.backends import sql_model as model
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import mapping_fixtures
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class IdentityTestCase(test_v3.RestfulTestCase):
    """Test users and groups."""

    def setUp(self):
        super(IdentityTestCase, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

        self.group = unit.new_group_ref(domain_id=self.domain_id)
        self.group = PROVIDERS.identity_api.create_group(self.group)
        self.group_id = self.group['id']

        self.credential = unit.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)

        PROVIDERS.credential_api.create_credential(
            self.credential['id'], self.credential
        )

    # user crud tests

    def test_create_user(self):
        """Call ``POST /users``."""
        ref = unit.new_user_ref(domain_id=self.domain_id)
        r = self.post(
            '/users',
            body={'user': ref})
        return self.assertValidUserResponse(r, ref)

    def test_create_user_without_domain(self):
        """Call ``POST /users`` without specifying domain.

        According to the identity-api specification, if you do not
        explicitly specific the domain_id in the entity, it should
        take the domain scope of the token as the domain_id.

        """
        # Create a user with a role on the domain so we can get a
        # domain scoped token
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user = unit.create_user(PROVIDERS.identity_api, domain_id=domain['id'])
        PROVIDERS.assignment_api.create_grant(
            role_id=self.role_id, user_id=user['id'],
            domain_id=domain['id'])

        ref = unit.new_user_ref(domain_id=domain['id'])
        ref_nd = ref.copy()
        ref_nd.pop('domain_id')
        auth = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            domain_id=domain['id'])
        r = self.post('/users', body={'user': ref_nd}, auth=auth)
        self.assertValidUserResponse(r, ref)

        # Now try the same thing without a domain token - which should fail
        ref = unit.new_user_ref(domain_id=domain['id'])
        ref_nd = ref.copy()
        ref_nd.pop('domain_id')
        auth = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])

        # TODO(henry-nash): Due to bug #1283539 we currently automatically
        # use the default domain_id if a domain scoped token is not being
        # used. For now we just check that a deprecation warning has been
        # issued. Change the code below to expect a failure once this bug is
        # fixed.
        with mock.patch(
                'oslo_log.versionutils.report_deprecated_feature') as mock_dep:
            r = self.post('/users', body={'user': ref_nd}, auth=auth)
            self.assertTrue(mock_dep.called)

        ref['domain_id'] = CONF.identity.default_domain_id
        return self.assertValidUserResponse(r, ref)

    def test_create_user_with_admin_token_and_domain(self):
        """Call ``POST /users`` with admin token and domain id."""
        ref = unit.new_user_ref(domain_id=self.domain_id)
        self.post('/users', body={'user': ref}, token=self.get_admin_token(),
                  expected_status=http.client.CREATED)

    def test_user_management_normalized_keys(self):
        """Illustrate the inconsistent handling of hyphens in keys.

        To quote Morgan in bug 1526244:

            the reason this is converted from "domain-id" to "domain_id" is
            because of how we process/normalize data. The way we have to handle
            specific data types for known columns requires avoiding "-" in the
            actual python code since "-" is not valid for attributes in python
            w/o significant use of "getattr" etc.

            In short, historically we handle some things in conversions. The
            use of "extras" has long been a poor design choice that leads to
            odd/strange inconsistent behaviors because of other choices made in
            handling data from within the body. (In many cases we convert from
            "-" to "_" throughout openstack)

        Source: https://bugs.launchpad.net/keystone/+bug/1526244/comments/9

        """
        # Create two domains to work with.
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)

        # We can successfully create a normal user without any surprises.
        user = unit.new_user_ref(domain_id=domain1['id'])
        r = self.post(
            '/users',
            body={'user': user})
        self.assertValidUserResponse(r, user)
        user['id'] = r.json['user']['id']

        # Query strings are not normalized: so we get all users back (like
        # self.user), not just the ones in the specified domain.
        r = self.get(
            '/users?domain-id=%s' % domain1['id'])
        self.assertValidUserListResponse(r, ref=self.user)
        self.assertNotEqual(domain1['id'], self.user['domain_id'])

        # When creating a new user, if we move the 'domain_id' into the
        # 'domain-id' attribute, the server will normalize the request
        # attribute, and effectively "move it back" for us.
        user = unit.new_user_ref(domain_id=domain1['id'])
        user['domain-id'] = user.pop('domain_id')
        r = self.post(
            '/users',
            body={'user': user})
        self.assertNotIn('domain-id', r.json['user'])
        self.assertEqual(domain1['id'], r.json['user']['domain_id'])
        # (move this attribute back so we can use assertValidUserResponse)
        user['domain_id'] = user.pop('domain-id')
        self.assertValidUserResponse(r, user)
        user['id'] = r.json['user']['id']

        # If we try updating the user's 'domain_id' by specifying a
        # 'domain-id', then it'll be stored into extras rather than normalized,
        # and the user's actual 'domain_id' is not affected.
        r = self.patch(
            '/users/%s' % user['id'],
            body={'user': {'domain-id': domain2['id']}})
        self.assertEqual(domain2['id'], r.json['user']['domain-id'])
        self.assertEqual(user['domain_id'], r.json['user']['domain_id'])
        self.assertNotEqual(domain2['id'], user['domain_id'])
        self.assertValidUserResponse(r, user)

    def test_create_user_bad_request(self):
        """Call ``POST /users``."""
        self.post('/users', body={'user': {}},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_user_bad_domain_id(self):
        """Call ``POST /users``."""
        # create user with 'DEFaUlT' domain_id instead if 'default'
        # and verify it fails
        self.post('/users',
                  body={'user': {"name": "baddomain", "domain_id":
                        "DEFaUlT"}},
                  expected_status=http.client.NOT_FOUND)

    def test_list_head_users(self):
        """Call ``GET & HEAD /users``."""
        resource_url = '/users'
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=self.user,
                                         resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

    def test_list_users_with_multiple_backends(self):
        """Call ``GET /users`` when multiple backends is enabled.

        In this scenario, the controller requires a domain to be specified
        either as a filter or by using a domain scoped token.

        """
        self.config_fixture.config(group='identity',
                                   domain_specific_drivers_enabled=True)

        # Create a new domain with a new project and user
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)

        user = unit.create_user(PROVIDERS.identity_api, domain_id=domain['id'])

        # Create both project and domain role grants for the user so we
        # can get both project and domain scoped tokens
        PROVIDERS.assignment_api.create_grant(
            role_id=self.role_id, user_id=user['id'],
            domain_id=domain['id'])
        PROVIDERS.assignment_api.create_grant(
            role_id=self.role_id, user_id=user['id'],
            project_id=project['id'])

        dom_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            domain_id=domain['id'])
        project_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            project_id=project['id'])

        # First try using a domain scoped token
        resource_url = '/users'
        r = self.get(resource_url, auth=dom_auth)
        self.assertValidUserListResponse(r, ref=user,
                                         resource_url=resource_url)

        # Now try using a project scoped token
        resource_url = '/users'
        r = self.get(resource_url, auth=project_auth)
        self.assertValidUserListResponse(r, ref=user,
                                         resource_url=resource_url)

        # Now try with an explicit filter
        resource_url = ('/users?domain_id=%(domain_id)s' %
                        {'domain_id': domain['id']})
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=user,
                                         resource_url=resource_url)

    def test_list_users_no_default_project(self):
        """Call ``GET /users`` making sure no default_project_id."""
        user = unit.new_user_ref(self.domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        resource_url = '/users'
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=user,
                                         resource_url=resource_url)

    def test_get_head_user(self):
        """Call ``GET & HEAD /users/{user_id}``."""
        resource_url = '/users/%(user_id)s' % {
            'user_id': self.user['id']}
        r = self.get(resource_url)
        self.assertValidUserResponse(r, self.user)
        self.head(resource_url, expected_status=http.client.OK)

    def test_get_user_does_not_include_extra_attributes(self):
        """Call ``GET /users/{user_id}`` extra attributes are not included."""
        user = unit.new_user_ref(domain_id=self.domain_id,
                                 project_id=self.project_id)
        user = PROVIDERS.identity_api.create_user(user)
        self.assertNotIn('created_at', user)
        self.assertNotIn('last_active_at', user)

    def test_get_user_includes_required_attributes(self):
        """Call ``GET /users/{user_id}`` required attributes are included."""
        user = unit.new_user_ref(domain_id=self.domain_id,
                                 project_id=self.project_id)
        user = PROVIDERS.identity_api.create_user(user)
        self.assertIn('id', user)
        self.assertIn('name', user)
        self.assertIn('enabled', user)
        self.assertIn('password_expires_at', user)
        r = self.get('/users/%(user_id)s' % {'user_id': user['id']})
        self.assertValidUserResponse(r, user)

    def test_get_user_with_default_project(self):
        """Call ``GET /users/{user_id}`` making sure of default_project_id."""
        user = unit.new_user_ref(domain_id=self.domain_id,
                                 project_id=self.project_id)
        user = PROVIDERS.identity_api.create_user(user)
        r = self.get('/users/%(user_id)s' % {'user_id': user['id']})
        self.assertValidUserResponse(r, user)

    def test_add_user_to_group(self):
        """Call ``PUT /groups/{group_id}/users/{user_id}``."""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

    def test_list_head_groups_for_user(self):
        """Call ``GET & HEAD /users/{user_id}/groups``."""
        user1 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])
        user2 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=self.domain['id'])

        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': user1['id']})

        # Scenarios below are written to test the default policy configuration

        # One should be allowed to list one's own groups
        auth = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'])
        resource_url = ('/users/%(user_id)s/groups' %
                        {'user_id': user1['id']})
        r = self.get(resource_url, auth=auth)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)
        self.head(resource_url, auth=auth, expected_status=http.client.OK)

        # Administrator is allowed to list others' groups
        resource_url = ('/users/%(user_id)s/groups' %
                        {'user_id': user1['id']})
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

        # Ordinary users should not be allowed to list other's groups
        auth = self.build_authentication_request(
            user_id=user2['id'],
            password=user2['password'])
        resource_url = '/users/%(user_id)s/groups' % {
            'user_id': user1['id']}
        self.get(resource_url, auth=auth,
                 expected_status=exception.ForbiddenAction.code)
        self.head(resource_url, auth=auth,
                  expected_status=exception.ForbiddenAction.code)

    def test_check_user_in_group(self):
        """Call ``HEAD /groups/{group_id}/users/{user_id}``."""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})
        self.head('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

    def test_list_head_users_in_group(self):
        """Call ``GET & HEAD /groups/{group_id}/users``."""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})
        resource_url = ('/groups/%(group_id)s/users' %
                        {'group_id': self.group_id})
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=self.user,
                                         resource_url=resource_url)
        self.assertIn('/groups/%(group_id)s/users' % {
            'group_id': self.group_id}, r.result['links']['self'])
        self.head(resource_url, expected_status=http.client.OK)

    def test_remove_user_from_group(self):
        """Call ``DELETE /groups/{group_id}/users/{user_id}``."""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})
        self.delete('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

    def test_update_ephemeral_user(self):
        federated_user_a = model.FederatedUser()
        federated_user_b = model.FederatedUser()
        federated_user_a.idp_id = 'a_idp'
        federated_user_b.idp_id = 'b_idp'
        federated_user_a.display_name = 'federated_a'
        federated_user_b.display_name = 'federated_b'
        federated_users = [federated_user_a, federated_user_b]

        user_a = model.User()
        user_a.federated_users = federated_users

        self.assertEqual(federated_user_a.display_name, user_a.name)
        self.assertIsNone(user_a.password)

        user_a.name = 'new_federated_a'

        self.assertEqual('new_federated_a', user_a.name)
        self.assertIsNone(user_a.local_user)

    def test_update_user(self):
        """Call ``PATCH /users/{user_id}``."""
        user = unit.new_user_ref(domain_id=self.domain_id)
        del user['id']
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body={'user': user})
        self.assertValidUserResponse(r, user)

    def test_admin_password_reset(self):
        # bootstrap a user as admin
        user_ref = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain['id'])

        # auth as user should work before a password change
        old_password_auth = self.build_authentication_request(
            user_id=user_ref['id'],
            password=user_ref['password'])
        r = self.v3_create_token(old_password_auth)
        old_token = r.headers.get('X-Subject-Token')

        # auth as user with a token should work before a password change
        old_token_auth = self.build_authentication_request(token=old_token)
        self.v3_create_token(old_token_auth)

        # administrative password reset
        new_password = uuid.uuid4().hex
        self.patch('/users/%s' % user_ref['id'],
                   body={'user': {'password': new_password}})

        # auth as user with original password should not work after change
        self.v3_create_token(old_password_auth,
                             expected_status=http.client.UNAUTHORIZED)

        # auth as user with an old token should not work after change
        self.v3_create_token(old_token_auth,
                             expected_status=http.client.NOT_FOUND)

        # new password should work
        new_password_auth = self.build_authentication_request(
            user_id=user_ref['id'],
            password=new_password)
        self.v3_create_token(new_password_auth)

    def test_admin_password_reset_with_min_password_age_enabled(self):
        # enable minimum_password_age, this should have no effect on admin
        # password reset
        self.config_fixture.config(group='security_compliance',
                                   minimum_password_age=1)
        # create user
        user_ref = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain['id'])
        # administrative password reset
        new_password = uuid.uuid4().hex
        r = self.patch('/users/%s' % user_ref['id'],
                       body={'user': {'password': new_password}})
        self.assertValidUserResponse(r, user_ref)
        # authenticate with new password
        new_password_auth = self.build_authentication_request(
            user_id=user_ref['id'],
            password=new_password)
        self.v3_create_token(new_password_auth)

    def test_admin_password_reset_with_password_lock(self):
        # create user
        user_ref = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain['id'])
        lock_pw_opt = options.LOCK_PASSWORD_OPT.option_name
        update_user_body = {'user': {'options': {lock_pw_opt: True}}}
        self.patch('/users/%s' % user_ref['id'], body=update_user_body)

        # administrative password reset
        new_password = uuid.uuid4().hex
        r = self.patch('/users/%s' % user_ref['id'],
                       body={'user': {'password': new_password}})
        self.assertValidUserResponse(r, user_ref)
        # authenticate with new password
        new_password_auth = self.build_authentication_request(
            user_id=user_ref['id'],
            password=new_password)
        self.v3_create_token(new_password_auth)

    def test_update_user_domain_id(self):
        """Call ``PATCH /users/{user_id}`` with domain_id.

        A user's `domain_id` is immutable. Ensure that any attempts to update
        the `domain_id` of a user fails.
        """
        user = unit.new_user_ref(domain_id=self.domain['id'])
        user = PROVIDERS.identity_api.create_user(user)
        user['domain_id'] = CONF.identity.default_domain_id
        self.patch('/users/%(user_id)s' % {
            'user_id': user['id']},
            body={'user': user},
            expected_status=exception.ValidationError.code)

    def test_delete_user(self):
        """Call ``DELETE /users/{user_id}``.

        As well as making sure the delete succeeds, we ensure
        that any credentials that reference this user are
        also deleted, while other credentials are unaffected.
        In addition, no tokens should remain valid for this user.

        """
        # First check the credential for this user is present
        r = PROVIDERS.credential_api.get_credential(self.credential['id'])
        self.assertDictEqual(self.credential, r)
        # Create a second credential with a different user

        user2 = unit.new_user_ref(domain_id=self.domain['id'],
                                  project_id=self.project['id'])
        user2 = PROVIDERS.identity_api.create_user(user2)
        credential2 = unit.new_credential_ref(user_id=user2['id'],
                                              project_id=self.project['id'])
        PROVIDERS.credential_api.create_credential(
            credential2['id'], credential2
        )

        # Create a token for this user which we can check later
        # gets deleted
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid for now
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)

        # Now delete the user
        self.delete('/users/%(user_id)s' % {
            'user_id': self.user['id']})

        # Deleting the user should have deleted any credentials
        # that reference this project
        self.assertRaises(exception.CredentialNotFound,
                          PROVIDERS.credential_api.get_credential,
                          self.credential['id'])
        # But the credential for user2 is unaffected
        r = PROVIDERS.credential_api.get_credential(credential2['id'])
        self.assertDictEqual(credential2, r)

    def test_delete_user_retries_on_deadlock(self):
        patcher = mock.patch('sqlalchemy.orm.query.Query.delete',
                             autospec=True)

        class FakeDeadlock(object):
            def __init__(self, mock_patcher):
                self.deadlock_count = 2
                self.mock_patcher = mock_patcher
                self.patched = True

            def __call__(self, *args, **kwargs):
                if self.deadlock_count > 1:
                    self.deadlock_count -= 1
                else:
                    self.mock_patcher.stop()
                    self.patched = False
                raise oslo_db_exception.DBDeadlock

        sql_delete_mock = patcher.start()
        side_effect = FakeDeadlock(patcher)
        sql_delete_mock.side_effect = side_effect

        user_ref = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain['id'])

        try:
            PROVIDERS.identity_api.delete_user(user_id=user_ref['id'])
        finally:
            if side_effect.patched:
                patcher.stop()

        call_count = sql_delete_mock.call_count

        # initial attempt + 1 retry
        delete_user_attempt_count = 2
        self.assertEqual(call_count, delete_user_attempt_count)

    # group crud tests

    def test_create_group(self):
        """Call ``POST /groups``."""
        # Create a new group to avoid a duplicate check failure
        ref = unit.new_group_ref(domain_id=self.domain_id)
        r = self.post(
            '/groups',
            body={'group': ref})
        return self.assertValidGroupResponse(r, ref)

    def test_create_group_bad_request(self):
        """Call ``POST /groups``."""
        self.post('/groups', body={'group': {}},
                  expected_status=http.client.BAD_REQUEST)

    def test_list_head_groups(self):
        """Call ``GET & HEAD /groups``."""
        resource_url = '/groups'
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

    def test_get_head_group(self):
        """Call ``GET & HEAD /groups/{group_id}``."""
        resource_url = '/groups/%(group_id)s' % {
            'group_id': self.group_id}
        r = self.get(resource_url)
        self.assertValidGroupResponse(r, self.group)
        self.head(resource_url, expected_status=http.client.OK)

    def test_update_group(self):
        """Call ``PATCH /groups/{group_id}``."""
        group = unit.new_group_ref(domain_id=self.domain_id)
        del group['id']
        r = self.patch('/groups/%(group_id)s' % {
            'group_id': self.group_id},
            body={'group': group})
        self.assertValidGroupResponse(r, group)

    def test_update_group_domain_id(self):
        """Call ``PATCH /groups/{group_id}`` with domain_id.

        A group's `domain_id` is immutable. Ensure that any attempts to update
        the `domain_id` of a group fails.
        """
        self.group['domain_id'] = CONF.identity.default_domain_id
        self.patch('/groups/%(group_id)s' % {
            'group_id': self.group['id']},
            body={'group': self.group},
            expected_status=exception.ValidationError.code)

    def test_delete_group(self):
        """Call ``DELETE /groups/{group_id}``."""
        self.delete('/groups/%(group_id)s' % {
            'group_id': self.group_id})

    def test_create_user_password_not_logged(self):
        # When a user is created, the password isn't logged at any level.

        log_fix = self.useFixture(fixtures.FakeLogger(level=log.DEBUG))

        ref = unit.new_user_ref(domain_id=self.domain_id)
        self.post(
            '/users',
            body={'user': ref})

        self.assertNotIn(ref['password'], log_fix.output)

    def test_update_password_not_logged(self):
        # When admin modifies user password, the password isn't logged at any
        # level.

        log_fix = self.useFixture(fixtures.FakeLogger(level=log.DEBUG))

        # bootstrap a user as admin
        user_ref = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain['id'])

        self.assertNotIn(user_ref['password'], log_fix.output)

        # administrative password reset
        new_password = uuid.uuid4().hex
        self.patch('/users/%s' % user_ref['id'],
                   body={'user': {'password': new_password}})

        self.assertNotIn(new_password, log_fix.output)

    def test_setting_default_project_id_to_domain_failed(self):
        """Call ``POST and PATCH /users`` default_project_id=domain_id.

        Make sure we validate the default_project_id if it is specified.
        It cannot be set to a domain_id, even for a project acting as domain
        right now. That's because we haven't sort out the issuing
        project-scoped token for project acting as domain bit yet. Once we
        got that sorted out, we can relax this constraint.

        """
        # creating a new user with default_project_id set to a
        # domain_id should result in HTTP 400
        ref = unit.new_user_ref(domain_id=self.domain_id,
                                project_id=self.domain_id)
        self.post('/users', body={'user': ref}, token=CONF.admin_token,
                  expected_status=http.client.BAD_REQUEST)

        # updating user's default_project_id to a domain_id should result
        # in HTTP 400
        user = {'default_project_id': self.domain_id}
        self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body={'user': user},
            token=CONF.admin_token,
            expected_status=http.client.BAD_REQUEST)


class ChangePasswordTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(ChangePasswordTestCase, self).setUp()
        self.user_ref = unit.create_user(PROVIDERS.identity_api,
                                         domain_id=self.domain['id'])
        self.token = self.get_request_token(self.user_ref['password'],
                                            http.client.CREATED)

    def get_request_token(self, password, expected_status):
        auth_data = self.build_authentication_request(
            user_id=self.user_ref['id'],
            password=password)
        r = self.v3_create_token(auth_data,
                                 expected_status=expected_status)
        return r.headers.get('X-Subject-Token')

    def change_password(self, expected_status, **kwargs):
        """Return a test response for a change password request."""
        return self.post('/users/%s/password' % self.user_ref['id'],
                         body={'user': kwargs},
                         token=self.token,
                         expected_status=expected_status)


class UserSelfServiceChangingPasswordsTestCase(ChangePasswordTestCase):

    def _create_user_with_expired_password(self):
        expire_days = CONF.security_compliance.password_expires_days + 1
        time = (
            datetime.datetime.utcnow() -
            datetime.timedelta(expire_days)
        )
        password = uuid.uuid4().hex
        user_ref = unit.new_user_ref(domain_id=self.domain_id,
                                     password=password)
        with freezegun.freeze_time(time):
            self.user_ref = PROVIDERS.identity_api.create_user(user_ref)

        return password

    def test_changing_password(self):
        # original password works
        token_id = self.get_request_token(self.user_ref['password'],
                                          expected_status=http.client.CREATED)
        # original token works
        old_token_auth = self.build_authentication_request(token=token_id)
        self.v3_create_token(old_token_auth)

        # change password
        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=self.user_ref['password'],
                             expected_status=http.client.NO_CONTENT)

        # old password fails
        self.get_request_token(self.user_ref['password'],
                               expected_status=http.client.UNAUTHORIZED)

        # old token fails
        self.v3_create_token(old_token_auth,
                             expected_status=http.client.NOT_FOUND)

        # new password works
        self.get_request_token(new_password,
                               expected_status=http.client.CREATED)

    def test_changing_password_with_min_password_age(self):
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            # enable minimum_password_age and attempt to change password
            new_password = uuid.uuid4().hex
            self.config_fixture.config(group='security_compliance',
                                       minimum_password_age=1)
            # able to change password after create user
            self.change_password(password=new_password,
                                 original_password=self.user_ref['password'],
                                 expected_status=http.client.NO_CONTENT)
            # 2nd change password should fail due to minimum password age and
            # make sure we wait one second to avoid race conditions with Fernet
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
            self.token = self.get_request_token(
                new_password,
                http.client.CREATED
            )
            self.change_password(password=uuid.uuid4().hex,
                                 original_password=new_password,
                                 expected_status=http.client.BAD_REQUEST)
            # disable minimum_password_age and attempt to change password
            self.config_fixture.config(group='security_compliance',
                                       minimum_password_age=0)
            self.change_password(password=uuid.uuid4().hex,
                                 original_password=new_password,
                                 expected_status=http.client.NO_CONTENT)

    def test_changing_password_with_password_lock(self):
        password = uuid.uuid4().hex
        ref = unit.new_user_ref(domain_id=self.domain_id, password=password)
        response = self.post('/users', body={'user': ref})
        user_id = response.json_body['user']['id']

        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            # Lock the user's password
            lock_pw_opt = options.LOCK_PASSWORD_OPT.option_name
            user_patch = {'user': {'options': {lock_pw_opt: True}}}
            self.patch('/users/%s' % user_id, body=user_patch)

            # Fail, password is locked
            new_password = uuid.uuid4().hex
            body = {
                'user': {
                    'original_password': password,
                    'password': new_password
                }
            }
            path = '/users/%s/password' % user_id
            self.post(path, body=body, expected_status=http.client.BAD_REQUEST)

            # Unlock the password, and change should work
            user_patch['user']['options'][lock_pw_opt] = False
            self.patch('/users/%s' % user_id, body=user_patch)

            path = '/users/%s/password' % user_id
            self.post(path, body=body, expected_status=http.client.NO_CONTENT)

            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

            auth_data = self.build_authentication_request(
                user_id=user_id,
                password=new_password
            )
            self.v3_create_token(
                auth_data, expected_status=http.client.CREATED
            )

            path = '/users/%s' % user_id
            user = self.get(path).json_body['user']
            self.assertIn(lock_pw_opt, user['options'])
            self.assertFalse(user['options'][lock_pw_opt])

            # Completely unset the option from the user's reference
            user_patch['user']['options'][lock_pw_opt] = None
            self.patch('/users/%s' % user_id, body=user_patch)
            path = '/users/%s' % user_id
            user = self.get(path).json_body['user']
            self.assertNotIn(lock_pw_opt, user['options'])

    def test_changing_password_with_missing_original_password_fails(self):
        r = self.change_password(password=uuid.uuid4().hex,
                                 expected_status=http.client.BAD_REQUEST)
        self.assertThat(r.result['error']['message'],
                        matchers.Contains('original_password'))

    def test_changing_password_with_missing_password_fails(self):
        r = self.change_password(original_password=self.user_ref['password'],
                                 expected_status=http.client.BAD_REQUEST)
        self.assertThat(r.result['error']['message'],
                        matchers.Contains('password'))

    def test_changing_password_with_incorrect_password_fails(self):
        self.change_password(password=uuid.uuid4().hex,
                             original_password=uuid.uuid4().hex,
                             expected_status=http.client.UNAUTHORIZED)

    def test_changing_password_with_disabled_user_fails(self):
        # disable the user account
        self.user_ref['enabled'] = False
        self.patch('/users/%s' % self.user_ref['id'],
                   body={'user': self.user_ref})

        self.change_password(password=uuid.uuid4().hex,
                             original_password=self.user_ref['password'],
                             expected_status=http.client.UNAUTHORIZED)

    def test_changing_password_not_logged(self):
        # When a user changes their password, the password isn't logged at any
        # level.

        log_fix = self.useFixture(fixtures.FakeLogger(level=log.DEBUG))

        # change password
        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=self.user_ref['password'],
                             expected_status=http.client.NO_CONTENT)

        self.assertNotIn(self.user_ref['password'], log_fix.output)
        self.assertNotIn(new_password, log_fix.output)

    def test_changing_expired_password_succeeds(self):
        self.config_fixture.config(group='security_compliance',
                                   password_expires_days=2)
        password = self._create_user_with_expired_password()

        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=password,
                             expected_status=http.client.NO_CONTENT)
        # new password works
        self.get_request_token(new_password,
                               expected_status=http.client.CREATED)

    def test_changing_expired_password_with_disabled_user_fails(self):
        self.config_fixture.config(group='security_compliance',
                                   password_expires_days=2)

        password = self._create_user_with_expired_password()
        # disable the user account
        self.user_ref['enabled'] = False
        self.patch('/users/%s' % self.user_ref['id'],
                   body={'user': self.user_ref})

        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=password,
                             expected_status=http.client.UNAUTHORIZED)

    def test_change_password_required_upon_first_use_for_create(self):
        self.config_fixture.config(group='security_compliance',
                                   change_password_upon_first_use=True)

        # create user
        self.user_ref = unit.create_user(PROVIDERS.identity_api,
                                         domain_id=self.domain['id'])

        # attempt to authenticate with create user password
        self.get_request_token(self.user_ref['password'],
                               expected_status=http.client.UNAUTHORIZED)

        # self-service change password
        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=self.user_ref['password'],
                             expected_status=http.client.NO_CONTENT)

        # authenticate with the new password
        self.token = self.get_request_token(new_password, http.client.CREATED)

    def test_change_password_required_upon_first_use_for_admin_reset(self):
        self.config_fixture.config(group='security_compliance',
                                   change_password_upon_first_use=True)

        # admin reset
        reset_password = uuid.uuid4().hex
        user_password = {'password': reset_password}
        PROVIDERS.identity_api.update_user(self.user_ref['id'], user_password)

        # attempt to authenticate with admin reset password
        self.get_request_token(reset_password,
                               expected_status=http.client.UNAUTHORIZED)

        # self-service change password
        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=reset_password,
                             expected_status=http.client.NO_CONTENT)

        # authenticate with the new password
        self.token = self.get_request_token(new_password, http.client.CREATED)

    def test_change_password_required_upon_first_use_ignore_user(self):
        self.config_fixture.config(group='security_compliance',
                                   change_password_upon_first_use=True)

        # ignore user and reset password
        reset_password = uuid.uuid4().hex
        self.user_ref['password'] = reset_password
        ignore_opt_name = options.IGNORE_CHANGE_PASSWORD_OPT.option_name
        self.user_ref['options'][ignore_opt_name] = True
        PROVIDERS.identity_api.update_user(self.user_ref['id'], self.user_ref)

        # authenticate with the reset password
        self.token = self.get_request_token(reset_password,
                                            http.client.CREATED)

    def test_lockout_exempt(self):
        self.config_fixture.config(group='security_compliance',
                                   lockout_failure_attempts=1)

        # create user
        self.user_ref = unit.create_user(PROVIDERS.identity_api,
                                         domain_id=self.domain['id'])

        # update the user, mark her as exempt from lockout
        ignore_opt_name = options.IGNORE_LOCKOUT_ATTEMPT_OPT.option_name
        self.user_ref['options'][ignore_opt_name] = True
        PROVIDERS.identity_api.update_user(self.user_ref['id'], self.user_ref)

        # fail to auth, this should lockout the user, since we're allowed
        # one failure, but we're exempt from lockout!
        bad_password = uuid.uuid4().hex
        self.token = self.get_request_token(bad_password,
                                            http.client.UNAUTHORIZED)

        # attempt to authenticate with correct password
        self.get_request_token(self.user_ref['password'],
                               expected_status=http.client.CREATED)


class PasswordValidationTestCase(ChangePasswordTestCase):

    def setUp(self):
        super(PasswordValidationTestCase, self).setUp()
        # passwords requires: 1 letter, 1 digit, 7 chars
        self.config_fixture.config(group='security_compliance',
                                   password_regex=(
                                       r'^(?=.*\d)(?=.*[a-zA-Z]).{7,}$'))

    def test_create_user_with_invalid_password(self):
        user = unit.new_user_ref(domain_id=self.domain_id)
        user['password'] = 'simple'
        self.post('/users', body={'user': user}, token=self.get_admin_token(),
                  expected_status=http.client.BAD_REQUEST)

    def test_update_user_with_invalid_password(self):
        user = unit.create_user(PROVIDERS.identity_api,
                                domain_id=self.domain['id'])
        user['password'] = 'simple'
        self.patch('/users/%(user_id)s' % {
            'user_id': user['id']},
            body={'user': user},
            expected_status=http.client.BAD_REQUEST)

    def test_changing_password_with_simple_password_strength(self):
        # password requires: any non-whitespace character
        self.config_fixture.config(group='security_compliance',
                                   password_regex=r'[\S]+')
        self.change_password(password='simple',
                             original_password=self.user_ref['password'],
                             expected_status=http.client.NO_CONTENT)

    def test_changing_password_with_strong_password_strength(self):
        self.change_password(password='mypassword2',
                             original_password=self.user_ref['password'],
                             expected_status=http.client.NO_CONTENT)

    def test_changing_password_with_strong_password_strength_fails(self):
        # no digit
        self.change_password(password='mypassword',
                             original_password=self.user_ref['password'],
                             expected_status=http.client.BAD_REQUEST)

        # no letter
        self.change_password(password='12345678',
                             original_password=self.user_ref['password'],
                             expected_status=http.client.BAD_REQUEST)

        # less than 7 chars
        self.change_password(password='mypas2',
                             original_password=self.user_ref['password'],
                             expected_status=http.client.BAD_REQUEST)


class UserFederatedAttributesTests(test_v3.RestfulTestCase):
    def _create_federated_attributes(self):
        # Create the idp
        idp = {
            'id': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        PROVIDERS.federation_api.create_idp(idp['id'], idp)
        # Create the mapping
        mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        mapping['id'] = uuid.uuid4().hex
        PROVIDERS.federation_api.create_mapping(mapping['id'], mapping)
        # Create the protocol
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': mapping['id']
        }
        PROVIDERS.federation_api.create_protocol(
            idp['id'], protocol['id'], protocol
        )
        return idp, protocol

    def _create_user_with_federated_user(self, user, fed_dict):
        with sql.session_for_write() as session:
            federated_ref = model.FederatedUser.from_dict(fed_dict)
            user_ref = model.User.from_dict(user)
            user_ref.created_at = datetime.datetime.utcnow()
            user_ref.federated_users.append(federated_ref)
            session.add(user_ref)
            return identity_base.filter_user(user_ref.to_dict())

    def setUp(self):
        super(UserFederatedAttributesTests, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        # Create the federated object
        idp, protocol = self._create_federated_attributes()
        self.fed_dict = unit.new_federated_user_ref()
        self.fed_dict['idp_id'] = idp['id']
        self.fed_dict['protocol_id'] = protocol['id']
        self.fed_dict['unique_id'] = "jdoe"
        # Create the domain_id, user, and federated_user relationship
        self.domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domain['id'], self.domain)
        self.fed_user = unit.new_user_ref(domain_id=self.domain['id'])
        self.fed_user = self._create_user_with_federated_user(self.fed_user,
                                                              self.fed_dict)
        # Create two new fed_users which will have the same idp and protocol
        # but be completely different from the first fed_user
        # Create a new idp and protocol for fed_user2 and 3
        idp, protocol = self._create_federated_attributes()
        self.fed_dict2 = unit.new_federated_user_ref()
        self.fed_dict2['idp_id'] = idp['id']
        self.fed_dict2['protocol_id'] = protocol['id']
        self.fed_dict2['unique_id'] = "ravelar"
        self.fed_user2 = unit.new_user_ref(domain_id=self.domain['id'])
        self.fed_user2 = self._create_user_with_federated_user(self.fed_user2,
                                                               self.fed_dict2)
        self.fed_dict3 = unit.new_federated_user_ref()
        self.fed_dict3['idp_id'] = idp['id']
        self.fed_dict3['protocol_id'] = protocol['id']
        self.fed_dict3['unique_id'] = "jsmith"
        self.fed_user3 = unit.new_user_ref(domain_id=self.domain['id'])
        self.fed_user3 = self._create_user_with_federated_user(self.fed_user3,
                                                               self.fed_dict3)

    def _test_list_users_with_federated_parameter(self, parameter):
        # construct the resource url based off what's passed in parameter
        resource_url = ('/users?%s=%s'
                        % (parameter[0], self.fed_dict[parameter[0]]))
        for attr in parameter[1:]:
            resource_url += '&%s=%s' % (attr, self.fed_dict[attr])
        r = self.get(resource_url)
        # Check that only one out of 3 fed_users is matched by calling the api
        # and that it is a valid response
        self.assertEqual(1, len(r.result['users']))
        self.assertValidUserListResponse(r, ref=self.fed_user,
                                         resource_url=resource_url)
        # Since unique_id will always return one user if matching for unique_id
        # in the query, we rule out unique_id for the next tests
        if not any('unique_id' in x for x in parameter):
            # Check that we get two matches here since fed_user2 and fed_user3
            # both have the same idp and protocol
            resource_url = ('/users?%s=%s'
                            % (parameter[0], self.fed_dict2[parameter[0]]))
            for attr in parameter[1:]:
                resource_url += '&%s=%s' % (attr, self.fed_dict2[attr])
            r = self.get(resource_url)
            self.assertEqual(2, len(r.result['users']))
            self.assertValidUserListResponse(r, ref=self.fed_user2,
                                             resource_url=resource_url)

    def test_list_users_with_idp_id(self):
        attribute = ['idp_id']
        self._test_list_users_with_federated_parameter(attribute)

    def test_list_users_with_protocol_id(self):
        attribute = ['protocol_id']
        self._test_list_users_with_federated_parameter(attribute)

    def test_list_users_with_unique_id(self):
        attribute = ['unique_id']
        self._test_list_users_with_federated_parameter(attribute)

    def test_list_users_with_idp_id_and_unique_id(self):
        attribute = ['idp_id', 'unique_id']
        self._test_list_users_with_federated_parameter(attribute)

    def test_list_users_with_idp_id_and_protocol_id(self):
        attribute = ['idp_id', 'protocol_id']
        self._test_list_users_with_federated_parameter(attribute)

    def test_list_users_with_protocol_id_and_unique_id(self):
        attribute = ['protocol_id', 'unique_id']
        self._test_list_users_with_federated_parameter(attribute)

    def test_list_users_with_all_federated_attributes(self):
        attribute = ['idp_id', 'protocol_id', 'unique_id']
        self._test_list_users_with_federated_parameter(attribute)

    def test_get_user_includes_required_federated_attributes(self):
        user = self.identity_api.get_user(self.fed_user['id'])
        self.assertIn('federated', user)
        self.assertIn('idp_id', user['federated'][0])
        self.assertIn('protocols', user['federated'][0])
        self.assertIn('protocol_id', user['federated'][0]['protocols'][0])
        self.assertIn('unique_id', user['federated'][0]['protocols'][0])
        r = self.get('/users/%(user_id)s' % {'user_id': user['id']})
        self.assertValidUserResponse(r, user)

    def test_create_user_with_federated_attributes(self):
        """Call ``POST /users``."""
        idp, protocol = self._create_federated_attributes()
        ref = unit.new_user_ref(domain_id=self.domain_id)
        ref['federated'] = [
            {
                'idp_id': idp['id'],
                'protocols': [
                    {
                        'protocol_id': protocol['id'],
                        'unique_id': uuid.uuid4().hex
                    }
                ]
            }
        ]
        r = self.post(
            '/users',
            body={'user': ref})
        user = r.result['user']
        self.assertEqual(user['name'], ref['name'])
        self.assertEqual(user['federated'], ref['federated'])
        self.assertValidUserResponse(r, ref)

    def test_create_user_fails_when_given_invalid_idp_and_protocols(self):
        """Call ``POST /users`` with invalid idp and protocol to fail."""
        idp, protocol = self._create_federated_attributes()
        ref = unit.new_user_ref(domain_id=self.domain_id)
        ref['federated'] = [
            {
                'idp_id': 'fakeidp',
                'protocols': [
                    {
                        'protocol_id': 'fakeprotocol_id',
                        'unique_id': uuid.uuid4().hex
                    }
                ]
            }
        ]

        self.post('/users', body={'user': ref}, token=self.get_admin_token(),
                  expected_status=http.client.BAD_REQUEST)
        ref['federated'][0]['idp_id'] = idp['id']
        self.post('/users', body={'user': ref}, token=self.get_admin_token(),
                  expected_status=http.client.BAD_REQUEST)

    def test_update_user_with_federated_attributes(self):
        """Call ``PATCH /users/{user_id}``."""
        user = self.fed_user.copy()
        del user['id']
        user['name'] = 'James Doe'
        idp, protocol = self._create_federated_attributes()
        user['federated'] = [
            {
                'idp_id': idp['id'],
                'protocols': [
                    {
                        'protocol_id': protocol['id'],
                        'unique_id': 'jdoe'
                    }
                ]
            }
        ]
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.fed_user['id']},
            body={'user': user})
        resp_user = r.result['user']
        self.assertEqual(user['name'], resp_user['name'])
        self.assertEqual(user['federated'], resp_user['federated'])
        self.assertValidUserResponse(r, user)

    def test_update_user_fails_when_given_invalid_idp_and_protocols(self):
        """Call ``PATCH /users/{user_id}``."""
        user = self.fed_user.copy()
        del user['id']
        idp, protocol = self._create_federated_attributes()
        user['federated'] = [
            {
                'idp_id': 'fakeidp',
                'protocols': [
                    {
                        'protocol_id': 'fakeprotocol_id',
                        'unique_id': uuid.uuid4().hex
                    }
                ]
            }
        ]

        self.patch('/users/%(user_id)s' % {
            'user_id': self.fed_user['id']},
            body={'user': user},
            expected_status=http.client.BAD_REQUEST)
        user['federated'][0]['idp_id'] = idp['id']
        self.patch('/users/%(user_id)s' % {
            'user_id': self.fed_user['id']},
            body={'user': user},
            expected_status=http.client.BAD_REQUEST)
