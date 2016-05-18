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

import fixtures
import mock
from oslo_config import cfg
from oslo_log import log
from six.moves import http_client
from testtools import matchers

from keystone.common import controller
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = cfg.CONF


# NOTE(morganfainberg): To be removed when admin_token_auth middleware is
# removed. This was moved to it's own testcase so it can setup the
# admin_token_auth pipeline without impacting other tests.
class IdentityTestCaseStaticAdminToken(test_v3.RestfulTestCase):
    EXTENSION_TO_ADD = 'admin_token_auth'

    def config_overrides(self):
        super(IdentityTestCaseStaticAdminToken, self).config_overrides()
        self.config_fixture.config(
            admin_token='ADMIN')

    def test_list_users_with_static_admin_token_and_multiple_backends(self):
        # domain-specific operations with the bootstrap ADMIN token is
        # disallowed when domain-specific drivers are enabled
        self.config_fixture.config(group='identity',
                                   domain_specific_drivers_enabled=True)
        self.get('/users', token=CONF.admin_token,
                 expected_status=exception.Unauthorized.code)

    def test_create_user_with_admin_token_and_no_domain(self):
        """Call ``POST /users`` with admin token but no domain id.

        It should not be possible to use the admin token to create a user
        while not explicitly passing the domain in the request body.

        """
        # Passing a valid domain id to new_user_ref() since domain_id is
        # not an optional parameter.
        ref = unit.new_user_ref(domain_id=self.domain_id)
        # Delete the domain id before sending the request.
        del ref['domain_id']
        self.post('/users', body={'user': ref}, token=CONF.admin_token,
                  expected_status=http_client.BAD_REQUEST)


class IdentityTestCase(test_v3.RestfulTestCase):
    """Test users and groups."""

    def setUp(self):
        super(IdentityTestCase, self).setUp()

        self.group = unit.new_group_ref(domain_id=self.domain_id)
        self.group = self.identity_api.create_group(self.group)
        self.group_id = self.group['id']

        self.credential = unit.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)

        self.credential_api.create_credential(self.credential['id'],
                                              self.credential)

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
        self.resource_api.create_domain(domain['id'], domain)
        user = unit.create_user(self.identity_api, domain_id=domain['id'])
        self.assignment_api.create_grant(
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
                  expected_status=http_client.CREATED)

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
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)

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
                  expected_status=http_client.BAD_REQUEST)

    def test_list_head_users(self):
        """Call ``GET & HEAD /users``."""
        resource_url = '/users'
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=self.user,
                                         resource_url=resource_url)
        self.head(resource_url, expected_status=http_client.OK)

    def test_list_users_with_multiple_backends(self):
        """Call ``GET /users`` when multiple backends is enabled.

        In this scenario, the controller requires a domain to be specified
        either as a filter or by using a domain scoped token.

        """
        self.config_fixture.config(group='identity',
                                   domain_specific_drivers_enabled=True)

        # Create a new domain with a new project and user
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)

        project = unit.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project['id'], project)

        user = unit.create_user(self.identity_api, domain_id=domain['id'])

        # Create both project and domain role grants for the user so we
        # can get both project and domain scoped tokens
        self.assignment_api.create_grant(
            role_id=self.role_id, user_id=user['id'],
            domain_id=domain['id'])
        self.assignment_api.create_grant(
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
        user = self.identity_api.create_user(user)
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
        self.head(resource_url, expected_status=http_client.OK)

    def test_get_user_with_default_project(self):
        """Call ``GET /users/{user_id}`` making sure of default_project_id."""
        user = unit.new_user_ref(domain_id=self.domain_id,
                                 project_id=self.project_id)
        user = self.identity_api.create_user(user)
        r = self.get('/users/%(user_id)s' % {'user_id': user['id']})
        self.assertValidUserResponse(r, user)

    def test_add_user_to_group(self):
        """Call ``PUT /groups/{group_id}/users/{user_id}``."""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

    def test_list_head_groups_for_user(self):
        """Call ``GET & HEAD /users/{user_id}/groups``."""
        user1 = unit.create_user(self.identity_api,
                                 domain_id=self.domain['id'])
        user2 = unit.create_user(self.identity_api,
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
        self.head(resource_url, auth=auth, expected_status=http_client.OK)

        # Administrator is allowed to list others' groups
        resource_url = ('/users/%(user_id)s/groups' %
                        {'user_id': user1['id']})
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)
        self.head(resource_url, expected_status=http_client.OK)

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
        self.head(resource_url, expected_status=http_client.OK)

    def test_remove_user_from_group(self):
        """Call ``DELETE /groups/{group_id}/users/{user_id}``."""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})
        self.delete('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

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
        user_ref = unit.create_user(self.identity_api,
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
                             expected_status=http_client.UNAUTHORIZED)

        # auth as user with an old token should not work after change
        self.v3_create_token(old_token_auth,
                             expected_status=http_client.NOT_FOUND)

        # new password should work
        new_password_auth = self.build_authentication_request(
            user_id=user_ref['id'],
            password=new_password)
        self.v3_create_token(new_password_auth)

    def test_update_user_domain_id(self):
        """Call ``PATCH /users/{user_id}`` with domain_id."""
        user = unit.new_user_ref(domain_id=self.domain['id'])
        user = self.identity_api.create_user(user)
        user['domain_id'] = CONF.identity.default_domain_id
        r = self.patch('/users/%(user_id)s' % {
            'user_id': user['id']},
            body={'user': user},
            expected_status=exception.ValidationError.code)
        self.config_fixture.config(domain_id_immutable=False)
        user['domain_id'] = self.domain['id']
        r = self.patch('/users/%(user_id)s' % {
            'user_id': user['id']},
            body={'user': user})
        self.assertValidUserResponse(r, user)

    def test_delete_user(self):
        """Call ``DELETE /users/{user_id}``.

        As well as making sure the delete succeeds, we ensure
        that any credentials that reference this user are
        also deleted, while other credentials are unaffected.
        In addition, no tokens should remain valid for this user.

        """
        # First check the credential for this user is present
        r = self.credential_api.get_credential(self.credential['id'])
        self.assertDictEqual(self.credential, r)
        # Create a second credential with a different user

        user2 = unit.new_user_ref(domain_id=self.domain['id'],
                                  project_id=self.project['id'])
        user2 = self.identity_api.create_user(user2)
        credential2 = unit.new_credential_ref(user_id=user2['id'],
                                              project_id=self.project['id'])
        self.credential_api.create_credential(credential2['id'], credential2)

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
                  expected_status=http_client.OK)

        # Now delete the user
        self.delete('/users/%(user_id)s' % {
            'user_id': self.user['id']})

        # Deleting the user should have deleted any credentials
        # that reference this project
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          self.credential['id'])
        # And the no tokens we remain valid
        tokens = self.token_provider_api._persistence._list_tokens(
            self.user['id'])
        self.assertEqual(0, len(tokens))
        # But the credential for user2 is unaffected
        r = self.credential_api.get_credential(credential2['id'])
        self.assertDictEqual(credential2, r)

    # shadow user tests
    def test_shadow_federated_user(self):
        fed_user = unit.new_federated_user_ref()
        user = (
            self.identity_api.shadow_federated_user(fed_user['idp_id'],
                                                    fed_user['protocol_id'],
                                                    fed_user['unique_id'],
                                                    fed_user['display_name'])
        )
        self.assertIsNotNone(user['id'])
        self.assertEqual(len(user.keys()), 4)
        self.assertIsNotNone(user['name'])
        self.assertIsNone(user['domain_id'])
        self.assertEqual(user['enabled'], True)

    def test_shadow_existing_federated_user(self):
        fed_user = unit.new_federated_user_ref()

        # introduce the user to keystone for the first time
        shadow_user1 = self.identity_api.shadow_federated_user(
            fed_user['idp_id'],
            fed_user['protocol_id'],
            fed_user['unique_id'],
            fed_user['display_name'])
        self.assertEqual(fed_user['display_name'], shadow_user1['name'])

        # shadow the user again, with another name to invalidate the cache
        # internally, this operation causes request to the driver. It should
        # not fail.
        fed_user['display_name'] = uuid.uuid4().hex
        shadow_user2 = self.identity_api.shadow_federated_user(
            fed_user['idp_id'],
            fed_user['protocol_id'],
            fed_user['unique_id'],
            fed_user['display_name'])
        self.assertEqual(fed_user['display_name'], shadow_user2['name'])
        self.assertNotEqual(shadow_user1['name'], shadow_user2['name'])

        # The shadowed users still share the same unique ID.
        self.assertEqual(shadow_user1['id'], shadow_user2['id'])

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
                  expected_status=http_client.BAD_REQUEST)

    def test_list_head_groups(self):
        """Call ``GET & HEAD /groups``."""
        resource_url = '/groups'
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)
        self.head(resource_url, expected_status=http_client.OK)

    def test_get_head_group(self):
        """Call ``GET & HEAD /groups/{group_id}``."""
        resource_url = '/groups/%(group_id)s' % {
            'group_id': self.group_id}
        r = self.get(resource_url)
        self.assertValidGroupResponse(r, self.group)
        self.head(resource_url, expected_status=http_client.OK)

    def test_update_group(self):
        """Call ``PATCH /groups/{group_id}``."""
        group = unit.new_group_ref(domain_id=self.domain_id)
        del group['id']
        r = self.patch('/groups/%(group_id)s' % {
            'group_id': self.group_id},
            body={'group': group})
        self.assertValidGroupResponse(r, group)

    def test_update_group_domain_id(self):
        """Call ``PATCH /groups/{group_id}`` with domain_id."""
        self.group['domain_id'] = CONF.identity.default_domain_id
        r = self.patch('/groups/%(group_id)s' % {
            'group_id': self.group['id']},
            body={'group': self.group},
            expected_status=exception.ValidationError.code)
        self.config_fixture.config(domain_id_immutable=False)
        self.group['domain_id'] = self.domain['id']
        r = self.patch('/groups/%(group_id)s' % {
            'group_id': self.group['id']},
            body={'group': self.group})
        self.assertValidGroupResponse(r, self.group)

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
        user_ref = unit.create_user(self.identity_api,
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
                  expected_status=http_client.BAD_REQUEST)

        # updating user's default_project_id to a domain_id should result
        # in HTTP 400
        user = {'default_project_id': self.domain_id}
        self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body={'user': user},
            token=CONF.admin_token,
            expected_status=http_client.BAD_REQUEST)


class IdentityV3toV2MethodsTestCase(unit.TestCase):
    """Test users V3 to V2 conversion methods."""

    def new_user_ref(self, **kwargs):
        """Construct a bare bones user ref.

        Omits all optional components.
        """
        ref = unit.new_user_ref(**kwargs)
        # description is already omitted
        del ref['email']
        del ref['enabled']
        del ref['password']
        return ref

    def setUp(self):
        super(IdentityV3toV2MethodsTestCase, self).setUp()
        self.load_backends()
        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex

        # User with only default_project_id in ref
        self.user1 = self.new_user_ref(
            id=user_id,
            name=user_id,
            project_id=project_id,
            domain_id=CONF.identity.default_domain_id)
        # User without default_project_id or tenantId in ref
        self.user2 = self.new_user_ref(
            id=user_id,
            name=user_id,
            domain_id=CONF.identity.default_domain_id)
        # User with both tenantId and default_project_id in ref
        self.user3 = self.new_user_ref(
            id=user_id,
            name=user_id,
            project_id=project_id,
            tenantId=project_id,
            domain_id=CONF.identity.default_domain_id)
        # User with only tenantId in ref
        self.user4 = self.new_user_ref(
            id=user_id,
            name=user_id,
            tenantId=project_id,
            domain_id=CONF.identity.default_domain_id)

        # Expected result if the user is meant to have a tenantId element
        self.expected_user = {'id': user_id,
                              'name': user_id,
                              'username': user_id,
                              'tenantId': project_id}

        # Expected result if the user is not meant to have a tenantId element
        self.expected_user_no_tenant_id = {'id': user_id,
                                           'name': user_id,
                                           'username': user_id}

    def test_v3_to_v2_user_method(self):

        updated_user1 = controller.V2Controller.v3_to_v2_user(self.user1)
        self.assertIs(self.user1, updated_user1)
        self.assertDictEqual(self.expected_user, self.user1)
        updated_user2 = controller.V2Controller.v3_to_v2_user(self.user2)
        self.assertIs(self.user2, updated_user2)
        self.assertDictEqual(self.expected_user_no_tenant_id, self.user2)
        updated_user3 = controller.V2Controller.v3_to_v2_user(self.user3)
        self.assertIs(self.user3, updated_user3)
        self.assertDictEqual(self.expected_user, self.user3)
        updated_user4 = controller.V2Controller.v3_to_v2_user(self.user4)
        self.assertIs(self.user4, updated_user4)
        self.assertDictEqual(self.expected_user_no_tenant_id, self.user4)

    def test_v3_to_v2_user_method_list(self):
        user_list = [self.user1, self.user2, self.user3, self.user4]
        updated_list = controller.V2Controller.v3_to_v2_user(user_list)

        self.assertEqual(len(user_list), len(updated_list))

        for i, ref in enumerate(updated_list):
            # Order should not change.
            self.assertIs(ref, user_list[i])

        self.assertDictEqual(self.expected_user, self.user1)
        self.assertDictEqual(self.expected_user_no_tenant_id, self.user2)
        self.assertDictEqual(self.expected_user, self.user3)
        self.assertDictEqual(self.expected_user_no_tenant_id, self.user4)


class UserSelfServiceChangingPasswordsTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(UserSelfServiceChangingPasswordsTestCase, self).setUp()
        self.user_ref = unit.create_user(self.identity_api,
                                         domain_id=self.domain['id'])
        self.token = self.get_request_token(self.user_ref['password'],
                                            http_client.CREATED)

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

    def test_changing_password(self):
        # original password works
        token_id = self.get_request_token(self.user_ref['password'],
                                          expected_status=http_client.CREATED)
        # original token works
        old_token_auth = self.build_authentication_request(token=token_id)
        self.v3_create_token(old_token_auth)

        # change password
        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=self.user_ref['password'],
                             expected_status=http_client.NO_CONTENT)

        # old password fails
        self.get_request_token(self.user_ref['password'],
                               expected_status=http_client.UNAUTHORIZED)

        # old token fails
        self.v3_create_token(old_token_auth,
                             expected_status=http_client.NOT_FOUND)

        # new password works
        self.get_request_token(new_password,
                               expected_status=http_client.CREATED)

    def test_changing_password_with_missing_original_password_fails(self):
        r = self.change_password(password=uuid.uuid4().hex,
                                 expected_status=http_client.BAD_REQUEST)
        self.assertThat(r.result['error']['message'],
                        matchers.Contains('original_password'))

    def test_changing_password_with_missing_password_fails(self):
        r = self.change_password(original_password=self.user_ref['password'],
                                 expected_status=http_client.BAD_REQUEST)
        self.assertThat(r.result['error']['message'],
                        matchers.Contains('password'))

    def test_changing_password_with_incorrect_password_fails(self):
        self.change_password(password=uuid.uuid4().hex,
                             original_password=uuid.uuid4().hex,
                             expected_status=http_client.UNAUTHORIZED)

    def test_changing_password_with_disabled_user_fails(self):
        # disable the user account
        self.user_ref['enabled'] = False
        self.patch('/users/%s' % self.user_ref['id'],
                   body={'user': self.user_ref})

        self.change_password(password=uuid.uuid4().hex,
                             original_password=self.user_ref['password'],
                             expected_status=http_client.UNAUTHORIZED)

    def test_changing_password_not_logged(self):
        # When a user changes their password, the password isn't logged at any
        # level.

        log_fix = self.useFixture(fixtures.FakeLogger(level=log.DEBUG))

        # change password
        new_password = uuid.uuid4().hex
        self.change_password(password=new_password,
                             original_password=self.user_ref['password'],
                             expected_status=http_client.NO_CONTENT)

        self.assertNotIn(self.user_ref['password'], log_fix.output)
        self.assertNotIn(new_password, log_fix.output)
