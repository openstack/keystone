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

import copy
import datetime
import random
import string
import time
import uuid

import mock
import oslo_utils.fixture
from oslo_utils import timeutils
import six
from testtools import matchers
import webob

from keystone import assignment
from keystone import auth
from keystone.common import authorization
import keystone.conf
from keystone import exception
from keystone.models import token_model
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone import token
from keystone import trust


CONF = keystone.conf.CONF
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

HOST = ''.join(random.choice(string.ascii_lowercase) for x in range(
    random.randint(5, 15)))
HOST_URL = 'http://%s' % (HOST)


def _build_user_auth(token=None, user_id=None, username=None,
                     password=None, tenant_id=None, tenant_name=None,
                     trust_id=None):
    """Build auth dictionary.

    It will create an auth dictionary based on all the arguments
    that it receives.
    """
    auth_json = {}
    if token is not None:
        auth_json['token'] = token
    if username or password:
        auth_json['passwordCredentials'] = {}
    if username is not None:
        auth_json['passwordCredentials']['username'] = username
    if user_id is not None:
        auth_json['passwordCredentials']['userId'] = user_id
    if password is not None:
        auth_json['passwordCredentials']['password'] = password
    if tenant_name is not None:
        auth_json['tenantName'] = tenant_name
    if tenant_id is not None:
        auth_json['tenantId'] = tenant_id
    if trust_id is not None:
        auth_json['trust_id'] = trust_id
    return auth_json


class AuthTest(unit.TestCase):
    def setUp(self):
        self.useFixture(database.Database())
        super(AuthTest, self).setUp()
        self.time_fixture = self.useFixture(oslo_utils.fixture.TimeFixture())

        self.load_backends()
        self.load_fixtures(default_fixtures)

        environ = {'REMOTE_USER': 'FOO', 'AUTH_TYPE': 'Negotiate'}
        self.request_with_remote_user = self.make_request(environ=environ)

        self.empty_request = self.make_request()

        self.controller = token.controllers.Auth()

    def assertEqualTokens(self, a, b, enforce_audit_ids=True):
        """Assert that two tokens are equal.

        Compare two tokens except for their ids. This also truncates
        the time in the comparison.
        """
        def normalize(token):
            token['access']['token']['id'] = 'dummy'
            del token['access']['token']['expires']
            del token['access']['token']['issued_at']
            del token['access']['token']['audit_ids']
            return token

        self.assertCloseEnoughForGovernmentWork(
            timeutils.parse_isotime(a['access']['token']['expires']),
            timeutils.parse_isotime(b['access']['token']['expires']))
        self.assertCloseEnoughForGovernmentWork(
            timeutils.parse_isotime(a['access']['token']['issued_at']),
            timeutils.parse_isotime(b['access']['token']['issued_at']))
        if enforce_audit_ids:
            self.assertIn(a['access']['token']['audit_ids'][0],
                          b['access']['token']['audit_ids'])
            self.assertThat(len(a['access']['token']['audit_ids']),
                            matchers.LessThan(3))
            self.assertThat(len(b['access']['token']['audit_ids']),
                            matchers.LessThan(3))

        return self.assertDictEqual(normalize(a), normalize(b))


class AuthBadRequests(AuthTest):
    def test_no_external_auth(self):
        """Verify that _authenticate_external() raises exception if N/A."""
        external_method = token.controllers.ExternalAuthenticationMethod()
        request = webob.Request.blank('/')
        self.assertRaises(
            token.controllers.ExternalAuthNotApplicable,
            external_method.authenticate,
            request, auth={})

    def test_empty_remote_user(self):
        """Verify exception is raised when REMOTE_USER is an empty string."""
        external_method = token.controllers.ExternalAuthenticationMethod()
        request = webob.Request.blank('/', environ={'REMOTE_USER': ''})
        self.assertRaises(
            token.controllers.ExternalAuthNotApplicable,
            external_method.authenticate,
            request, auth={})

    def test_no_token_in_auth(self):
        """Verify that authenticate raises exception if no token."""
        token_method = token.controllers.TokenAuthenticationMethod()
        self.assertRaises(
            exception.ValidationError,
            token_method.authenticate,
            None, {})

    def test_no_credentials_in_auth(self):
        """Verify that the method generator raises exception if no creds."""
        self.assertRaises(
            exception.ValidationError,
            token.controllers.authentication_method_generator,
            self.make_request(),
            {}
        )

    def test_empty_username_and_userid_in_auth(self):
        """Verify that empty username and userID raises ValidationError."""
        token_method = token.controllers.LocalAuthenticationMethod()
        self.assertRaises(
            exception.ValidationError,
            token_method.authenticate,
            None, {'passwordCredentials': {'password': 'abc',
                                           'userId': '', 'username': ''}})

    def test_authenticate_blank_request_body(self):
        """Verify sending empty json dict raises the right exception."""
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          self.make_request(), {})

    def test_authenticate_blank_auth(self):
        """Verify sending blank 'auth' raises the right exception."""
        body_dict = _build_user_auth()
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_invalid_auth_content(self):
        """Verify sending invalid 'auth' raises the right exception."""
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          self.make_request(), {'auth': 'abcd'})

    def test_authenticate_user_id_too_large(self):
        """Verify sending large 'userId' raises the right exception."""
        body_dict = _build_user_auth(user_id='0' * 65, username='FOO',
                                     password='foo2')
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_username_too_large(self):
        """Verify sending large 'username' raises the right exception."""
        body_dict = _build_user_auth(username='0' * 65, password='foo2')
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_tenant_id_too_large(self):
        """Verify sending large 'tenantId' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='foo2',
                                     tenant_id='0' * 65)
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_tenant_name_too_large(self):
        """Verify sending large 'tenantName' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='foo2',
                                     tenant_name='0' * 65)
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_token_too_large(self):
        """Verify sending large 'token' raises the right exception."""
        body_dict = _build_user_auth(token={'id': '0' * 8193})
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_password_too_large(self):
        """Verify sending large 'password' raises the right exception."""
        length = CONF.identity.max_password_length + 1
        body_dict = _build_user_auth(username='FOO', password='0' * length)
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_fails_if_project_unsafe(self):
        """Verify authenticate to a project with unsafe name fails."""
        # Start with url name restrictions off, so we can create the unsafe
        # named project
        self.config_fixture.config(group='resource',
                                   project_name_url_safe='off')
        unsafe_name = 'i am not / safe'
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id, name=unsafe_name)
        self.resource_api.create_project(project['id'], project)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], project['id'], self.role_member['id'])
        empty_request = self.make_request()

        body_dict = _build_user_auth(
            username=self.user_foo['name'],
            password=self.user_foo['password'],
            tenant_name=project['name'])

        # Since name url restriction is off, we should be able to authenticate
        self.controller.authenticate(empty_request, body_dict)

        # Set the name url restriction to strict and we should fail to
        # authenticate
        self.config_fixture.config(group='resource',
                                   project_name_url_safe='strict')
        self.assertRaises(exception.Unauthorized,
                          self.controller.authenticate,
                          empty_request, body_dict)


class AuthWithToken(object):
    def test_unscoped_token(self):
        """Verify getting an unscoped token with password creds."""
        body_dict = _build_user_auth(username='FOO',
                                     password='foo2')
        unscoped_token = self.controller.authenticate(self.make_request(),
                                                      body_dict)
        self.assertNotIn('tenant', unscoped_token['access']['token'])

    def test_auth_invalid_token(self):
        """Verify exception is raised if invalid token."""
        body_dict = _build_user_auth(token={"id": uuid.uuid4().hex})
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.make_request(), body_dict)

    def test_auth_bad_formatted_token(self):
        """Verify exception is raised if invalid token."""
        body_dict = _build_user_auth(token={})
        self.assertRaises(
            exception.ValidationError,
            self.controller.authenticate,
            self.make_request(), body_dict)

    def test_auth_unscoped_token_no_project(self):
        """Verify getting an unscoped token with an unscoped token."""
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2')
        unscoped_token = self.controller.authenticate(self.make_request(),
                                                      body_dict)

        body_dict = _build_user_auth(
            token=unscoped_token["access"]["token"])
        unscoped_token_2 = self.controller.authenticate(self.make_request(),
                                                        body_dict)

        self.assertEqualTokens(unscoped_token, unscoped_token_2)

    def test_auth_unscoped_token_project(self):
        """Verify getting a token in a tenant with an unscoped token."""
        # Add a role in so we can check we get this back
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_member['id'])
        # Get an unscoped token
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2')
        unscoped_token = self.controller.authenticate(self.make_request(),
                                                      body_dict)
        # Get a token on BAR tenant using the unscoped token
        body_dict = _build_user_auth(
            token=unscoped_token["access"]["token"],
            tenant_name="BAR")
        scoped_token = self.controller.authenticate(self.make_request(),
                                                    body_dict)

        tenant = scoped_token["access"]["token"]["tenant"]
        roles = scoped_token["access"]["metadata"]["roles"]
        self.assertEqual(self.tenant_bar['id'], tenant["id"])
        self.assertThat(roles, matchers.Contains(self.role_member['id']))

    def test_auth_scoped_token_bad_project_with_debug(self):
        """Authenticating with an invalid project fails."""
        # Bug 1379952 reports poor user feedback, even in insecure_debug mode,
        # when the user accidentally passes a project name as an ID.
        # This test intentionally does exactly that.
        body_dict = _build_user_auth(
            username=self.user_foo['name'],
            password=self.user_foo['password'],
            tenant_id=self.tenant_bar['name'])

        # with insecure_debug enabled, this produces a friendly exception.
        self.config_fixture.config(debug=True, insecure_debug=True)
        e = self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.make_request(), body_dict)
        # explicitly verify that the error message shows that a *name* is
        # found where an *ID* is expected
        self.assertIn(
            'Project ID not found: %s' % self.tenant_bar['name'],
            six.text_type(e))

    def test_auth_scoped_token_bad_project_without_debug(self):
        """Authenticating with an invalid project fails."""
        # Bug 1379952 reports poor user feedback, even in insecure_debug mode,
        # when the user accidentally passes a project name as an ID.
        # This test intentionally does exactly that.
        body_dict = _build_user_auth(
            username=self.user_foo['name'],
            password=self.user_foo['password'],
            tenant_id=self.tenant_bar['name'])

        # with insecure_debug disabled (the default), authentication failure
        # details are suppressed.
        e = self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.make_request(), body_dict)
        # explicitly verify that the error message details above have been
        # suppressed.
        self.assertNotIn(
            'Project ID not found: %s' % self.tenant_bar['name'],
            six.text_type(e))

    def test_auth_token_project_group_role(self):
        """Verify getting a token in a tenant with group roles."""
        # Add a v2 style role in so we can check we get this back
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_member['id'])
        # Now create a group role for this user as well
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        new_group = unit.new_group_ref(domain_id=domain1['id'])
        new_group = self.identity_api.create_group(new_group)
        self.identity_api.add_user_to_group(self.user_foo['id'],
                                            new_group['id'])
        self.assignment_api.create_grant(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'],
            role_id=self.role_admin['id'])

        # Get a scoped token for the tenant
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name="BAR")

        scoped_token = self.controller.authenticate(self.make_request(),
                                                    body_dict)

        tenant = scoped_token["access"]["token"]["tenant"]
        roles = scoped_token["access"]["metadata"]["roles"]
        self.assertEqual(self.tenant_bar['id'], tenant["id"])
        self.assertIn(self.role_member['id'], roles)
        self.assertIn(self.role_admin['id'], roles)

    def test_belongs_to_no_tenant(self):
        r = self.controller.authenticate(
            self.make_request(),
            auth={
                'passwordCredentials': {
                    'username': self.user_foo['name'],
                    'password': self.user_foo['password']
                }
            })
        unscoped_token_id = r['access']['token']['id']
        query_string = 'belongsTo=%s' % self.tenant_bar['id']
        self.assertRaises(
            exception.Unauthorized,
            self.controller.validate_token,
            self.make_request(is_admin=True, query_string=query_string),
            token_id=unscoped_token_id)

        self.assertRaises(
            exception.Unauthorized,
            self.controller.validate_token_head,
            self.make_request(is_admin=True, query_string=query_string),
            token_id=unscoped_token_id)

    def test_belongs_to(self):
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name=self.tenant_bar['name'])

        scoped_token = self.controller.authenticate(self.make_request(),
                                                    body_dict)
        scoped_token_id = scoped_token['access']['token']['id']

        query_string = 'belongsTo=%s' % uuid.uuid4().hex
        self.assertRaises(
            exception.Unauthorized,
            self.controller.validate_token,
            self.make_request(is_admin=True, query_string=query_string),
            token_id=scoped_token_id)

        self.assertRaises(
            exception.Unauthorized,
            self.controller.validate_token_head,
            self.make_request(is_admin=True, query_string=query_string),
            token_id=scoped_token_id)

        query_string = 'belongsTo=%s' % self.tenant_bar['id']
        self.controller.validate_token(
            self.make_request(is_admin=True, query_string=query_string),
            token_id=scoped_token_id
        )

        self.controller.validate_token_head(
            self.make_request(is_admin=True, query_string=query_string),
            token_id=scoped_token_id
        )

    def test_token_auth_with_binding(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        body_dict = _build_user_auth()
        unscoped_token = self.controller.authenticate(
            self.request_with_remote_user, body_dict)

        # the token should have bind information in it
        bind = unscoped_token['access']['token']['bind']
        self.assertEqual('FOO', bind['kerberos'])

        body_dict = _build_user_auth(
            token=unscoped_token['access']['token'],
            tenant_name='BAR')

        # using unscoped token without remote user context fails
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.empty_request, body_dict)

        # using token with remote user context succeeds
        scoped_token = self.controller.authenticate(
            self.request_with_remote_user, body_dict)

        # the bind information should be carried over from the original token
        bind = scoped_token['access']['token']['bind']
        self.assertEqual('FOO', bind['kerberos'])

    def test_deleting_role_revokes_token(self):
        role_controller = assignment.controllers.Role()
        project1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project1['id'], project1)
        role_one = unit.new_role_ref(id='role_one')
        self.role_api.create_role(role_one['id'], role_one)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], project1['id'], role_one['id'])

        # Get a scoped token for the tenant
        body_dict = _build_user_auth(
            username=self.user_foo['name'],
            password=self.user_foo['password'],
            tenant_name=project1['name'])
        token = self.controller.authenticate(self.empty_request, body_dict)
        # Ensure it is valid
        token_id = token['access']['token']['id']
        self.controller.validate_token(self.make_request(is_admin=True),
                                       token_id=token_id)

        # Delete the role, which should invalidate the token
        role_controller.delete_role(self.make_request(is_admin=True),
                                    role_one['id'])

        # Check the token is now invalid
        self.assertRaises(
            exception.TokenNotFound,
            self.controller.validate_token,
            self.make_request(is_admin=True),
            token_id=token_id)

    def test_deleting_role_assignment_does_not_revoke_unscoped_token(self):
        admin_request = self.make_request(is_admin=True)

        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(project['id'], project)
        role = unit.new_role_ref()
        self.role_api.create_role(role['id'], role)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], project['id'], role['id'])

        # Get an unscoped token.
        token = self.controller.authenticate(
            self.make_request(),
            _build_user_auth(username=self.user_foo['name'],
                             password=self.user_foo['password']))
        token_id = token['access']['token']['id']

        # Ensure it is valid
        self.controller.validate_token(admin_request, token_id=token_id)

        # Delete the role assignment, which should not invalidate the token,
        # because we're not consuming it with just an unscoped token.
        self.assignment_api.remove_role_from_user_and_project(
            self.user_foo['id'], project['id'], role['id'])

        # Ensure it is still valid
        self.controller.validate_token(admin_request, token_id=token_id)

    def test_only_original_audit_id_is_kept(self):
        def get_audit_ids(token):
            return token['access']['token']['audit_ids']

        # get a token
        body_dict = _build_user_auth(username='FOO', password='foo2')
        unscoped_token = self.controller.authenticate(self.make_request(),
                                                      body_dict)
        starting_audit_id = get_audit_ids(unscoped_token)[0]
        self.assertIsNotNone(starting_audit_id)

        # get another token to ensure the correct parent audit_id is set
        body_dict = _build_user_auth(token=unscoped_token["access"]["token"])
        unscoped_token_2 = self.controller.authenticate(self.make_request(),
                                                        body_dict)
        audit_ids = get_audit_ids(unscoped_token_2)
        self.assertThat(audit_ids, matchers.HasLength(2))
        self.assertThat(audit_ids[-1], matchers.Equals(starting_audit_id))

        # get another token from token 2 and ensure the correct parent
        # audit_id is set
        body_dict = _build_user_auth(token=unscoped_token_2["access"]["token"])
        unscoped_token_3 = self.controller.authenticate(self.make_request(),
                                                        body_dict)
        audit_ids = get_audit_ids(unscoped_token_3)
        self.assertThat(audit_ids, matchers.HasLength(2))
        self.assertThat(audit_ids[-1], matchers.Equals(starting_audit_id))

    def test_revoke_by_audit_chain_id_original_token(self):
        self.config_fixture.config(group='token', revoke_by_id=False)

        # get a token
        body_dict = _build_user_auth(username='FOO', password='foo2')
        unscoped_token = self.controller.authenticate(self.make_request(),
                                                      body_dict)
        token_id = unscoped_token['access']['token']['id']
        self.time_fixture.advance_time_seconds(1)

        # get a second token
        body_dict = _build_user_auth(token=unscoped_token["access"]["token"])
        unscoped_token_2 = self.controller.authenticate(self.make_request(),
                                                        body_dict)
        token_2_id = unscoped_token_2['access']['token']['id']
        self.time_fixture.advance_time_seconds(1)

        self.token_provider_api.revoke_token(token_id, revoke_chain=True)

        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          token_id=token_id)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          token_id=token_2_id)

    def test_revoke_by_audit_chain_id_chained_token(self):
        self.config_fixture.config(group='token', revoke_by_id=False)

        # get a token
        body_dict = _build_user_auth(username='FOO', password='foo2')
        unscoped_token = self.controller.authenticate(self.make_request(),
                                                      body_dict)
        token_id = unscoped_token['access']['token']['id']
        self.time_fixture.advance_time_seconds(1)

        # get a second token
        body_dict = _build_user_auth(token=unscoped_token["access"]["token"])
        unscoped_token_2 = self.controller.authenticate(self.make_request(),
                                                        body_dict)
        token_2_id = unscoped_token_2['access']['token']['id']
        self.time_fixture.advance_time_seconds(1)

        self.token_provider_api.revoke_token(token_2_id, revoke_chain=True)

        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          token_id=token_id)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          token_id=token_2_id)

    def _mock_audit_info(self, parent_audit_id):
        # NOTE(morgainfainberg): The token model and other cases that are
        # extracting the audit id expect 'None' if the audit id doesn't
        # exist. This ensures that the audit_id is None and the
        # audit_chain_id will also return None.
        return [None, None]


class UUIDAuthWithToken(AuthWithToken, AuthTest):
    def config_overrides(self):
        super(UUIDAuthWithToken, self).config_overrides()
        self.config_fixture.config(group='token', provider='uuid')


class FernetAuthWithToken(AuthWithToken, AuthTest):
    def config_overrides(self):
        super(FernetAuthWithToken, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def test_token_auth_with_binding(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        body_dict = _build_user_auth()
        self.assertRaises(exception.NotImplemented,
                          self.controller.authenticate,
                          self.request_with_remote_user,
                          body_dict)

    def test_deleting_role_revokes_token(self):
        self.skip_test_overrides('Fernet with v2.0 and revocation is broken')


class AuthWithPasswordCredentials(AuthTest):
    def test_auth_invalid_user(self):
        """Verify exception is raised if invalid user."""
        body_dict = _build_user_auth(
            username=uuid.uuid4().hex,
            password=uuid.uuid4().hex)
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.make_request(), body_dict)

    def test_auth_valid_user_invalid_password(self):
        """Verify exception is raised if invalid password."""
        body_dict = _build_user_auth(
            username="FOO",
            password=uuid.uuid4().hex)
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.make_request(), body_dict)

    def test_auth_empty_password(self):
        """Verify exception is raised if empty password."""
        body_dict = _build_user_auth(
            username="FOO",
            password="")
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.empty_request, body_dict)

    def test_auth_no_password(self):
        """Verify exception is raised if empty password."""
        body_dict = _build_user_auth(username="FOO")
        self.assertRaises(
            exception.ValidationError,
            self.controller.authenticate,
            self.make_request(), body_dict)

    def test_authenticate_blank_password_credentials(self):
        """Sending empty dict as passwordCredentials raises 400 Bad Requset."""
        body_dict = {'passwordCredentials': {}, 'tenantName': 'demo'}
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_authenticate_no_username(self):
        """Verify skipping username raises the right exception."""
        body_dict = _build_user_auth(password="pass",
                                     tenant_name="demo")
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          self.make_request(), body_dict)

    def test_bind_without_remote_user(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        body_dict = _build_user_auth(username='FOO', password='foo2',
                                     tenant_name='BAR')
        token = self.controller.authenticate(self.make_request(), body_dict)
        self.assertNotIn('bind', token['access']['token'])

    def test_change_default_domain_id(self):
        # If the default_domain_id config option is not the default then the
        # user in auth data is from the new default domain.

        # 1) Create a new domain.
        new_domain = unit.new_domain_ref()
        new_domain_id = new_domain['id']

        self.resource_api.create_domain(new_domain_id, new_domain)

        # 2) Create user "foo" in new domain with different password than
        #    default-domain foo.
        new_user = unit.create_user(self.identity_api,
                                    name=self.user_foo['name'],
                                    domain_id=new_domain_id)

        # 3) Update the default_domain_id config option to the new domain

        self.config_fixture.config(group='identity',
                                   default_domain_id=new_domain_id)

        # 4) Authenticate as "foo" using the password in the new domain.

        body_dict = _build_user_auth(
            username=self.user_foo['name'],
            password=new_user['password'])

        # The test is successful if this doesn't raise, so no need to assert.
        self.controller.authenticate(self.make_request(), body_dict)


class AuthWithRemoteUser(object):
    def test_unscoped_remote_authn(self):
        """Verify getting an unscoped token with external authn."""
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2')
        local_token = self.controller.authenticate(
            self.make_request(), body_dict)

        body_dict = _build_user_auth()
        remote_token = self.controller.authenticate(
            self.request_with_remote_user, body_dict)

        self.assertEqualTokens(local_token, remote_token,
                               enforce_audit_ids=False)

    def test_unscoped_remote_authn_jsonless(self):
        """Verify that external auth with invalid request fails."""
        self.assertRaises(
            exception.ValidationError,
            self.controller.authenticate,
            self.make_request(environ={'REMOTE_USER': 'FOO'}),
            None)

    def test_scoped_remote_authn(self):
        """Verify getting a token with external authn."""
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name='BAR')
        local_token = self.controller.authenticate(
            self.make_request(), body_dict)

        body_dict = _build_user_auth(
            tenant_name='BAR')
        remote_token = self.controller.authenticate(
            self.request_with_remote_user, body_dict)

        self.assertEqualTokens(local_token, remote_token,
                               enforce_audit_ids=False)

    def test_scoped_nometa_remote_authn(self):
        """Verify getting a token with external authn and no metadata."""
        body_dict = _build_user_auth(
            username='TWO',
            password='two2',
            tenant_name='BAZ')
        local_token = self.controller.authenticate(
            self.make_request(), body_dict)

        body_dict = _build_user_auth(tenant_name='BAZ')
        remote_token = self.controller.authenticate(
            self.make_request(environ={'REMOTE_USER': 'TWO'}), body_dict)

        self.assertEqualTokens(local_token, remote_token,
                               enforce_audit_ids=False)

    def test_scoped_remote_authn_invalid_user(self):
        """Verify that external auth with invalid user fails."""
        body_dict = _build_user_auth(tenant_name="BAR")
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            self.make_request(environ={'REMOTE_USER': uuid.uuid4().hex}),
            body_dict)

    def test_bind_with_kerberos(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        body_dict = _build_user_auth(tenant_name="BAR")
        token = self.controller.authenticate(self.request_with_remote_user,
                                             body_dict)
        self.assertEqual('FOO', token['access']['token']['bind']['kerberos'])

    def test_bind_without_config_opt(self):
        self.config_fixture.config(group='token', bind=['x509'])
        body_dict = _build_user_auth(tenant_name='BAR')
        token = self.controller.authenticate(self.request_with_remote_user,
                                             body_dict)
        self.assertNotIn('bind', token['access']['token'])


class FernetAuthWithRemoteUser(AuthWithRemoteUser, AuthTest):

    def config_overrides(self):
        super(FernetAuthWithRemoteUser, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def test_bind_with_kerberos(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        body_dict = _build_user_auth(tenant_name="BAR")
        # NOTE(lbragstad): Bind authentication is not supported by the Fernet
        # provider.
        self.assertRaises(exception.NotImplemented,
                          self.controller.authenticate,
                          self.request_with_remote_user,
                          body_dict)


class UUIDAuthWithRemoteUser(AuthWithRemoteUser, AuthTest):

    def config_overrides(self):
        super(UUIDAuthWithRemoteUser, self).config_overrides()
        self.config_fixture.config(group='token', provider='uuid')


class AuthWithTrust(object):
    def setUp(self):
        super(AuthWithTrust, self).setUp()

        self.trust_controller = trust.controllers.TrustV3()
        self.auth_v3_controller = auth.controllers.Auth()
        self.trustor = self.user_foo
        self.trustee = self.user_two
        self.assigned_roles = [self.role_member['id'],
                               self.role_browser['id']]
        for assigned_role in self.assigned_roles:
            self.assignment_api.add_role_to_user_and_project(
                self.trustor['id'], self.tenant_bar['id'], assigned_role)

        self.sample_data = {'trustor_user_id': self.trustor['id'],
                            'trustee_user_id': self.trustee['id'],
                            'project_id': self.tenant_bar['id'],
                            'impersonation': True,
                            'roles': [{'id': self.role_browser['id']},
                                      {'name': self.role_member['name']}]}

    def config_overrides(self):
        super(AuthWithTrust, self).config_overrides()
        self.config_fixture.config(group='trust', enabled=True)

    def _create_auth_request(self, token_id):
        token_ref = token_model.KeystoneToken(
            token_id=token_id,
            token_data=self.token_provider_api.validate_token(token_id))
        auth_context = authorization.token_to_auth_context(token_ref)
        # NOTE(gyee): if public_endpoint and admin_endpoint are not set, which
        # is the default, the base url will be constructed from the environment
        # variables wsgi.url_scheme, SERVER_NAME, SERVER_PORT, and SCRIPT_NAME.
        # We have to set them in the context so the base url can be constructed
        # accordingly.
        environ = {authorization.AUTH_CONTEXT_ENV: auth_context,
                   'wsgi.url_scheme': 'http',
                   'HTTP_HOST': HOST_URL,
                   'SCRIPT_NAME': '/v3',
                   'SERVER_PORT': '80',
                   'SERVER_NAME': HOST}

        req = self.make_request(environ=environ)
        req.context_dict['token_id'] = token_id

        # NOTE(jamielennox): This wouldn't be necessary if these were calls via
        # the wsgi interface instead of directly creating a request to pass to
        # a controller.
        req.context.auth_token = token_id
        req.context.user_id = auth_context.get('user_id')
        req.context.project_id = auth_context.get('project_id')
        req.context.domain_id = auth_context.get('domain_id')
        req.context.domain_name = auth_context.get('domain_name')
        req.context.user_domain_id = auth_context.get('user_domain_id')
        req.context.roles = auth_context.get('roles')
        req.context.trust_id = auth_context.get('trust_id')
        req.context.trustor_id = auth_context.get('trustor_id')
        req.context.trustee_id = auth_context.get('trustee_id')

        return req

    def create_trust(self, trust_data, trustor_name, expires_at=None,
                     impersonation=True):
        username = trustor_name
        password = 'foo2'
        unscoped_token = self.get_unscoped_token(username, password)
        request = self._create_auth_request(
            unscoped_token['access']['token']['id'])
        trust_data_copy = copy.deepcopy(trust_data)
        trust_data_copy['expires_at'] = expires_at
        trust_data_copy['impersonation'] = impersonation

        return self.trust_controller.create_trust(
            request, trust=trust_data_copy)['trust']

    def get_unscoped_token(self, username, password='foo2'):
        body_dict = _build_user_auth(username=username, password=password)
        return self.controller.authenticate(self.make_request(), body_dict)

    def build_v2_token_request(self, username, password, trust,
                               tenant_id=None):
        if not tenant_id:
            tenant_id = self.tenant_bar['id']
        unscoped_token = self.get_unscoped_token(username, password)
        unscoped_token_id = unscoped_token['access']['token']['id']
        request_body = _build_user_auth(token={'id': unscoped_token_id},
                                        trust_id=trust['id'],
                                        tenant_id=tenant_id)
        return request_body

    def test_create_trust_bad_data_fails(self):
        unscoped_token = self.get_unscoped_token(self.trustor['name'])
        request = self._create_auth_request(
            unscoped_token['access']['token']['id'])
        bad_sample_data = {'trustor_user_id': self.trustor['id'],
                           'project_id': self.tenant_bar['id'],
                           'roles': [{'id': self.role_browser['id']}]}

        self.assertRaises(exception.ValidationError,
                          self.trust_controller.create_trust,
                          request, trust=bad_sample_data)

    def test_create_trust_no_roles(self):
        unscoped_token = self.get_unscoped_token(self.trustor['name'])
        req = self.make_request()
        req.context_dict['token_id'] = unscoped_token['access']['token']['id']
        self.sample_data['roles'] = []
        self.assertRaises(exception.Forbidden,
                          self.trust_controller.create_trust,
                          req, trust=self.sample_data)

    def test_create_trust(self):
        expires_at = (timeutils.utcnow() +
                      datetime.timedelta(minutes=10)).strftime(TIME_FORMAT)
        new_trust = self.create_trust(self.sample_data, self.trustor['name'],
                                      expires_at=expires_at)
        self.assertEqual(self.trustor['id'], new_trust['trustor_user_id'])
        self.assertEqual(self.trustee['id'], new_trust['trustee_user_id'])
        role_ids = [self.role_browser['id'], self.role_member['id']]
        self.assertTrue(timeutils.parse_strtime(new_trust['expires_at'],
                                                fmt=TIME_FORMAT))
        self.assertIn('%s/v3/OS-TRUST/' % HOST_URL,
                      new_trust['links']['self'])
        self.assertIn('%s/v3/OS-TRUST/' % HOST_URL,
                      new_trust['roles_links']['self'])

        for role in new_trust['roles']:
            self.assertIn(role['id'], role_ids)

    def test_create_trust_expires_bad(self):
        self.assertRaises(exception.ValidationTimeStampError,
                          self.create_trust, self.sample_data,
                          self.trustor['name'], expires_at="bad")
        self.assertRaises(exception.ValidationTimeStampError,
                          self.create_trust, self.sample_data,
                          self.trustor['name'], expires_at="")
        self.assertRaises(exception.ValidationTimeStampError,
                          self.create_trust, self.sample_data,
                          self.trustor['name'], expires_at="Z")

    def test_create_trust_expires_older_than_now(self):
        self.assertRaises(exception.ValidationExpirationError,
                          self.create_trust, self.sample_data,
                          self.trustor['name'],
                          expires_at="2010-06-04T08:44:31.999999Z")

    def test_create_trust_without_project_id(self):
        """Verify that trust can be created without project id.

        Also, token can be generated with that trust.
        """
        unscoped_token = self.get_unscoped_token(self.trustor['name'])
        request = self._create_auth_request(
            unscoped_token['access']['token']['id'])
        self.sample_data['project_id'] = None
        self.sample_data['roles'] = []
        new_trust = self.trust_controller.create_trust(
            request, trust=self.sample_data)['trust']
        self.assertEqual(self.trustor['id'], new_trust['trustor_user_id'])
        self.assertEqual(self.trustee['id'], new_trust['trustee_user_id'])
        self.assertIs(True, new_trust['impersonation'])
        auth_response = self.fetch_v2_token_from_trust(new_trust)
        token_user = auth_response['access']['user']
        self.assertEqual(token_user['id'], new_trust['trustor_user_id'])

    def test_get_trust(self):
        unscoped_token = self.get_unscoped_token(self.trustor['name'])
        request = self._create_auth_request(
            unscoped_token['access']['token']['id'])
        new_trust = self.trust_controller.create_trust(
            request, trust=self.sample_data)['trust']
        trust = self.trust_controller.get_trust(request,
                                                new_trust['id'])['trust']
        self.assertEqual(self.trustor['id'], trust['trustor_user_id'])
        self.assertEqual(self.trustee['id'], trust['trustee_user_id'])
        role_ids = [self.role_browser['id'], self.role_member['id']]
        for role in new_trust['roles']:
            self.assertIn(role['id'], role_ids)

    def test_create_trust_no_impersonation(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'],
                                      expires_at=None, impersonation=False)
        self.assertEqual(self.trustor['id'], new_trust['trustor_user_id'])
        self.assertEqual(self.trustee['id'], new_trust['trustee_user_id'])
        self.assertIs(False, new_trust['impersonation'])
        auth_response = self.fetch_v2_token_from_trust(new_trust)
        token_user = auth_response['access']['user']
        self.assertEqual(token_user['id'], new_trust['trustee_user_id'])

    def test_create_trust_impersonation(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        self.assertEqual(self.trustor['id'], new_trust['trustor_user_id'])
        self.assertEqual(self.trustee['id'], new_trust['trustee_user_id'])
        self.assertIs(True, new_trust['impersonation'])
        auth_response = self.fetch_v2_token_from_trust(new_trust)
        token_user = auth_response['access']['user']
        self.assertEqual(token_user['id'], new_trust['trustor_user_id'])

    def test_token_from_trust_wrong_user_fails(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        request_body = self.build_v2_token_request('FOO', 'foo2', new_trust)
        self.assertRaises(exception.Forbidden, self.controller.authenticate,
                          self.make_request(), request_body)

    def test_token_from_trust_wrong_project_fails(self):
        for assigned_role in self.assigned_roles:
            self.assignment_api.add_role_to_user_and_project(
                self.trustor['id'], self.tenant_baz['id'], assigned_role)
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        request_body = self.build_v2_token_request('TWO', 'two2', new_trust,
                                                   self.tenant_baz['id'])
        self.assertRaises(exception.Forbidden, self.controller.authenticate,
                          self.make_request(), request_body)

    def fetch_v2_token_from_trust(self, trust):
        request_body = self.build_v2_token_request('TWO', 'two2', trust)
        auth_response = self.controller.authenticate(self.make_request(),
                                                     request_body)
        return auth_response

    def fetch_v3_token_from_trust(self, trust, trustee):
        v3_password_data = {
            'identity': {
                "methods": ["password"],
                "password": {
                    "user": {
                        "id": trustee["id"],
                        "password": trustee["password"]
                    }
                }
            },
            'scope': {
                'project': {
                    'id': self.tenant_baz['id']
                }
            }
        }
        auth_response = self.auth_v3_controller.authenticate_for_token(
            self.make_request(), v3_password_data)
        token = auth_response.headers['X-Subject-Token']

        v3_req_with_trust = {
            "identity": {
                "methods": ["token"],
                "token": {"id": token}},
            "scope": {
                "OS-TRUST:trust": {"id": trust['id']}}}
        token_auth_response = self.auth_v3_controller.authenticate_for_token(
            self.make_request(), v3_req_with_trust)
        return token_auth_response

    def test_validate_v3_trust_scoped_token_against_v2_succeeds(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        auth_response = self.fetch_v3_token_from_trust(new_trust, self.trustee)
        trust_token = auth_response.headers['X-Subject-Token']
        self.controller.validate_token(self.make_request(is_admin=True),
                                       trust_token)

    def test_create_v3_token_from_trust(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        auth_response = self.fetch_v3_token_from_trust(new_trust, self.trustee)

        trust_token_user = auth_response.json['token']['user']
        self.assertEqual(self.trustor['id'], trust_token_user['id'])

        trust_token_trust = auth_response.json['token']['OS-TRUST:trust']
        self.assertEqual(trust_token_trust['id'], new_trust['id'])
        self.assertEqual(self.trustor['id'],
                         trust_token_trust['trustor_user']['id'])
        self.assertEqual(self.trustee['id'],
                         trust_token_trust['trustee_user']['id'])

        trust_token_roles = auth_response.json['token']['roles']
        self.assertEqual(2, len(trust_token_roles))

    def test_v3_trust_token_get_token_fails(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        auth_response = self.fetch_v3_token_from_trust(new_trust, self.trustee)
        trust_token = auth_response.headers['X-Subject-Token']
        v3_token_data = {'identity': {
            'methods': ['token'],
            'token': {'id': trust_token}
        }}
        self.assertRaises(
            exception.Forbidden,
            self.auth_v3_controller.authenticate_for_token,
            self.make_request(), v3_token_data)

    def test_token_from_trust(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        auth_response = self.fetch_v2_token_from_trust(new_trust)

        self.assertIsNotNone(auth_response)
        self.assertEqual(2,
                         len(auth_response['access']['metadata']['roles']),
                         "user_foo has three roles, but the token should"
                         " only get the two roles specified in the trust.")

    def assert_token_count_for_trust(self, trust, expected_value):
        tokens = self.token_provider_api._persistence._list_tokens(
            self.trustee['id'], trust_id=trust['id'])
        token_count = len(tokens)
        self.assertEqual(expected_value, token_count)

    def test_delete_tokens_for_user_invalidates_tokens_from_trust(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        self.assert_token_count_for_trust(new_trust, 0)
        self.fetch_v2_token_from_trust(new_trust)
        self.assert_token_count_for_trust(new_trust, 1)
        self.token_provider_api._persistence.delete_tokens_for_user(
            self.trustee['id'])
        self.assert_token_count_for_trust(new_trust, 0)

    def test_token_from_trust_cant_get_another_token(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        auth_response = self.fetch_v2_token_from_trust(new_trust)
        trust_token_id = auth_response['access']['token']['id']
        request_body = _build_user_auth(token={'id': trust_token_id},
                                        tenant_id=self.tenant_bar['id'])
        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, self.make_request(), request_body)

    def test_delete_trust_revokes_token(self):
        unscoped_token = self.get_unscoped_token(self.trustor['name'])
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        request = self._create_auth_request(
            unscoped_token['access']['token']['id'])
        trust_token_resp = self.fetch_v2_token_from_trust(new_trust)
        trust_scoped_token_id = trust_token_resp['access']['token']['id']
        self.controller.validate_token(
            self.make_request(is_admin=True),
            token_id=trust_scoped_token_id)
        trust_id = new_trust['id']

        self.time_fixture.advance_time_seconds(1)

        self.trust_controller.delete_trust(request, trust_id=trust_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.controller.validate_token,
            self.make_request(is_admin=True),
            token_id=trust_scoped_token_id)

    def test_token_from_trust_with_no_role_fails(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        for assigned_role in self.assigned_roles:
            self.assignment_api.remove_role_from_user_and_project(
                self.trustor['id'], self.tenant_bar['id'], assigned_role)
        request_body = self.build_v2_token_request('TWO', 'two2', new_trust)
        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, self.make_request(), request_body)

    def test_expired_trust_get_token_fails(self):
        expires_at = (timeutils.utcnow() +
                      datetime.timedelta(minutes=5)).strftime(TIME_FORMAT)
        time_expired = timeutils.utcnow() + datetime.timedelta(minutes=10)
        new_trust = self.create_trust(self.sample_data, self.trustor['name'],
                                      expires_at)
        with mock.patch.object(timeutils, 'utcnow') as mock_now:
            mock_now.return_value = time_expired
            request_body = self.build_v2_token_request('TWO', 'two2',
                                                       new_trust)
            self.assertRaises(
                exception.Forbidden,
                self.controller.authenticate,
                self.make_request(), request_body)

    def test_token_from_trust_with_wrong_role_fails(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        self.assignment_api.add_role_to_user_and_project(
            self.trustor['id'],
            self.tenant_bar['id'],
            self.role_other['id'])
        for assigned_role in self.assigned_roles:
            self.assignment_api.remove_role_from_user_and_project(
                self.trustor['id'], self.tenant_bar['id'], assigned_role)

        request_body = self.build_v2_token_request('TWO', 'two2', new_trust)

        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, self.make_request(), request_body)

    def test_do_not_consume_remaining_uses_when_get_token_fails(self):
        trust_data = copy.deepcopy(self.sample_data)
        trust_data['remaining_uses'] = 3
        new_trust = self.create_trust(trust_data, self.trustor['name'])

        for assigned_role in self.assigned_roles:
            self.assignment_api.remove_role_from_user_and_project(
                self.trustor['id'], self.tenant_bar['id'], assigned_role)

        request_body = self.build_v2_token_request('TWO', 'two2', new_trust)
        self.assertRaises(exception.Forbidden,
                          self.controller.authenticate,
                          self.make_request(),
                          request_body)

        unscoped_token = self.get_unscoped_token(self.trustor['name'])
        request = self._create_auth_request(
            unscoped_token['access']['token']['id'])
        trust = self.trust_controller.get_trust(request,
                                                new_trust['id'])['trust']
        self.assertEqual(3, trust['remaining_uses'])

    def disable_user(self, user):
        user['enabled'] = False
        self.identity_api.update_user(user['id'], user)

    def test_trust_get_token_fails_if_trustor_disabled(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        request_body = self.build_v2_token_request(self.trustee['name'],
                                                   self.trustee['password'],
                                                   new_trust)
        self.disable_user(self.trustor)
        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, self.make_request(), request_body)

    def test_trust_get_token_fails_if_trustee_disabled(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        request_body = self.build_v2_token_request(self.trustee['name'],
                                                   self.trustee['password'],
                                                   new_trust)
        self.time_fixture.advance_time_seconds(1)
        self.disable_user(self.trustee)
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate, self.make_request(), request_body)

    def test_validate_trust_scoped_token_against_v2(self):
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])
        trust_token_resp = self.fetch_v2_token_from_trust(new_trust)
        trust_scoped_token_id = trust_token_resp['access']['token']['id']
        self.controller.validate_token(self.make_request(is_admin=True),
                                       token_id=trust_scoped_token_id)

    def test_trust_get_token_fails_with_future_token_if_trustee_disabled(self):
        """Test disabling trustee and using an unrevoked token.

        This test simulates what happens when a token is generated *after* the
        disable event. Technically this should not happen, but it's possible in
        a multinode deployment with only a slight clock skew.
        """
        # We need to turn off caching here since we are bypassing the
        # identity_api to disable a user. The identity_api would typically
        # invalidate the cache when a user is disabled but it will also emit a
        # notification/callback to prune all user tokens from the backend,
        # which defeats the purpose of this test.
        self.config_fixture.config(group='identity', caching=False)

        new_trust = self.create_trust(self.sample_data, self.trustor['name'])

        # NOTE(lbragstad): We want to make sure we control the issued_at time
        # of the token.
        future_time = timeutils.utcnow() + datetime.timedelta(seconds=5)

        # get a token from the future
        with mock.patch.object(timeutils, 'utcnow', lambda: future_time):
            request_body = self.build_v2_token_request(
                self.trustee['name'], self.trustee['password'], new_trust)

        # We need to disable the user using the driver directly for the same
        # reason stated above. This test really just ensures that if a trustee
        # is disabled the logic in
        # keystone.token.controller:Auth._authenticate_token will throw an
        # Unauthorized.
        user = {'enabled': False}
        self.identity_api.driver.update_user(self.trustee['id'], user)
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate, self.make_request(), request_body)


class UUIDAuthWithTrust(AuthWithTrust, AuthTest):

    def config_overrides(self):
        super(UUIDAuthWithTrust, self).config_overrides()
        self.config_fixture.config(group='token', provider='uuid')

    def setUp(self):
        super(UUIDAuthWithTrust, self).setUp()


class FernetAuthWithTrust(AuthWithTrust, AuthTest):

    def config_overrides(self):
        super(FernetAuthWithTrust, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet',
                                   cache_on_issue=True)
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def setUp(self):
        super(FernetAuthWithTrust, self).setUp()

    def test_delete_tokens_for_user_invalidates_tokens_from_trust(self):
        # TODO(lbragstad): Rewrite this test to not rely on the persistence
        # backend. This same test can be exercised through the API.
        msg = 'The Fernet token provider does not support token persistence'
        self.skipTest(msg)

    def test_delete_trust_revokes_token(self):
        # NOTE(amakarov): have to override this for Fernet as TokenNotFound
        # can't be raised for non-persistent token, but deleted trust will
        # cause TrustNotFound exception.
        self.assertRaises(
            exception.TrustNotFound,
            super(FernetAuthWithTrust, self).test_delete_trust_revokes_token)

    def test_trust_get_token_fails_with_future_token_if_trustee_disabled(self):
        """Test disabling trustee and using an unrevoked token.

        This test simulates what happens when a Fernet token is generated
        *after* the disable event. Technically this should not happen, but
        it's possible in a multinode deployment with only a slight clock skew.
        """
        new_trust = self.create_trust(self.sample_data, self.trustor['name'])

        # NOTE(dstanek): cryptography.fernet gets it's timestamps from
        # time.time(). We need to control what it gets.
        epoch = datetime.datetime.utcfromtimestamp(0)
        future_time = (timeutils.utcnow() - epoch).total_seconds() + 5

        # get a token from the future
        with mock.patch.object(time, 'time', lambda: future_time):
            request_body = self.build_v2_token_request(
                self.trustee['name'], self.trustee['password'], new_trust)

        self.disable_user(self.trustee)
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate, self.make_request(), request_body)


class TokenExpirationTest(AuthTest):

    @mock.patch.object(timeutils, 'utcnow')
    def _maintain_token_expiration(self, mock_utcnow):
        """Token expiration should be maintained after re-auth & validation."""
        now = datetime.datetime.utcnow()
        mock_utcnow.return_value = now

        r = self.controller.authenticate(
            self.make_request(),
            auth={
                'passwordCredentials': {
                    'username': self.user_foo['name'],
                    'password': self.user_foo['password']
                }
            })
        unscoped_token_id = r['access']['token']['id']
        original_expiration = r['access']['token']['expires']

        mock_utcnow.return_value = now + datetime.timedelta(seconds=1)

        r = self.controller.validate_token(
            self.make_request(is_admin=True),
            token_id=unscoped_token_id)
        self.assertEqual(
            timeutils.parse_isotime(original_expiration),
            timeutils.parse_isotime(r['access']['token']['expires'])
        )

        mock_utcnow.return_value = now + datetime.timedelta(seconds=2)

        r = self.controller.authenticate(
            self.make_request(),
            auth={
                'token': {
                    'id': unscoped_token_id,
                },
                'tenantId': self.tenant_bar['id'],
            })
        scoped_token_id = r['access']['token']['id']
        self.assertEqual(original_expiration, r['access']['token']['expires'])

        mock_utcnow.return_value = now + datetime.timedelta(seconds=3)

        r = self.controller.validate_token(
            self.make_request(is_admin=True),
            token_id=scoped_token_id)
        self.assertEqual(
            timeutils.parse_isotime(original_expiration),
            timeutils.parse_isotime(r['access']['token']['expires'])
        )

    def test_maintain_uuid_token_expiration(self):
        self.config_fixture.config(group='token', provider='uuid')
        self._maintain_token_expiration()


class AuthCatalog(unit.SQLDriverOverrides, AuthTest):
    """Test for the catalog provided in the auth response."""

    def config_files(self):
        config_files = super(AuthCatalog, self).config_files()
        # We need to use a backend that supports disabled endpoints, like the
        # SQL backend.
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def _create_endpoints(self):
        def create_region(**kwargs):
            ref = unit.new_region_ref(**kwargs)
            self.catalog_api.create_region(ref)
            return ref

        def create_endpoint(service_id, region, **kwargs):
            endpoint = unit.new_endpoint_ref(region_id=region,
                                             service_id=service_id, **kwargs)

            self.catalog_api.create_endpoint(endpoint['id'], endpoint)
            return endpoint

        # Create a service for use with the endpoints.
        def create_service(**kwargs):
            ref = unit.new_service_ref(**kwargs)
            self.catalog_api.create_service(ref['id'], ref)
            return ref

        enabled_service_ref = create_service(enabled=True)
        disabled_service_ref = create_service(enabled=False)

        region = create_region()

        # Create endpoints
        enabled_endpoint_ref = create_endpoint(
            enabled_service_ref['id'], region['id'])
        create_endpoint(
            enabled_service_ref['id'], region['id'], enabled=False,
            interface='internal')
        create_endpoint(
            disabled_service_ref['id'], region['id'])

        return enabled_endpoint_ref

    def test_auth_catalog_disabled_endpoint(self):
        """On authenticate, get a catalog that excludes disabled endpoints."""
        endpoint_ref = self._create_endpoints()

        # Authenticate
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name="BAR")

        token = self.controller.authenticate(self.make_request(), body_dict)

        # Check the catalog
        self.assertEqual(1, len(token['access']['serviceCatalog']))
        endpoint = token['access']['serviceCatalog'][0]['endpoints'][0]
        self.assertEqual(
            1, len(token['access']['serviceCatalog'][0]['endpoints']))

        exp_endpoint = {
            'id': endpoint_ref['id'],
            'publicURL': endpoint_ref['url'],
            'region': endpoint_ref['region_id'],
        }

        self.assertEqual(exp_endpoint, endpoint)

    def test_validate_catalog_disabled_endpoint(self):
        """On validate, get back a catalog that excludes disabled endpoints."""
        endpoint_ref = self._create_endpoints()

        # Authenticate
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name="BAR")

        token = self.controller.authenticate(self.make_request(), body_dict)

        # Validate
        token_id = token['access']['token']['id']
        validate_ref = self.controller.validate_token(
            self.make_request(is_admin=True),
            token_id=token_id)

        # Check the catalog
        self.assertEqual(1, len(token['access']['serviceCatalog']))
        endpoint = validate_ref['access']['serviceCatalog'][0]['endpoints'][0]
        self.assertEqual(
            1, len(token['access']['serviceCatalog'][0]['endpoints']))

        exp_endpoint = {
            'id': endpoint_ref['id'],
            'publicURL': endpoint_ref['url'],
            'region': endpoint_ref['region_id'],
        }

        self.assertEqual(exp_endpoint, endpoint)


class NonDefaultAuthTest(unit.TestCase):

    def test_add_non_default_auth_method(self):
        self.config_fixture.config(group='auth',
                                   methods=['password', 'token', 'custom'])
        keystone.conf.auth.setup_authentication()
        self.assertTrue(hasattr(CONF.auth, 'custom'))
