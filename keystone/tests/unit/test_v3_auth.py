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
import fixtures
import itertools
import operator
import re
from unittest import mock
import uuid

import freezegun
import http.client
from oslo_serialization import jsonutils as json
from oslo_utils import fixture
from oslo_utils import timeutils
from testtools import matchers
from testtools import testcase

from keystone import auth
from keystone.auth.plugins import totp
from keystone.common import authorization
from keystone.common import provider_api
from keystone.common.rbac_enforcer import policy
from keystone.common import utils
import keystone.conf
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone.identity.backends import resource_options as ro
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TestMFARules(test_v3.RestfulTestCase):
    def config_overrides(self):
        super(TestMFARules, self).config_overrides()

        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    def assertValidErrorResponse(self, r):
        resp = r.result
        if r.headers.get(authorization.AUTH_RECEIPT_HEADER):
            self.assertIsNotNone(resp.get('receipt'))
            self.assertIsNotNone(resp.get('receipt').get('methods'))
        else:
            self.assertIsNotNone(resp.get('error'))
            self.assertIsNotNone(resp['error'].get('code'))
            self.assertIsNotNone(resp['error'].get('title'))
            self.assertIsNotNone(resp['error'].get('message'))
            self.assertEqual(int(resp['error']['code']), r.status_code)

    def _create_totp_cred(self):
        totp_cred = unit.new_totp_credential(self.user_id, self.project_id)
        PROVIDERS.credential_api.create_credential(uuid.uuid4().hex, totp_cred)

        def cleanup(testcase):
            totp_creds = testcase.credential_api.list_credentials_for_user(
                testcase.user['id'], type='totp')

            for cred in totp_creds:
                testcase.credential_api.delete_credential(cred['id'])

        self.addCleanup(cleanup, testcase=self)
        return totp_cred

    def auth_plugin_config_override(self, methods=None, **method_classes):
        methods = ['totp', 'token', 'password']
        super(TestMFARules, self).auth_plugin_config_override(methods)

    def _update_user_with_MFA_rules(self, rule_list, rules_enabled=True):
        user = self.user.copy()
        # Do not update password
        user.pop('password')
        user['options'][ro.MFA_RULES_OPT.option_name] = rule_list
        user['options'][ro.MFA_ENABLED_OPT.option_name] = rules_enabled
        PROVIDERS.identity_api.update_user(user['id'], user)

    def test_MFA_single_method_rules_requirements_met_succeeds(self):
        # ensure that a simple password works if a password-only rules exists
        rule_list = [['password'], ['password', 'totp']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id))

    def test_MFA_multi_method_rules_requirements_met_succeeds(self):
        # validate that multiple auth-methods function if all are specified
        # and the rules requires it
        rule_list = [['password', 'totp']]
        totp_cred = self._create_totp_cred()
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            auth_req = self.build_authentication_request(
                user_id=self.user_id,
                password=self.user['password'],
                user_domain_id=self.domain_id,
                passcode=totp._generate_totp_passcodes(totp_cred['blob'])[0])
            self.v3_create_token(auth_req)

    def test_MFA_single_method_rules_requirements_not_met_fails(self):
        # if a rule matching a single auth type is specified and is not matched
        # the result should be unauthorized
        rule_list = [['totp']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id),
                expected_status=http.client.UNAUTHORIZED)

    def test_MFA_multi_method_rules_requirements_not_met_fails(self):
        # if multiple rules are specified and only one is passed,
        # unauthorized is expected
        rule_list = [['password', 'totp']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id),
                expected_status=http.client.UNAUTHORIZED)

    def test_MFA_rules_bogus_non_existing_auth_method_succeeds(self):
        # Bogus auth methods are thrown out from rules.
        rule_list = [['password'], ['BoGusAuThMeTh0dHandl3r']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id))

    def test_MFA_rules_disabled_MFA_succeeeds(self):
        # ensure that if MFA is "disableD" authentication succeeds, even if
        # not enough auth methods are specified
        rule_list = [['password', 'totp']]
        self._update_user_with_MFA_rules(rule_list=rule_list,
                                         rules_enabled=False)
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        with freezegun.freeze_time(time):
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id))

    def test_MFA_rules_all_bogus_rules_results_in_default_behavior(self):
        # if all the rules are bogus, the result is the same as the default
        # behavior, any single password method is sufficient
        rule_list = [[uuid.uuid4().hex, uuid.uuid4().hex],
                     ['BoGus'],
                     ['NonExistantMethod']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id))

    def test_MFA_rules_rescope_works_without_token_method_in_rules(self):
        rule_list = [['password', 'totp']]
        totp_cred = self._create_totp_cred()
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            auth_data = self.build_authentication_request(
                user_id=self.user_id,
                password=self.user['password'],
                user_domain_id=self.domain_id,
                passcode=totp._generate_totp_passcodes(totp_cred['blob'])[0])
            r = self.v3_create_token(auth_data)
            auth_data = self.build_authentication_request(
                token=r.headers.get('X-Subject-Token'),
                project_id=self.project_id)
            self.v3_create_token(auth_data)

    def test_MFA_requirements_makes_correct_receipt_for_password(self):
        # if multiple rules are specified and only one is passed,
        # unauthorized is expected
        rule_list = [['password', 'totp']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            response = self.admin_request(
                method='POST',
                path='/v3/auth/tokens',
                body=self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id),
                expected_status=http.client.UNAUTHORIZED)

        self.assertIsNotNone(
            response.headers.get(authorization.AUTH_RECEIPT_HEADER))
        resp_data = response.result
        # NOTE(adriant): We convert to sets to avoid any potential sorting
        # related failures since order isn't important, just content.
        self.assertEqual(
            {'password'}, set(resp_data.get('receipt').get('methods')))
        self.assertEqual(
            set(frozenset(r) for r in rule_list),
            set(frozenset(r) for r in resp_data.get('required_auth_methods')))

    def test_MFA_requirements_makes_correct_receipt_for_totp(self):
        # if multiple rules are specified and only one is passed,
        # unauthorized is expected
        totp_cred = self._create_totp_cred()
        rule_list = [['password', 'totp']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            response = self.admin_request(
                method='POST',
                path='/v3/auth/tokens',
                body=self.build_authentication_request(
                    user_id=self.user_id,
                    user_domain_id=self.domain_id,
                    project_id=self.project_id,
                    passcode=totp._generate_totp_passcodes(
                        totp_cred['blob'])[0]),
                expected_status=http.client.UNAUTHORIZED)

        self.assertIsNotNone(
            response.headers.get(authorization.AUTH_RECEIPT_HEADER))
        resp_data = response.result
        # NOTE(adriant): We convert to sets to avoid any potential sorting
        # related failures since order isn't important, just content.
        self.assertEqual(
            {'totp'}, set(resp_data.get('receipt').get('methods')))
        self.assertEqual(
            set(frozenset(r) for r in rule_list),
            set(frozenset(r) for r in resp_data.get('required_auth_methods')))

    def test_MFA_requirements_makes_correct_receipt_for_pass_and_totp(self):
        # if multiple rules are specified and only one is passed,
        # unauthorized is expected
        totp_cred = self._create_totp_cred()
        rule_list = [['password', 'totp', 'token']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            response = self.admin_request(
                method='POST',
                path='/v3/auth/tokens',
                body=self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id,
                    passcode=totp._generate_totp_passcodes(
                        totp_cred['blob'])[0]),
                expected_status=http.client.UNAUTHORIZED)

        self.assertIsNotNone(
            response.headers.get(authorization.AUTH_RECEIPT_HEADER))
        resp_data = response.result
        # NOTE(adriant): We convert to sets to avoid any potential sorting
        # related failures since order isn't important, just content.
        self.assertEqual(
            {'password', 'totp'}, set(resp_data.get('receipt').get('methods')))
        self.assertEqual(
            set(frozenset(r) for r in rule_list),
            set(frozenset(r) for r in resp_data.get('required_auth_methods')))

    def test_MFA_requirements_returns_correct_required_auth_methods(self):
        # if multiple rules are specified and only one is passed,
        # unauthorized is expected
        rule_list = [
            ['password', 'totp', 'token'],
            ['password', 'totp'],
            ['token', 'totp'],
            ['BoGusAuThMeTh0dHandl3r']
        ]
        expect_rule_list = rule_list = [
            ['password', 'totp', 'token'],
            ['password', 'totp'],
        ]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            response = self.admin_request(
                method='POST',
                path='/v3/auth/tokens',
                body=self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id),
                expected_status=http.client.UNAUTHORIZED)

        self.assertIsNotNone(
            response.headers.get(authorization.AUTH_RECEIPT_HEADER))
        resp_data = response.result
        # NOTE(adriant): We convert to sets to avoid any potential sorting
        # related failures since order isn't important, just content.
        self.assertEqual(
            {'password'}, set(resp_data.get('receipt').get('methods')))
        self.assertEqual(
            set(frozenset(r) for r in expect_rule_list),
            set(frozenset(r) for r in resp_data.get('required_auth_methods')))

    def test_MFA_consuming_receipt_with_totp(self):
        # if multiple rules are specified and only one is passed,
        # unauthorized is expected
        totp_cred = self._create_totp_cred()
        rule_list = [['password', 'totp']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        # NOTE(notmorgan): Step forward in time to ensure we're not causing
        # issues with revocation events that occur at the same time as the
        # token issuance. This is a bug with the limited resolution that
        # tokens and revocation events have.
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            response = self.admin_request(
                method='POST',
                path='/v3/auth/tokens',
                body=self.build_authentication_request(
                    user_id=self.user_id,
                    password=self.user['password'],
                    user_domain_id=self.domain_id,
                    project_id=self.project_id),
                expected_status=http.client.UNAUTHORIZED)

        self.assertIsNotNone(
            response.headers.get(authorization.AUTH_RECEIPT_HEADER))
        receipt = response.headers.get(authorization.AUTH_RECEIPT_HEADER)
        resp_data = response.result
        # NOTE(adriant): We convert to sets to avoid any potential sorting
        # related failures since order isn't important, just content.
        self.assertEqual(
            {'password'}, set(resp_data.get('receipt').get('methods')))
        self.assertEqual(
            set(frozenset(r) for r in rule_list),
            set(frozenset(r) for r in resp_data.get('required_auth_methods')))

        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            response = self.admin_request(
                method='POST',
                path='/v3/auth/tokens',
                headers={authorization.AUTH_RECEIPT_HEADER: receipt},
                body=self.build_authentication_request(
                    user_id=self.user_id,
                    user_domain_id=self.domain_id,
                    project_id=self.project_id,
                    passcode=totp._generate_totp_passcodes(
                        totp_cred['blob'])[0]))

    def test_MFA_consuming_receipt_not_found(self):
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        with freezegun.freeze_time(time):
            response = self.admin_request(
                method='POST',
                path='/v3/auth/tokens',
                headers={authorization.AUTH_RECEIPT_HEADER: "bogus-receipt"},
                body=self.build_authentication_request(
                    user_id=self.user_id,
                    user_domain_id=self.domain_id,
                    project_id=self.project_id),
                expected_status=http.client.UNAUTHORIZED)
        self.assertEqual(401, response.result['error']['code'])


class TestAuthInfo(common_auth.AuthTestMixin, testcase.TestCase):
    def setUp(self):
        super(TestAuthInfo, self).setUp()
        auth.core.load_auth_methods()

    def test_unsupported_auth_method(self):
        auth_data = {'methods': ['abc']}
        auth_data['abc'] = {'test': 'test'}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.AuthMethodNotSupported,
                          auth.core.AuthInfo.create,
                          auth_data)

    def test_missing_auth_method_data(self):
        auth_data = {'methods': ['password']}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.ValidationError,
                          auth.core.AuthInfo.create,
                          auth_data)

    def test_project_name_no_domain(self):
        auth_data = self.build_authentication_request(
            username='test',
            password='test',
            project_name='abc')['auth']
        self.assertRaises(exception.ValidationError,
                          auth.core.AuthInfo.create,
                          auth_data)

    def test_both_project_and_domain_in_scope(self):
        auth_data = self.build_authentication_request(
            user_id='test',
            password='test',
            project_name='test',
            domain_name='test')['auth']
        self.assertRaises(exception.ValidationError,
                          auth.core.AuthInfo.create,
                          auth_data)

    def test_get_method_names_duplicates(self):
        auth_data = self.build_authentication_request(
            token='test',
            user_id='test',
            password='test')['auth']
        auth_data['identity']['methods'] = ['password', 'token',
                                            'password', 'password']
        auth_info = auth.core.AuthInfo.create(auth_data)
        self.assertEqual(['password', 'token'],
                         auth_info.get_method_names())

    def test_get_method_data_invalid_method(self):
        auth_data = self.build_authentication_request(
            user_id='test',
            password='test')['auth']
        auth_info = auth.core.AuthInfo.create(auth_data)

        method_name = uuid.uuid4().hex
        self.assertRaises(exception.ValidationError,
                          auth_info.get_method_data,
                          method_name)


class TokenAPITests(object):
    # Why is this not just setUp? Because TokenAPITests is not a test class
    # itself. If TokenAPITests became a subclass of the testcase, it would get
    # called by the enumerate-tests-in-file code. The way the functions get
    # resolved in Python for multiple inheritance means that a setUp in this
    # would get skipped by the testrunner.
    def doSetUp(self):
        r = self.v3_create_token(self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain_id,
            password=self.user['password']))
        self.v3_token_data = r.result
        self.v3_token = r.headers.get('X-Subject-Token')
        self.headers = {'X-Subject-Token': r.headers.get('X-Subject-Token')}

    def _get_unscoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)
        return r.headers.get('X-Subject-Token')

    def _get_domain_scoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain_id)
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)
        return r.headers.get('X-Subject-Token')

    def _get_project_scoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project_id)
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)
        return r.headers.get('X-Subject-Token')

    def _get_trust_scoped_token(self, trustee_user, trust):
        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)
        return r.headers.get('X-Subject-Token')

    def _create_trust(self, impersonation=False):
        # Create a trustee user
        trustee_user = unit.create_user(PROVIDERS.identity_api,
                                        domain_id=self.domain_id)
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=trustee_user['id'],
            project_id=self.project_id,
            impersonation=impersonation,
            role_ids=[self.role_id])

        # Create a trust
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        return (trustee_user, trust)

    def _validate_token(self, token,
                        expected_status=http.client.OK, allow_expired=False):
        path = '/v3/auth/tokens'

        if allow_expired:
            path += '?allow_expired=1'

        return self.admin_request(
            path=path,
            headers={'X-Auth-Token': self.get_admin_token(),
                     'X-Subject-Token': token},
            method='GET',
            expected_status=expected_status
        )

    def _revoke_token(self, token, expected_status=http.client.NO_CONTENT):
        return self.delete(
            '/auth/tokens',
            headers={'x-subject-token': token},
            expected_status=expected_status)

    def _set_user_enabled(self, user, enabled=True):
        user['enabled'] = enabled
        PROVIDERS.identity_api.update_user(user['id'], user)

    def _create_project_and_set_as_default_project(self):
        # create a new project
        ref = unit.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)

        # grant the user a role on the project
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'user_id': self.user['id'],
                'project_id': project['id'],
                'role_id': self.role['id']})

        # make the new project the user's default project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body=body)
        self.assertValidUserResponse(r)

        return project

    def test_auth_with_token_as_different_user_fails(self):
        # get the token for a user. This is self.user which is different from
        # self.default_domain_user.
        token = self.get_scoped_token()
        # try both password and token methods with different identities and it
        # should fail
        auth_data = self.build_authentication_request(
            token=token,
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_token_for_user_without_password_fails(self):
        user = unit.new_user_ref(domain_id=self.domain['id'])
        del user['password']  # can't have a password for this test
        user = PROVIDERS.identity_api.create_user(user)

        auth_data = self.build_authentication_request(
            user_id=user['id'],
            password='password')

        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_unscoped_token_by_authenticating_with_unscoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)
        token_id = r.headers.get('X-Subject-Token')

        auth_data = self.build_authentication_request(token=token_id)
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_create_unscoped_token_with_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_create_unscoped_token_with_user_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_create_unscoped_token_with_user_domain_name(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_validate_unscoped_token(self):
        unscoped_token = self._get_unscoped_token()
        r = self._validate_token(unscoped_token)
        self.assertValidUnscopedTokenResponse(r)

    def test_validate_expired_unscoped_token_returns_not_found(self):
        # NOTE(lbragstad): We set token expiration to 10 seconds so that we can
        # use the context manager of freezegun without sqlite issues.
        self.config_fixture.config(group='token',
                                   expiration=10)
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            unscoped_token = self._get_unscoped_token()
            frozen_datetime.tick(delta=datetime.timedelta(seconds=15))
            self._validate_token(
                unscoped_token,
                expected_status=http.client.NOT_FOUND
            )

    def test_revoke_unscoped_token(self):
        unscoped_token = self._get_unscoped_token()
        r = self._validate_token(unscoped_token)
        self.assertValidUnscopedTokenResponse(r)
        self._revoke_token(unscoped_token)
        self._validate_token(unscoped_token,
                             expected_status=http.client.NOT_FOUND)

    def test_create_explicit_unscoped_token(self):
        self._create_project_and_set_as_default_project()

        # explicitly ask for an unscoped token
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            unscoped="unscoped")
        r = self.post('/auth/tokens', body=auth_data, noauth=True)
        self.assertValidUnscopedTokenResponse(r)

    def test_disabled_users_default_project_result_in_unscoped_token(self):
        # create a disabled project to work with
        project = self.create_new_default_project_for_user(
            self.user['id'], self.domain_id, enable_project=False)

        # assign a role to user for the new project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user['id'], project['id'], self.role_id
        )

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_disabled_default_project_domain_result_in_unscoped_token(self):
        domain_ref = unit.new_domain_ref()
        r = self.post('/domains', body={'domain': domain_ref})
        domain = self.assertValidDomainResponse(r, domain_ref)

        project = self.create_new_default_project_for_user(
            self.user['id'], domain['id'])

        # assign a role to user for the new project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user['id'], project['id'], self.role_id
        )

        # now disable the project domain
        body = {'domain': {'enabled': False}}
        r = self.patch('/domains/%(domain_id)s' % {'domain_id': domain['id']},
                       body=body)
        self.assertValidDomainResponse(r)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_unscoped_token_is_invalid_after_disabling_user(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        r = self._validate_token(unscoped_token)
        self.assertValidUnscopedTokenResponse(r)
        # Disable the user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            unscoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_unscoped_token_is_invalid_after_enabling_disabled_user(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        r = self._validate_token(unscoped_token)
        self.assertValidUnscopedTokenResponse(r)
        # Disable the user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            unscoped_token,
            expected_status=http.client.NOT_FOUND
        )
        # Enable the user
        self._set_user_enabled(self.user)
        # Ensure validating a token for a re-enabled user fails
        self._validate_token(
            unscoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_unscoped_token_is_invalid_after_disabling_user_domain(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        r = self._validate_token(unscoped_token)
        self.assertValidUnscopedTokenResponse(r)
        # Disable the user's domain
        self.domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(self.domain['id'], self.domain)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            unscoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_unscoped_token_is_invalid_after_changing_user_password(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        r = self._validate_token(unscoped_token)
        self.assertValidUnscopedTokenResponse(r)
        # Change user's password
        self.user['password'] = 'Password1'
        PROVIDERS.identity_api.update_user(self.user['id'], self.user)
        # Ensure updating user's password revokes existing user's tokens
        self._validate_token(
            unscoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_create_system_token_with_user_id(self):
        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            system=True
        )

        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)

    def test_create_system_token_with_username(self):
        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            username=self.user['name'],
            password=self.user['password'],
            user_domain_id=self.domain['id'],
            system=True
        )

        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)

    def test_create_system_token_fails_without_system_assignment(self):
        auth_request_body = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            system=True
        )
        self.v3_create_token(
            auth_request_body,
            expected_status=http.client.UNAUTHORIZED
        )

    def test_system_token_is_invalid_after_disabling_user(self):
        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            username=self.user['name'],
            password=self.user['password'],
            user_domain_id=self.domain['id'],
            system=True
        )

        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)
        token = response.headers.get('X-Subject-Token')
        self._validate_token(token)

        # NOTE(lbragstad): This would make a good test for groups, but
        # apparently it's not possible to disable a group.
        user_ref = {
            'user': {
                'enabled': False
            }
        }
        self.patch(
            '/users/%(user_id)s' % {'user_id': self.user['id']},
            body=user_ref
        )

        self.admin_request(
            path='/v3/auth/tokens',
            headers={'X-Auth-Token': token,
                     'X-Subject-Token': token},
            method='GET',
            expected_status=http.client.UNAUTHORIZED
        )
        self.admin_request(
            path='/v3/auth/tokens',
            headers={'X-Auth-Token': token,
                     'X-Subject-Token': token},
            method='HEAD',
            expected_status=http.client.UNAUTHORIZED
        )

    def test_create_system_token_via_system_group_assignment(self):
        ref = {
            'group': unit.new_group_ref(
                domain_id=CONF.identity.default_domain_id
            )
        }

        group = self.post('/groups', body=ref).json_body['group']
        path = '/system/groups/%(group_id)s/roles/%(role_id)s' % {
            'group_id': group['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        path = '/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': group['id'],
            'user_id': self.user['id']
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            system=True
        )
        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)
        token = response.headers.get('X-Subject-Token')
        self._validate_token(token)

    def test_revoke_system_token(self):
        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            username=self.user['name'],
            password=self.user['password'],
            user_domain_id=self.domain['id'],
            system=True
        )

        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)
        token = response.headers.get('X-Subject-Token')
        self._validate_token(token)
        self._revoke_token(token)
        self._validate_token(token, expected_status=http.client.NOT_FOUND)

    def test_system_token_is_invalid_after_deleting_system_role(self):
        ref = {'role': unit.new_role_ref()}
        system_role = self.post('/roles', body=ref).json_body['role']

        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role['id']
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            username=self.user['name'],
            password=self.user['password'],
            user_domain_id=self.domain['id'],
            system=True
        )

        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)
        token = response.headers.get('X-Subject-Token')
        self._validate_token(token)

        self.delete('/roles/%(role_id)s' % {'role_id': system_role['id']})
        self._validate_token(token, expected_status=http.client.NOT_FOUND)

    def test_rescoping_a_system_token_for_a_project_token_fails(self):
        ref = {'role': unit.new_role_ref()}
        system_role = self.post('/roles', body=ref).json_body['role']

        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role['id']
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            username=self.user['name'],
            password=self.user['password'],
            user_domain_id=self.domain['id'],
            system=True
        )
        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)
        system_token = response.headers.get('X-Subject-Token')

        auth_request_body = self.build_authentication_request(
            token=system_token, project_id=self.project_id
        )
        self.v3_create_token(
            auth_request_body, expected_status=http.client.FORBIDDEN
        )

    def test_rescoping_a_system_token_for_a_domain_token_fails(self):
        ref = {'role': unit.new_role_ref()}
        system_role = self.post('/roles', body=ref).json_body['role']

        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': system_role['id']
        }
        self.put(path=path)

        auth_request_body = self.build_authentication_request(
            username=self.user['name'],
            password=self.user['password'],
            user_domain_id=self.domain['id'],
            system=True
        )
        response = self.v3_create_token(auth_request_body)
        self.assertValidSystemScopedTokenResponse(response)
        system_token = response.headers.get('X-Subject-Token')

        auth_request_body = self.build_authentication_request(
            token=system_token, domain_id=CONF.identity.default_domain_id
        )
        self.v3_create_token(
            auth_request_body, expected_status=http.client.FORBIDDEN
        )

    def test_create_domain_token_scoped_with_domain_id_and_user_id(self):
        # grant the user a role on the domain
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_create_domain_token_scoped_with_domain_id_and_username(self):
        # grant the user a role on the domain
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_create_domain_token_scoped_with_domain_id(self):
        # grant the user a role on the domain
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_create_domain_token_scoped_with_domain_name(self):
        # grant the user a role on the domain
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.v3_create_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_create_domain_token_scoped_with_domain_name_and_username(self):
        # grant the user a role on the domain
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.v3_create_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_create_domain_token_with_only_domain_name_and_username(self):
        # grant the user a role on the domain
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.v3_create_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_create_domain_token_with_group_role(self):
        group = unit.new_group_ref(domain_id=self.domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        # add user to group
        PROVIDERS.identity_api.add_user_to_group(self.user['id'], group['id'])

        # grant the domain role to group
        path = '/domains/%s/groups/%s/roles/%s' % (
            self.domain['id'], group['id'], self.role['id'])
        self.put(path=path)

        # now get a domain-scoped token
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_create_domain_token_fails_if_domain_name_unsafe(self):
        """Verify authenticate to a domain with unsafe name fails."""
        # Start with url name restrictions off, so we can create the unsafe
        # named domain
        self.config_fixture.config(group='resource',
                                   domain_name_url_safe='off')
        unsafe_name = 'i am not / safe'
        domain = unit.new_domain_ref(name=unsafe_name)
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.create_grant(
            role_member['id'],
            user_id=self.user['id'],
            domain_id=domain['id'])

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=domain['name'])

        # Since name url restriction is off, we should be able to authenticate
        self.v3_create_token(auth_data)

        # Set the name url restriction to new, which should still allow us to
        # authenticate
        self.config_fixture.config(group='resource',
                                   project_name_url_safe='new')
        self.v3_create_token(auth_data)

        # Set the name url restriction to strict and we should fail to
        # authenticate
        self.config_fixture.config(group='resource',
                                   domain_name_url_safe='strict')
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_domain_token_without_grant_returns_unauthorized(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        # this fails because the user does not have a role on self.domain
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_validate_domain_scoped_token(self):
        # Grant user access to domain
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domain['id']
        )
        domain_scoped_token = self._get_domain_scoped_token()
        r = self._validate_token(domain_scoped_token)
        self.assertValidDomainScopedTokenResponse(r)
        resp_json = json.loads(r.body)
        self.assertIsNotNone(resp_json['token']['catalog'])
        self.assertIsNotNone(resp_json['token']['roles'])
        self.assertIsNotNone(resp_json['token']['domain'])

    def test_validate_expired_domain_scoped_token_returns_not_found(self):
        # Grant user access to domain
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domain['id']
        )
        # NOTE(lbragstad): We set token expiration to 10 seconds so that we can
        # use the context manager of freezegun without sqlite issues.
        self.config_fixture.config(group='token',
                                   expiration=10)
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            domain_scoped_token = self._get_domain_scoped_token()
            frozen_datetime.tick(delta=datetime.timedelta(seconds=15))
            self._validate_token(
                domain_scoped_token,
                expected_status=http.client.NOT_FOUND
            )

    def test_domain_scoped_token_is_invalid_after_disabling_user(self):
        # Grant user access to domain
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domain['id']
        )
        domain_scoped_token = self._get_domain_scoped_token()
        # Make sure the token is valid
        r = self._validate_token(domain_scoped_token)
        self.assertValidDomainScopedTokenResponse(r)
        # Disable user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            domain_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_domain_scoped_token_is_invalid_after_deleting_grant(self):
        # Grant user access to domain
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domain['id']
        )
        domain_scoped_token = self._get_domain_scoped_token()
        # Make sure the token is valid
        r = self._validate_token(domain_scoped_token)
        self.assertValidDomainScopedTokenResponse(r)
        # Delete access to domain
        PROVIDERS.assignment_api.delete_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domain['id']
        )
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            domain_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_domain_scoped_token_invalid_after_disabling_domain(self):
        # Grant user access to domain
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domain['id']
        )
        domain_scoped_token = self._get_domain_scoped_token()
        # Make sure the token is valid
        r = self._validate_token(domain_scoped_token)
        self.assertValidDomainScopedTokenResponse(r)
        # Disable domain
        self.domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(self.domain['id'], self.domain)
        # Ensure validating a token for a disabled domain fails
        self._validate_token(
            domain_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_create_project_scoped_token_with_project_id_and_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_validate_project_scoped_token(self):
        project_scoped_token = self._get_project_scoped_token()
        r = self._validate_token(project_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

    def test_validate_expired_project_scoped_token_returns_not_found(self):
        # NOTE(lbragstad): We set token expiration to 10 seconds so that we can
        # use the context manager of freezegun without sqlite issues.
        self.config_fixture.config(group='token',
                                   expiration=10)
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            project_scoped_token = self._get_project_scoped_token()
            frozen_datetime.tick(delta=datetime.timedelta(seconds=15))
            self._validate_token(
                project_scoped_token,
                expected_status=http.client.NOT_FOUND
            )

    def test_revoke_project_scoped_token(self):
        project_scoped_token = self._get_project_scoped_token()
        r = self._validate_token(project_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)
        self._revoke_token(project_scoped_token)
        self._validate_token(project_scoped_token,
                             expected_status=http.client.NOT_FOUND)

    def test_project_scoped_token_is_scoped_to_default_project(self):
        project = self._create_project_and_set_as_default_project()

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)

        # ensure the project id in the token matches the default project id
        self.assertValidProjectScopedTokenResponse(r)
        self.assertEqual(project['id'], r.result['token']['project']['id'])

    def test_project_scoped_token_no_catalog_is_scoped_to_default_project(
            self):
        project = self._create_project_and_set_as_default_project()

        # attempt to authenticate without requesting a project or catalog
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data, noauth=True)

        # ensure the project id in the token matches the default project id
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)
        self.assertEqual(project['id'], r.result['token']['project']['id'])

    def test_implicit_project_id_scoped_token_with_user_id_no_catalog(self):
        self._create_project_and_set_as_default_project()

        # create a project scoped token that isn't scoped to the default
        # project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data, noauth=True)

        # ensure the project id in the token matches the one we as for
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)
        self.assertEqual(self.project['id'],
                         r.result['token']['project']['id'])

    def test_project_scoped_token_catalog_attributes(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_create_token(auth_data)

        catalog = r.result['token']['catalog']
        self.assertEqual(1, len(catalog))
        catalog = catalog[0]

        self.assertEqual(self.service['id'], catalog['id'])
        self.assertEqual(self.service['name'], catalog['name'])
        self.assertEqual(self.service['type'], catalog['type'])

        endpoint = catalog['endpoints']
        self.assertEqual(1, len(endpoint))
        endpoint = endpoint[0]

        self.assertEqual(self.endpoint['id'], endpoint['id'])
        self.assertEqual(self.endpoint['interface'], endpoint['interface'])
        self.assertEqual(self.endpoint['region_id'], endpoint['region_id'])
        self.assertEqual(self.endpoint['url'], endpoint['url'])

    def test_project_scoped_token_catalog_excludes_disabled_endpoint(self):
        # Create a disabled endpoint
        disabled_endpoint_ref = copy.copy(self.endpoint)
        disabled_endpoint_id = uuid.uuid4().hex
        disabled_endpoint_ref.update({
            'id': disabled_endpoint_id,
            'enabled': False,
            'interface': 'internal'
        })
        PROVIDERS.catalog_api.create_endpoint(
            disabled_endpoint_id, disabled_endpoint_ref
        )

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        resp = self.v3_create_token(auth_data)

        # make sure the disabled endpoint id isn't in the list of endpoints
        endpoints = resp.result['token']['catalog'][0]['endpoints']
        endpoint_ids = [endpoint['id'] for endpoint in endpoints]
        self.assertNotIn(disabled_endpoint_id, endpoint_ids)

    def test_project_scoped_token_catalog_excludes_disabled_service(self):
        """On authenticate, get a catalog that excludes disabled services."""
        # although the endpoint associated with the service is enabled, the
        # service is disabled
        self.assertTrue(self.endpoint['enabled'])
        PROVIDERS.catalog_api.update_service(
            self.endpoint['service_id'], {'enabled': False})
        service = PROVIDERS.catalog_api.get_service(
            self.endpoint['service_id']
        )
        self.assertFalse(service['enabled'])

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_create_token(auth_data)

        self.assertEqual([], r.result['token']['catalog'])

    def test_scope_to_project_without_grant_returns_unauthorized(self):
        project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=project['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_project_scoped_token_with_username_and_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_create_project_scoped_token_with_username_and_domain_name(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_create_project_scoped_token_fails_if_project_name_unsafe(self):
        """Verify authenticate to a project with unsafe name fails."""
        # Start with url name restrictions off, so we can create the unsafe
        # named project
        self.config_fixture.config(group='resource',
                                   project_name_url_safe='off')
        unsafe_name = 'i am not / safe'
        project = unit.new_project_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID,
                                       name=unsafe_name)
        PROVIDERS.resource_api.create_project(project['id'], project)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user['id'], project['id'], role_member['id'])

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_name=project['name'],
            project_domain_id=test_v3.DEFAULT_DOMAIN_ID)

        # Since name url restriction is off, we should be able to authenticate
        self.v3_create_token(auth_data)

        # Set the name url restriction to new, which should still allow us to
        # authenticate
        self.config_fixture.config(group='resource',
                                   project_name_url_safe='new')
        self.v3_create_token(auth_data)

        # Set the name url restriction to strict and we should fail to
        # authenticate
        self.config_fixture.config(group='resource',
                                   project_name_url_safe='strict')
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_project_scoped_token_fails_if_domain_name_unsafe(self):
        """Verify authenticate to a project using unsafe domain name fails."""
        # Start with url name restrictions off, so we can create the unsafe
        # named domain
        self.config_fixture.config(group='resource',
                                   domain_name_url_safe='off')
        unsafe_name = 'i am not / safe'
        domain = unit.new_domain_ref(name=unsafe_name)
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        # Add a (safely named) project to that domain
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.create_grant(
            role_member['id'],
            user_id=self.user['id'],
            project_id=project['id'])

        # An auth request via project ID, but specifying domain by name
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_name=project['name'],
            project_domain_name=domain['name'])

        # Since name url restriction is off, we should be able to authenticate
        self.v3_create_token(auth_data)

        # Set the name url restriction to new, which should still allow us to
        # authenticate
        self.config_fixture.config(group='resource',
                                   project_name_url_safe='new')
        self.v3_create_token(auth_data)

        # Set the name url restriction to strict and we should fail to
        # authenticate
        self.config_fixture.config(group='resource',
                                   domain_name_url_safe='strict')
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_project_token_with_same_domain_and_project_name(self):
        """Authenticate to a project with the same name as its domain."""
        domain = unit.new_project_ref(is_domain=True)
        domain = PROVIDERS.resource_api.create_project(domain['id'], domain)
        project = unit.new_project_ref(domain_id=domain['id'],
                                       name=domain['name'])
        PROVIDERS.resource_api.create_project(project['id'], project)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user['id'], project['id'], role_member['id'])

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_name=project['name'],
            project_domain_name=domain['name'])

        r = self.v3_create_token(auth_data)
        self.assertEqual(project['id'], r.result['token']['project']['id'])

    def test_create_project_token_fails_with_project_acting_as_domain(self):
        domain = unit.new_project_ref(is_domain=True)
        domain = PROVIDERS.resource_api.create_project(domain['id'], domain)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.create_grant(
            role_member['id'],
            user_id=self.user['id'],
            domain_id=domain['id'])

        # authentication will fail because the project name is incorrect
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_name=domain['name'],
            project_domain_name=domain['name'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_project_token_with_disabled_project_domain_fails(self):
        # create a disabled domain
        domain = unit.new_domain_ref()
        domain = PROVIDERS.resource_api.create_domain(domain['id'], domain)

        # create a project in the domain
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)

        # assign some role to self.user for the project in the domain
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user['id'],
            project['id'],
            self.role_id)

        # Disable the domain
        domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain['id'], domain)

        # user should not be able to auth with project_id
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=project['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        # user should not be able to auth with project_name & domain
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_name=project['name'],
            project_domain_id=domain['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_project_token_with_default_domain_as_project(self):
        # Authenticate to a project with the default domain as project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=test_v3.DEFAULT_DOMAIN_ID)
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_project_scoped_token_is_invalid_after_disabling_user(self):
        project_scoped_token = self._get_project_scoped_token()
        # Make sure the token is valid
        r = self._validate_token(project_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)
        # Disable the user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            project_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_project_scoped_token_invalid_after_changing_user_password(self):
        project_scoped_token = self._get_project_scoped_token()
        # Make sure the token is valid
        r = self._validate_token(project_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)
        # Update user's password
        self.user['password'] = 'Password1'
        PROVIDERS.identity_api.update_user(self.user['id'], self.user)
        # Ensure updating user's password revokes existing tokens
        self._validate_token(
            project_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_project_scoped_token_invalid_after_disabling_project(self):
        project_scoped_token = self._get_project_scoped_token()
        # Make sure the token is valid
        r = self._validate_token(project_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)
        # Disable project
        self.project['enabled'] = False
        PROVIDERS.resource_api.update_project(self.project['id'], self.project)
        # Ensure validating a token for a disabled project fails
        self._validate_token(
            project_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_project_scoped_token_is_invalid_after_deleting_grant(self):
        # disable caching so that user grant deletion is not hidden
        # by token caching
        self.config_fixture.config(
            group='cache',
            enabled=False)
        # Grant user access to project
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            project_id=self.project['id']
        )
        project_scoped_token = self._get_project_scoped_token()
        # Make sure the token is valid
        r = self._validate_token(project_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)
        # Delete access to project
        PROVIDERS.assignment_api.delete_grant(
            self.role['id'], user_id=self.user['id'],
            project_id=self.project['id']
        )
        # Ensure the token has been revoked
        self._validate_token(
            project_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_no_access_to_default_project_result_in_unscoped_token(self):
        # create a disabled project to work with
        self.create_new_default_project_for_user(self.user['id'],
                                                 self.domain_id)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_create_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_rescope_unscoped_token_with_trust(self):
        trustee_user, trust = self._create_trust()
        self._get_trust_scoped_token(trustee_user, trust)

    def test_validate_a_trust_scoped_token(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

    def test_validate_expired_trust_scoped_token_returns_not_found(self):
        # NOTE(lbragstad): We set token expiration to 10 seconds so that we can
        # use the context manager of freezegun without sqlite issues.
        self.config_fixture.config(group='token',
                                   expiration=10)
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            trustee_user, trust = self._create_trust()
            trust_scoped_token = self._get_trust_scoped_token(
                trustee_user, trust
            )
            frozen_datetime.tick(delta=datetime.timedelta(seconds=15))
            self._validate_token(
                trust_scoped_token,
                expected_status=http.client.NOT_FOUND
            )

    def test_validate_a_trust_scoped_token_impersonated(self):
        trustee_user, trust = self._create_trust(impersonation=True)
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

    def test_revoke_trust_scoped_token(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)
        self._revoke_token(trust_scoped_token)
        self._validate_token(trust_scoped_token,
                             expected_status=http.client.NOT_FOUND)

    def test_trust_scoped_token_is_invalid_after_disabling_trustee(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

        # Disable trustee
        trustee_update_ref = dict(enabled=False)
        PROVIDERS.identity_api.update_user(
            trustee_user['id'], trustee_update_ref
        )
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            trust_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_trust_token_is_invalid_when_trustee_domain_disabled(self):
        # create a new domain with new user in that domain
        new_domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(
            new_domain_ref['id'], new_domain_ref
        )

        trustee_ref = unit.create_user(PROVIDERS.identity_api,
                                       domain_id=new_domain_ref['id'])

        new_project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(
            new_project_ref['id'], new_project_ref
        )

        # grant the trustor access to the new project
        PROVIDERS.assignment_api.create_grant(
            self.role['id'],
            user_id=self.user_id,
            project_id=new_project_ref['id'])

        trust_ref = unit.new_trust_ref(trustor_user_id=self.user_id,
                                       trustee_user_id=trustee_ref['id'],
                                       expires=dict(minutes=1),
                                       project_id=new_project_ref['id'],
                                       impersonation=True,
                                       role_ids=[self.role['id']])

        resp = self.post('/OS-TRUST/trusts', body={'trust': trust_ref})
        self.assertValidTrustResponse(resp, trust_ref)
        trust_id = resp.json_body['trust']['id']

        # get a project-scoped token using the trust
        trust_auth_data = self.build_authentication_request(
            user_id=trustee_ref['id'],
            password=trustee_ref['password'],
            trust_id=trust_id)
        trust_scoped_token = self.get_requested_token(trust_auth_data)

        # ensure the project-scoped token from the trust is valid
        self._validate_token(trust_scoped_token)

        disable_body = {'domain': {'enabled': False}}
        self.patch(
            '/domains/%(domain_id)s' % {'domain_id': new_domain_ref['id']},
            body=disable_body)

        # ensure the project-scoped token from the trust is invalid
        self._validate_token(trust_scoped_token,
                             expected_status=http.client.NOT_FOUND)

    def test_trust_scoped_token_invalid_after_changing_trustee_password(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)
        # Change trustee's password
        trustee_update_ref = dict(password='Password1')
        PROVIDERS.identity_api.update_user(
            trustee_user['id'], trustee_update_ref
        )
        # Ensure updating trustee's password revokes existing tokens
        self._validate_token(
            trust_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_trust_scoped_token_is_invalid_after_disabling_trustor(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

        # Disable the trustor
        trustor_update_ref = dict(enabled=False)
        PROVIDERS.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            trust_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_trust_scoped_token_invalid_after_changing_trustor_password(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

        # Change trustor's password
        trustor_update_ref = dict(password='Password1')
        PROVIDERS.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure updating trustor's password revokes existing user's tokens
        self._validate_token(
            trust_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_trust_scoped_token_invalid_after_disabled_trustor_domain(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

        # Disable trustor's domain
        self.domain['enabled'] = False
        PROVIDERS.resource_api.update_domain(self.domain['id'], self.domain)

        trustor_update_ref = dict(password='Password1')
        PROVIDERS.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure updating trustor's password revokes existing user's tokens
        self._validate_token(
            trust_scoped_token,
            expected_status=http.client.NOT_FOUND
        )

    def test_default_fixture_scope_token(self):
        self.assertIsNotNone(self.get_scoped_token())

    def test_rescoping_token(self):
        expires = self.v3_token_data['token']['expires_at']

        # rescope the token
        r = self.v3_create_token(self.build_authentication_request(
            token=self.v3_token,
            project_id=self.project_id))
        self.assertValidProjectScopedTokenResponse(r)

        # ensure token expiration stayed the same
        self.assertTimestampEqual(expires, r.result['token']['expires_at'])

    def test_check_token(self):
        self.head('/auth/tokens', headers=self.headers,
                  expected_status=http.client.OK)

    def test_validate_token(self):
        r = self.get('/auth/tokens', headers=self.headers)
        self.assertValidUnscopedTokenResponse(r)

    def test_validate_missing_subject_token(self):
        self.get('/auth/tokens',
                 expected_status=http.client.NOT_FOUND)

    def test_validate_missing_auth_token(self):
        self.admin_request(
            method='GET',
            path='/v3/projects',
            token=None,
            expected_status=http.client.UNAUTHORIZED)

    def test_validate_token_nocatalog(self):
        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id']))
        r = self.get(
            '/auth/tokens?nocatalog',
            headers={'X-Subject-Token': v3_token})
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)

    def test_is_admin_token_by_ids(self):
        self.config_fixture.config(
            group='resource',
            admin_project_domain_name=self.domain['name'],
            admin_project_name=self.project['name'])
        r = self.v3_create_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id']))
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=True)
        v3_token = r.headers.get('X-Subject-Token')
        r = self.get('/auth/tokens', headers={'X-Subject-Token': v3_token})
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=True)

    def test_is_admin_token_by_names(self):
        self.config_fixture.config(
            group='resource',
            admin_project_domain_name=self.domain['name'],
            admin_project_name=self.project['name'])
        r = self.v3_create_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_domain_name=self.domain['name'],
            project_name=self.project['name']))
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=True)
        v3_token = r.headers.get('X-Subject-Token')
        r = self.get('/auth/tokens', headers={'X-Subject-Token': v3_token})
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=True)

    def test_token_for_non_admin_project_is_not_admin(self):
        self.config_fixture.config(
            group='resource',
            admin_project_domain_name=self.domain['name'],
            admin_project_name=uuid.uuid4().hex)
        r = self.v3_create_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id']))
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=False)
        v3_token = r.headers.get('X-Subject-Token')
        r = self.get('/auth/tokens', headers={'X-Subject-Token': v3_token})
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=False)

    def test_token_for_non_admin_domain_same_project_name_is_not_admin(self):
        self.config_fixture.config(
            group='resource',
            admin_project_domain_name=uuid.uuid4().hex,
            admin_project_name=self.project['name'])
        r = self.v3_create_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id']))
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=False)
        v3_token = r.headers.get('X-Subject-Token')
        r = self.get('/auth/tokens', headers={'X-Subject-Token': v3_token})
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=False)

    def test_only_admin_project_set_acts_as_non_admin(self):
        self.config_fixture.config(
            group='resource',
            admin_project_name=self.project['name'])
        r = self.v3_create_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id']))
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=None)
        v3_token = r.headers.get('X-Subject-Token')
        r = self.get('/auth/tokens', headers={'X-Subject-Token': v3_token})
        self.assertValidProjectScopedTokenResponse(r, is_admin_project=None)

    def _create_role(self, domain_id=None):
        """Call ``POST /roles``."""
        ref = unit.new_role_ref(domain_id=domain_id)
        r = self.post('/roles', body={'role': ref})
        return self.assertValidRoleResponse(r, ref)

    def _create_implied_role(self, prior_id):
        implied = self._create_role()
        url = '/roles/%s/implies/%s' % (prior_id, implied['id'])
        self.put(url, expected_status=http.client.CREATED)
        return implied

    def _delete_implied_role(self, prior_role_id, implied_role_id):
        url = '/roles/%s/implies/%s' % (prior_role_id, implied_role_id)
        self.delete(url)

    def _get_scoped_token_roles(self, is_domain=False):
        if is_domain:
            v3_token = self.get_domain_scoped_token()
        else:
            v3_token = self.get_scoped_token()

        r = self.get('/auth/tokens', headers={'X-Subject-Token': v3_token})
        v3_token_data = r.result
        token_roles = v3_token_data['token']['roles']
        return token_roles

    def _create_implied_role_shows_in_v3_token(self, is_domain):
        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(1, len(token_roles))

        prior = token_roles[0]['id']
        implied1 = self._create_implied_role(prior)

        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(2, len(token_roles))

        implied2 = self._create_implied_role(prior)
        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(3, len(token_roles))

        token_role_ids = [role['id'] for role in token_roles]
        self.assertIn(prior, token_role_ids)
        self.assertIn(implied1['id'], token_role_ids)
        self.assertIn(implied2['id'], token_role_ids)

    def test_create_implied_role_shows_in_v3_project_token(self):
        # regardless of the default chosen, this should always
        # test with the option set.
        self.config_fixture.config(group='token')
        self._create_implied_role_shows_in_v3_token(False)

    def test_create_implied_role_shows_in_v3_domain_token(self):
        self.config_fixture.config(group='token')
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domain['id']
        )

        self._create_implied_role_shows_in_v3_token(True)

    def test_create_implied_role_shows_in_v3_system_token(self):
        self.config_fixture.config(group='token')
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user['id'], self.role['id']
        )

        token_id = self.get_system_scoped_token()
        r = self.get('/auth/tokens', headers={'X-Subject-Token': token_id})
        token_roles = r.result['token']['roles']

        prior = token_roles[0]['id']
        self._create_implied_role(prior)

        r = self.get('/auth/tokens', headers={'X-Subject-Token': token_id})
        token_roles = r.result['token']['roles']
        self.assertEqual(2, len(token_roles))

    def test_group_assigned_implied_role_shows_in_v3_token(self):
        self.config_fixture.config(group='token')
        is_domain = False
        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(1, len(token_roles))

        new_role = self._create_role()
        prior = new_role['id']

        new_group_ref = unit.new_group_ref(domain_id=self.domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group_ref)
        PROVIDERS.assignment_api.create_grant(
            prior, group_id=new_group['id'], project_id=self.project['id']
        )

        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(1, len(token_roles))

        PROVIDERS.identity_api.add_user_to_group(
            self.user['id'], new_group['id']
        )

        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(2, len(token_roles))

        implied1 = self._create_implied_role(prior)

        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(3, len(token_roles))

        implied2 = self._create_implied_role(prior)
        token_roles = self._get_scoped_token_roles(is_domain)
        self.assertEqual(4, len(token_roles))

        token_role_ids = [role['id'] for role in token_roles]
        self.assertIn(prior, token_role_ids)
        self.assertIn(implied1['id'], token_role_ids)
        self.assertIn(implied2['id'], token_role_ids)

    def test_multiple_implied_roles_show_in_v3_token(self):
        self.config_fixture.config(group='token')
        token_roles = self._get_scoped_token_roles()
        self.assertEqual(1, len(token_roles))

        prior = token_roles[0]['id']
        implied1 = self._create_implied_role(prior)
        implied2 = self._create_implied_role(prior)
        implied3 = self._create_implied_role(prior)

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(4, len(token_roles))

        token_role_ids = [role['id'] for role in token_roles]
        self.assertIn(prior, token_role_ids)
        self.assertIn(implied1['id'], token_role_ids)
        self.assertIn(implied2['id'], token_role_ids)
        self.assertIn(implied3['id'], token_role_ids)

    def test_chained_implied_role_shows_in_v3_token(self):
        self.config_fixture.config(group='token')
        token_roles = self._get_scoped_token_roles()
        self.assertEqual(1, len(token_roles))

        prior = token_roles[0]['id']
        implied1 = self._create_implied_role(prior)
        implied2 = self._create_implied_role(implied1['id'])
        implied3 = self._create_implied_role(implied2['id'])

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(4, len(token_roles))

        token_role_ids = [role['id'] for role in token_roles]

        self.assertIn(prior, token_role_ids)
        self.assertIn(implied1['id'], token_role_ids)
        self.assertIn(implied2['id'], token_role_ids)
        self.assertIn(implied3['id'], token_role_ids)

    def test_implied_role_disabled_by_config(self):
        self.config_fixture.config(group='token')
        token_roles = self._get_scoped_token_roles()
        self.assertEqual(1, len(token_roles))

        prior = token_roles[0]['id']
        implied1 = self._create_implied_role(prior)
        implied2 = self._create_implied_role(implied1['id'])
        self._create_implied_role(implied2['id'])

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(4, len(token_roles))
        token_role_ids = [role['id'] for role in token_roles]
        self.assertIn(prior, token_role_ids)

    def test_delete_implied_role_do_not_show_in_v3_token(self):
        self.config_fixture.config(group='token')
        token_roles = self._get_scoped_token_roles()
        prior = token_roles[0]['id']
        implied = self._create_implied_role(prior)

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(2, len(token_roles))
        self._delete_implied_role(prior, implied['id'])

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(1, len(token_roles))

    def test_unrelated_implied_roles_do_not_change_v3_token(self):
        self.config_fixture.config(group='token')
        token_roles = self._get_scoped_token_roles()
        prior = token_roles[0]['id']
        implied = self._create_implied_role(prior)

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(2, len(token_roles))

        unrelated = self._create_role()
        url = '/roles/%s/implies/%s' % (unrelated['id'], implied['id'])
        self.put(url, expected_status=http.client.CREATED)

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(2, len(token_roles))

        self._delete_implied_role(unrelated['id'], implied['id'])
        token_roles = self._get_scoped_token_roles()
        self.assertEqual(2, len(token_roles))

    def test_domain_specific_roles_do_not_show_v3_token(self):
        self.config_fixture.config(group='token')
        initial_token_roles = self._get_scoped_token_roles()

        new_role = self._create_role(domain_id=self.domain_id)
        PROVIDERS.assignment_api.create_grant(
            new_role['id'], user_id=self.user['id'],
            project_id=self.project['id']
        )
        implied = self._create_implied_role(new_role['id'])

        token_roles = self._get_scoped_token_roles()
        self.assertEqual(len(initial_token_roles) + 1, len(token_roles))

        # The implied role from the domain specific role should be in the
        # token, but not the domain specific role itself.
        token_role_ids = [role['id'] for role in token_roles]
        self.assertIn(implied['id'], token_role_ids)
        self.assertNotIn(new_role['id'], token_role_ids)

    def test_remove_all_roles_from_scope_result_in_404(self):
        # create a new user
        new_user = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain['id'])

        # give the new user a role on a project
        path = '/projects/%s/users/%s/roles/%s' % (
            self.project['id'], new_user['id'], self.role['id'])
        self.put(path=path)

        # authenticate as the new user and get a project-scoped token
        auth_data = self.build_authentication_request(
            user_id=new_user['id'],
            password=new_user['password'],
            project_id=self.project['id'])
        subject_token_id = self.v3_create_token(auth_data).headers.get(
            'X-Subject-Token')

        # make sure the project-scoped token is valid
        headers = {'X-Subject-Token': subject_token_id}
        r = self.get('/auth/tokens', headers=headers)
        self.assertValidProjectScopedTokenResponse(r)

        # remove the roles from the user for the given scope
        path = '/projects/%s/users/%s/roles/%s' % (
            self.project['id'], new_user['id'], self.role['id'])
        self.delete(path=path)

        # token validation should now result in 404
        self.get('/auth/tokens', headers=headers,
                 expected_status=http.client.NOT_FOUND)

    def test_create_token_with_nonexistant_user_id_fails(self):
        auth_data = self.build_authentication_request(
            user_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_token_with_nonexistant_username_fails(self):
        auth_data = self.build_authentication_request(
            username=uuid.uuid4().hex,
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_token_with_nonexistant_domain_id_fails(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_token_with_nonexistant_domain_name_fails(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=uuid.uuid4().hex,
            password=self.user['password'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_token_with_wrong_password_fails(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=uuid.uuid4().hex)
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_user_and_group_roles_scoped_token(self):
        """Test correct roles are returned in scoped token.

        Test Plan:

        - Create a domain, with 1 project, 2 users (user1 and user2)
          and 2 groups (group1 and group2)
        - Make user1 a member of group1, user2 a member of group2
        - Create 8 roles, assigning them to each of the 8 combinations
          of users/groups on domain/project
        - Get a project scoped token for user1, checking that the right
          two roles are returned (one directly assigned, one by virtue
          of group membership)
        - Repeat this for a domain scoped token
        - Make user1 also a member of group2
        - Get another scoped token making sure the additional role
          shows up
        - User2 is just here as a spoiler, to make sure we don't get
          any roles uniquely assigned to it returned in any of our
          tokens

        """
        domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domainA['id'], domainA)
        projectA = unit.new_project_ref(domain_id=domainA['id'])
        PROVIDERS.resource_api.create_project(projectA['id'], projectA)

        user1 = unit.create_user(
            PROVIDERS.identity_api, domain_id=domainA['id']
        )

        user2 = unit.create_user(
            PROVIDERS.identity_api, domain_id=domainA['id']
        )

        group1 = unit.new_group_ref(domain_id=domainA['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)

        group2 = unit.new_group_ref(domain_id=domainA['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)

        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            user2['id'], group2['id']
        )

        # Now create all the roles and assign them
        role_list = []
        for _ in range(8):
            role = unit.new_role_ref()
            PROVIDERS.role_api.create_role(role['id'], role)
            role_list.append(role)

        PROVIDERS.assignment_api.create_grant(
            role_list[0]['id'], user_id=user1['id'], domain_id=domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            role_list[1]['id'], user_id=user1['id'], project_id=projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            role_list[2]['id'], user_id=user2['id'], domain_id=domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            role_list[3]['id'], user_id=user2['id'], project_id=projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            role_list[4]['id'], group_id=group1['id'], domain_id=domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            role_list[5]['id'], group_id=group1['id'],
            project_id=projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            role_list[6]['id'], group_id=group2['id'], domain_id=domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            role_list[7]['id'], group_id=group2['id'],
            project_id=projectA['id']
        )

        # First, get a project scoped token - which should
        # contain the direct user role and the one by virtue
        # of group membership
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            project_id=projectA['id'])
        r = self.v3_create_token(auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(2, len(token['roles']))
        self.assertIn(role_list[1]['id'], roles_ids)
        self.assertIn(role_list[5]['id'], roles_ids)

        # Now the same thing for a domain scoped token
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            domain_id=domainA['id'])
        r = self.v3_create_token(auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(2, len(token['roles']))
        self.assertIn(role_list[0]['id'], roles_ids)
        self.assertIn(role_list[4]['id'], roles_ids)

        # Finally, add user1 to the 2nd group, and get a new
        # scoped token - the extra role should now be included
        # by virtue of the 2nd group
        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group2['id']
        )
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            project_id=projectA['id'])
        r = self.v3_create_token(auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(3, len(token['roles']))
        self.assertIn(role_list[1]['id'], roles_ids)
        self.assertIn(role_list[5]['id'], roles_ids)
        self.assertIn(role_list[7]['id'], roles_ids)

    def test_auth_token_cross_domain_group_and_project(self):
        """Verify getting a token in cross domain group/project roles."""
        # create domain, project and group and grant roles to user
        domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        PROVIDERS.resource_api.create_project(project1['id'], project1)
        user_foo = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=test_v3.DEFAULT_DOMAIN_ID)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        role_admin = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_admin['id'], role_admin)
        role_foo_domain1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            role_foo_domain1['id'], role_foo_domain1
        )
        role_group_domain1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(
            role_group_domain1['id'], role_group_domain1
        )
        new_group = unit.new_group_ref(domain_id=domain1['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        PROVIDERS.identity_api.add_user_to_group(
            user_foo['id'], new_group['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user_foo['id'],
            project_id=project1['id'],
            role_id=role_member['id'])
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'],
            project_id=project1['id'],
            role_id=role_admin['id'])
        PROVIDERS.assignment_api.create_grant(
            user_id=user_foo['id'],
            domain_id=domain1['id'],
            role_id=role_foo_domain1['id'])
        PROVIDERS.assignment_api.create_grant(
            group_id=new_group['id'],
            domain_id=domain1['id'],
            role_id=role_group_domain1['id'])

        # Get a scoped token for the project
        auth_data = self.build_authentication_request(
            username=user_foo['name'],
            user_domain_id=test_v3.DEFAULT_DOMAIN_ID,
            password=user_foo['password'],
            project_name=project1['name'],
            project_domain_id=domain1['id'])

        r = self.v3_create_token(auth_data)
        scoped_token = self.assertValidScopedTokenResponse(r)
        project = scoped_token["project"]
        roles_ids = []
        for ref in scoped_token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(project1['id'], project["id"])
        self.assertIn(role_member['id'], roles_ids)
        self.assertIn(role_admin['id'], roles_ids)
        self.assertNotIn(role_foo_domain1['id'], roles_ids)
        self.assertNotIn(role_group_domain1['id'], roles_ids)

    def test_remote_user_no_realm(self):
        app = self.loadapp()

        auth_contexts = []

        # NOTE(morgan): This __init__ is used to inject the auth context into
        # the auth_contexts list so that we can perform introspection. This way
        # we do not need to try and mock out anything deep within keystone's
        # auth pipeline. Note that we are using MockPatch to ensure we undo
        # the mock after the fact.
        def new_init(self, *args, **kwargs):
            super(auth.core.AuthContext, self).__init__(*args, **kwargs)
            auth_contexts.append(self)

        self.useFixture(fixtures.MockPatch(
            'keystone.auth.core.AuthContext.__init__', new_init))
        with app.test_client() as c:
            c.environ_base.update(self.build_external_auth_environ(
                self.default_domain_user['name']))
            auth_req = self.build_authentication_request()
            c.post('/v3/auth/tokens', json=auth_req)
            self.assertEqual(self.default_domain_user['id'],
                             auth_contexts[-1]['user_id'])

        # Now test to make sure the user name can, itself, contain the
        # '@' character.
        user = {'name': 'myname@mydivision'}
        PROVIDERS.identity_api.update_user(
            self.default_domain_user['id'], user
        )
        with app.test_client() as c:
            c.environ_base.update(self.build_external_auth_environ(
                user['name']))
            auth_req = self.build_authentication_request()
            c.post('/v3/auth/tokens', json=auth_req)
            self.assertEqual(self.default_domain_user['id'],
                             auth_contexts[-1]['user_id'])
        self.assertEqual(self.default_domain_user['id'],
                         auth_contexts[-1]['user_id'])

    def test_remote_user_no_domain(self):
        app = self.loadapp()
        with app.test_client() as c:
            c.environ_base.update(self.build_external_auth_environ(
                self.user['name']))
            auth_request = self.build_authentication_request()
            c.post('/v3/auth/tokens', json=auth_request,
                   expected_status_code=http.client.UNAUTHORIZED)

    def test_remote_user_and_password(self):
        # both REMOTE_USER and password methods must pass.
        # note that they do not have to match
        app = self.loadapp()
        with app.test_client() as c:
            auth_data = self.build_authentication_request(
                user_domain_id=self.default_domain_user['domain_id'],
                username=self.default_domain_user['name'],
                password=self.default_domain_user['password'])
            c.post('/v3/auth/tokens', json=auth_data)

    def test_remote_user_and_explicit_external(self):
        # both REMOTE_USER and password methods must pass.
        # note that they do not have to match
        auth_data = self.build_authentication_request(
            user_domain_id=self.domain['id'],
            username=self.user['name'],
            password=self.user['password'])
        auth_data['auth']['identity']['methods'] = ["password", "external"]
        auth_data['auth']['identity']['external'] = {}
        app = self.loadapp()
        with app.test_client() as c:
            c.post('/v3/auth/tokens', json=auth_data,
                   expected_status_code=http.client.UNAUTHORIZED)

    def test_remote_user_bad_password(self):
        # both REMOTE_USER and password methods must pass.
        app = self.loadapp()
        auth_data = self.build_authentication_request(
            user_domain_id=self.domain['id'],
            username=self.user['name'],
            password='badpassword')
        with app.test_client() as c:
            c.post('/v3/auth/tokens', json=auth_data,
                   expected_status_code=http.client.UNAUTHORIZED)

    def test_fetch_expired_allow_expired(self):
        self.config_fixture.config(group='token',
                                   expiration=10,
                                   allow_expired_window=20)
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            token = self._get_project_scoped_token()

            # initially it validates because it's within time
            frozen_datetime.tick(delta=datetime.timedelta(seconds=2))
            self._validate_token(token)

            # after passing expiry time validation fails
            frozen_datetime.tick(delta=datetime.timedelta(seconds=12))
            self._validate_token(token, expected_status=http.client.NOT_FOUND)

            # but if we pass allow_expired it validates
            self._validate_token(token, allow_expired=True)

            # and then if we're passed the allow_expired_window it will fail
            # anyway raises expired when now > expiration + window
            frozen_datetime.tick(delta=datetime.timedelta(seconds=22))
            self._validate_token(token,
                                 allow_expired=True,
                                 expected_status=http.client.NOT_FOUND)

    def test_system_scoped_token_works_with_domain_specific_drivers(self):
        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user['id'], self.role['id']
        )

        token_id = self.get_system_scoped_token()
        headers = {'X-Auth-Token': token_id}

        app = self.loadapp()
        with app.test_client() as c:
            c.get('/v3/users', headers=headers)

    def test_fetch_expired_allow_expired_in_expired_window(self):
        self.config_fixture.config(group='token',
                                   expiration=10,
                                   allow_expired_window=20)
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time):
            token = self._get_project_scoped_token()

        tick = datetime.timedelta(seconds=15)
        with freezegun.freeze_time(time + tick):
            # after passing expiry time validation fails
            self._validate_token(token, expected_status=http.client.NOT_FOUND)

            # but if we pass allow_expired it validates
            r = self._validate_token(token, allow_expired=True)
            self.assertValidProjectScopedTokenResponse(r)


class TokenDataTests(object):
    """Test the data in specific token types."""

    def test_unscoped_token_format(self):
        # ensure the unscoped token response contains the appropriate data
        r = self.get('/auth/tokens', headers=self.headers)
        self.assertValidUnscopedTokenResponse(r)

    def test_domain_scoped_token_format(self):
        # ensure the domain scoped token response contains the appropriate data
        PROVIDERS.assignment_api.create_grant(
            self.role['id'],
            user_id=self.default_domain_user['id'],
            domain_id=self.domain['id'])

        domain_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.default_domain_user['id'],
                password=self.default_domain_user['password'],
                domain_id=self.domain['id'])
        )
        self.headers['X-Subject-Token'] = domain_scoped_token
        r = self.get('/auth/tokens', headers=self.headers)
        self.assertValidDomainScopedTokenResponse(r)

    def test_project_scoped_token_format(self):
        # ensure project scoped token responses contains the appropriate data
        project_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.default_domain_user['id'],
                password=self.default_domain_user['password'],
                project_id=self.default_domain_project['id'])
        )
        self.headers['X-Subject-Token'] = project_scoped_token
        r = self.get('/auth/tokens', headers=self.headers)
        self.assertValidProjectScopedTokenResponse(r)

    def test_extra_data_in_unscoped_token_fails_validation(self):
        # ensure unscoped token response contains the appropriate data
        r = self.get('/auth/tokens', headers=self.headers)

        # populate the response result with some extra data
        r.result['token'][u'extra'] = str(uuid.uuid4().hex)
        self.assertRaises(exception.SchemaValidationError,
                          self.assertValidUnscopedTokenResponse,
                          r)

    def test_extra_data_in_domain_scoped_token_fails_validation(self):
        # ensure domain scoped token response contains the appropriate data
        PROVIDERS.assignment_api.create_grant(
            self.role['id'],
            user_id=self.default_domain_user['id'],
            domain_id=self.domain['id'])

        domain_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.default_domain_user['id'],
                password=self.default_domain_user['password'],
                domain_id=self.domain['id'])
        )
        self.headers['X-Subject-Token'] = domain_scoped_token
        r = self.get('/auth/tokens', headers=self.headers)

        # populate the response result with some extra data
        r.result['token'][u'extra'] = str(uuid.uuid4().hex)
        self.assertRaises(exception.SchemaValidationError,
                          self.assertValidDomainScopedTokenResponse,
                          r)

    def test_extra_data_in_project_scoped_token_fails_validation(self):
        # ensure project scoped token responses contains the appropriate data
        project_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.default_domain_user['id'],
                password=self.default_domain_user['password'],
                project_id=self.default_domain_project['id'])
        )
        self.headers['X-Subject-Token'] = project_scoped_token
        resp = self.get('/auth/tokens', headers=self.headers)

        # populate the response result with some extra data
        resp.result['token'][u'extra'] = str(uuid.uuid4().hex)
        self.assertRaises(exception.SchemaValidationError,
                          self.assertValidProjectScopedTokenResponse,
                          resp)


class AllowRescopeScopedTokenDisabledTests(test_v3.RestfulTestCase):
    def config_overrides(self):
        super(AllowRescopeScopedTokenDisabledTests, self).config_overrides()
        self.config_fixture.config(
            group='token',
            allow_rescope_scoped_token=False)

    def test_rescoping_v3_to_v3_disabled(self):
        self.v3_create_token(
            self.build_authentication_request(
                token=self.get_scoped_token(),
                project_id=self.project_id),
            expected_status=http.client.FORBIDDEN)

    def test_rescoped_domain_token_disabled(self):

        self.domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainA['id'], self.domainA)
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user['id'],
            domain_id=self.domainA['id']
        )
        unscoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user['id'],
                password=self.user['password']))
        # Get a domain-scoped token from the unscoped token
        domain_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                domain_id=self.domainA['id']))
        self.v3_create_token(
            self.build_authentication_request(
                token=domain_scoped_token,
                project_id=self.project_id),
            expected_status=http.client.FORBIDDEN)


class TestFernetTokenAPIs(test_v3.RestfulTestCase, TokenAPITests,
                          TokenDataTests):
    def config_overrides(self):
        super(TestFernetTokenAPIs, self).config_overrides()
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
        super(TestFernetTokenAPIs, self).setUp()
        self.doSetUp()

    def _make_auth_request(self, auth_data):
        token = super(TestFernetTokenAPIs, self)._make_auth_request(auth_data)
        self.assertLess(len(token), 255)
        return token

    def test_validate_tampered_unscoped_token_fails(self):
        unscoped_token = self._get_unscoped_token()
        tampered_token = (unscoped_token[:50] + uuid.uuid4().hex +
                          unscoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http.client.NOT_FOUND)

    def test_validate_tampered_project_scoped_token_fails(self):
        project_scoped_token = self._get_project_scoped_token()
        tampered_token = (project_scoped_token[:50] + uuid.uuid4().hex +
                          project_scoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http.client.NOT_FOUND)

    def test_validate_tampered_trust_scoped_token_fails(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Get a trust scoped token
        tampered_token = (trust_scoped_token[:50] + uuid.uuid4().hex +
                          trust_scoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http.client.NOT_FOUND)

    def test_trust_scoped_token_is_invalid_after_disabling_trustor(self):
        # NOTE(amakarov): have to override this test for non-persistent tokens
        # as TokenNotFound exception makes no sense for those.
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

        # Disable the trustor
        trustor_update_ref = dict(enabled=False)
        PROVIDERS.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            trust_scoped_token,
            expected_status=http.client.FORBIDDEN
        )


class TestJWSTokenAPIs(test_v3.RestfulTestCase, TokenAPITests, TokenDataTests):
    def config_overrides(self):
        super(TestJWSTokenAPIs, self).config_overrides()
        self.config_fixture.config(group='token', provider='jws',
                                   cache_on_issue=True)
        self.useFixture(ksfixtures.JWSKeyRepository(self.config_fixture))

    def setUp(self):
        super(TestJWSTokenAPIs, self).setUp()
        self.doSetUp()

    def _make_auth_request(self, auth_data):
        token = super(TestJWSTokenAPIs, self)._make_auth_request(auth_data)
        self.assertLess(len(token), 350)
        return token

    def test_validate_tampered_unscoped_token_fails(self):
        unscoped_token = self._get_unscoped_token()
        tampered_token = (unscoped_token[:50] + uuid.uuid4().hex +
                          unscoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http.client.NOT_FOUND)

    def test_validate_tampered_project_scoped_token_fails(self):
        project_scoped_token = self._get_project_scoped_token()
        tampered_token = (project_scoped_token[:50] + uuid.uuid4().hex +
                          project_scoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http.client.NOT_FOUND)

    def test_validate_tampered_trust_scoped_token_fails(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Get a trust scoped token
        tampered_token = (trust_scoped_token[:50] + uuid.uuid4().hex +
                          trust_scoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http.client.NOT_FOUND)

    def test_trust_scoped_token_is_invalid_after_disabling_trustor(self):
        # NOTE(amakarov): have to override this test for non-persistent tokens
        # as TokenNotFound exception makes no sense for those.
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        r = self._validate_token(trust_scoped_token)
        self.assertValidProjectScopedTokenResponse(r)

        # Disable the trustor
        trustor_update_ref = dict(enabled=False)
        PROVIDERS.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure validating a token for a disabled user fails
        self._validate_token(
            trust_scoped_token,
            expected_status=http.client.FORBIDDEN
        )


class TestTokenRevokeById(test_v3.RestfulTestCase):
    """Test token revocation on the v3 Identity API."""

    def config_overrides(self):
        super(TestTokenRevokeById, self).config_overrides()
        self.config_fixture.config(
            group='token',
            provider='fernet',
            revoke_by_id=False)
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def setUp(self):
        """Setup for Token Revoking Test Cases.

        As well as the usual housekeeping, create a set of domains,
        users, groups, roles and projects for the subsequent tests:

        - Two domains: A & B
        - Three users (1, 2 and 3)
        - Three groups (1, 2 and 3)
        - Two roles (1 and 2)
        - DomainA owns user1, domainB owns user2 and user3
        - DomainA owns group1 and group2, domainB owns group3
        - User1 and user2 are members of group1
        - User3 is a member of group2
        - Two projects: A & B, both in domainA
        - Group1 has role1 on Project A and B, meaning that user1 and user2
          will get these roles by virtue of membership
        - User1, 2 and 3 have role1 assigned to projectA
        - Group1 has role1 on Project A and B, meaning that user1 and user2
          will get role1 (duplicated) by virtue of membership
        - User1 has role2 assigned to domainA

        """
        super(TestTokenRevokeById, self).setUp()

        # Start by creating a couple of domains and projects
        self.domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainB['id'], self.domainB)
        self.projectA = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(
            self.projectA['id'], self.projectA
        )
        self.projectB = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(
            self.projectB['id'], self.projectB
        )

        # Now create some users
        self.user1 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainA['id'])

        self.user2 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainB['id'])

        self.user3 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainB['id'])

        self.group1 = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group1 = PROVIDERS.identity_api.create_group(self.group1)

        self.group2 = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group2 = PROVIDERS.identity_api.create_group(self.group2)

        self.group3 = unit.new_group_ref(domain_id=self.domainB['id'])
        self.group3 = PROVIDERS.identity_api.create_group(self.group3)

        PROVIDERS.identity_api.add_user_to_group(
            self.user1['id'], self.group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            self.user2['id'], self.group1['id']
        )
        PROVIDERS.identity_api.add_user_to_group(
            self.user3['id'], self.group2['id']
        )

        self.role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role1['id'], self.role1)
        self.role2 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role2['id'], self.role2)

        PROVIDERS.assignment_api.create_grant(
            self.role2['id'], user_id=self.user1['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], user_id=self.user1['id'],
            project_id=self.projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], user_id=self.user2['id'],
            project_id=self.projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], user_id=self.user3['id'],
            project_id=self.projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], group_id=self.group1['id'],
            project_id=self.projectA['id']
        )

    def test_unscoped_token_remains_valid_after_role_assignment(self):
        unscoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password']))

        scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                project_id=self.projectA['id']))

        # confirm both tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': scoped_token},
                  expected_status=http.client.OK)

        # create a new role
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        # assign a new role
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'user_id': self.user1['id'],
                'role_id': role['id']})

        # both tokens should remain valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': scoped_token},
                  expected_status=http.client.OK)

    def test_deleting_user_grant_revokes_token(self):
        """Test deleting a user grant revokes token.

        Test Plan:

        - Get a token for user, scoped to Project
        - Delete the grant user has on Project
        - Check token is no longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)
        # Delete the grant, which should invalidate the token
        grant_url = (
            '/projects/%(project_id)s/users/%(user_id)s/'
            'roles/%(role_id)s' % {
                'project_id': self.project['id'],
                'user_id': self.user['id'],
                'role_id': self.role['id']})
        self.delete(grant_url)
        self.head('/auth/tokens', token=token,
                  expected_status=http.client.UNAUTHORIZED)

    def role_data_fixtures(self):
        self.projectC = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(
            self.projectC['id'], self.projectC
        )
        self.user4 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainB['id'])
        self.user5 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainA['id'])
        self.user6 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainA['id'])
        PROVIDERS.identity_api.add_user_to_group(
            self.user5['id'], self.group1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], group_id=self.group1['id'],
            project_id=self.projectB['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role2['id'], user_id=self.user4['id'],
            project_id=self.projectC['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], user_id=self.user6['id'],
            project_id=self.projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], user_id=self.user6['id'],
            domain_id=self.domainA['id']
        )

    def test_deleting_role_revokes_token(self):
        """Test deleting a role revokes token.

        Add some additional test data, namely:

        - A third project (project C)
        - Three additional users - user4 owned by domainB and user5 and 6 owned
          by domainA (different domain ownership should not affect the test
          results, just provided to broaden test coverage)
        - User5 is a member of group1
        - Group1 gets an additional assignment - role1 on projectB as well as
          its existing role1 on projectA
        - User4 has role2 on Project C
        - User6 has role1 on projectA and domainA
        - This allows us to create 5 tokens by virtue of different types of
          role assignment:
          - user1, scoped to ProjectA by virtue of user role1 assignment
          - user5, scoped to ProjectB by virtue of group role1 assignment
          - user4, scoped to ProjectC by virtue of user role2 assignment
          - user6, scoped to ProjectA by virtue of user role1 assignment
          - user6, scoped to DomainA by virtue of user role1 assignment
        - role1 is then deleted
        - Check the tokens on Project A and B, and DomainA are revoked, but not
          the one for Project C

        """
        self.role_data_fixtures()

        # Now we are ready to start issuing requests
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        tokenA = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user5['id'],
            password=self.user5['password'],
            project_id=self.projectB['id'])
        tokenB = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user4['id'],
            password=self.user4['password'],
            project_id=self.projectC['id'])
        tokenC = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user6['id'],
            password=self.user6['password'],
            project_id=self.projectA['id'])
        tokenD = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user6['id'],
            password=self.user6['password'],
            domain_id=self.domainA['id'])
        tokenE = self.get_requested_token(auth_data)
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenA},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenB},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenC},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenD},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenE},
                  expected_status=http.client.OK)

        # Delete the role, which should invalidate the tokens
        role_url = '/roles/%s' % self.role1['id']
        self.delete(role_url)

        # Check the tokens that used role1 is invalid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenA},
                  expected_status=http.client.NOT_FOUND)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenB},
                  expected_status=http.client.NOT_FOUND)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenD},
                  expected_status=http.client.NOT_FOUND)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenE},
                  expected_status=http.client.NOT_FOUND)

        # ...but the one using role2 is still valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenC},
                  expected_status=http.client.OK)

    def test_domain_user_role_assignment_maintains_token(self):
        """Test user-domain role assignment maintains existing token.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Create a grant for user1 on DomainB
        - Check token is still valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)
        # Assign a role, which should not affect the token
        grant_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/'
            'roles/%(role_id)s' % {
                'domain_id': self.domainB['id'],
                'user_id': self.user1['id'],
                'role_id': self.role1['id']})
        self.put(grant_url)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)

    def test_disabling_project_revokes_token(self):
        token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))

        # confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)

        # disable the project, which should invalidate the token
        self.patch(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']},
            body={'project': {'enabled': False}})

        # user should no longer have access to the project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.NOT_FOUND)
        self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']),
            expected_status=http.client.UNAUTHORIZED)

    def test_deleting_project_revokes_token(self):
        token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))

        # confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)

        # delete the project, which should invalidate the token
        self.delete(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']})

        # user should no longer have access to the project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.NOT_FOUND)
        self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']),
            expected_status=http.client.UNAUTHORIZED)

    def test_deleting_group_grant_revokes_tokens(self):
        """Test deleting a group grant revokes tokens.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Get a token for user2, scoped to ProjectA
        - Get a token for user3, scoped to ProjectA
        - Delete the grant group1 has on ProjectA
        - Check tokens for user1 & user2 are no longer valid,
          since user1 and user2 are members of group1
        - Check token for user3 is invalid too

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token1 = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        token2 = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user3['id'],
            password=self.user3['password'],
            project_id=self.projectA['id'])
        token3 = self.get_requested_token(auth_data)
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token3},
                  expected_status=http.client.OK)
        # Delete the group grant, which should invalidate the
        # tokens for user1 and user2
        grant_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/'
            'roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'group_id': self.group1['id'],
                'role_id': self.role1['id']})
        self.delete(grant_url)
        PROVIDERS.assignment_api.delete_grant(
            role_id=self.role1['id'], project_id=self.projectA['id'],
            user_id=self.user1['id']
        )
        PROVIDERS.assignment_api.delete_grant(
            role_id=self.role1['id'], project_id=self.projectA['id'],
            user_id=self.user2['id']
        )
        self.head('/auth/tokens', token=token1,
                  expected_status=http.client.UNAUTHORIZED)
        self.head('/auth/tokens', token=token2,
                  expected_status=http.client.UNAUTHORIZED)
        # But user3's token should be invalid too as revocation is done for
        # scope role & project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token3},
                  expected_status=http.client.OK)

    def test_domain_group_role_assignment_maintains_token(self):
        """Test domain-group role assignment maintains existing token.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Create a grant for group1 on DomainB
        - Check token is still longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)
        # Delete the grant, which should invalidate the token
        grant_url = (
            '/domains/%(domain_id)s/groups/%(group_id)s/'
            'roles/%(role_id)s' % {
                'domain_id': self.domainB['id'],
                'group_id': self.group1['id'],
                'role_id': self.role1['id']})
        self.put(grant_url)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http.client.OK)

    def test_group_membership_changes_revokes_token(self):
        """Test add/removal to/from group revokes token.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Get a token for user2, scoped to ProjectA
        - Remove user1 from group1
        - Check token for user1 is no longer valid
        - Check token for user2 is still valid, even though
          user2 is also part of group1
        - Add user2 to group2
        - Check token for user2 is now no longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token1 = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        token2 = self.get_requested_token(auth_data)
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=http.client.OK)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=http.client.OK)
        # Remove user1 from group1, which should invalidate
        # the token
        self.delete('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group1['id'],
            'user_id': self.user1['id']})
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=http.client.NOT_FOUND)
        # But user2's token should still be valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=http.client.OK)
        # Adding user2 to a group should not invalidate token
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group2['id'],
            'user_id': self.user2['id']})
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=http.client.OK)

    def test_removing_role_assignment_does_not_affect_other_users(self):
        """Revoking a role from one user should not affect other users."""
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:
            # This group grant is not needed for the test
            self.delete(
                '/projects/%(p_id)s/groups/%(g_id)s/roles/%(r_id)s' %
                {'p_id': self.projectA['id'],
                 'g_id': self.group1['id'],
                 'r_id': self.role1['id']})

            # NOTE(lbragstad): Here we advance the clock one second to pass
            # into the threshold of a new second because we just persisted a
            # revocation event for removing a role from a group on a project.
            # One thing to note about that revocation event is that it has no
            # context about the group, so even though user3 might not be in
            # group1, they could have their token revoked because the
            # revocation event is very general.
            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

            user1_token = self.get_requested_token(
                self.build_authentication_request(
                    user_id=self.user1['id'],
                    password=self.user1['password'],
                    project_id=self.projectA['id']))

            user3_token = self.get_requested_token(
                self.build_authentication_request(
                    user_id=self.user3['id'],
                    password=self.user3['password'],
                    project_id=self.projectA['id']))

            # delete relationships between user1 and projectA from setUp
            self.delete(
                '/projects/%(p_id)s/users/%(u_id)s/roles/%(r_id)s' % {
                    'p_id': self.projectA['id'],
                    'u_id': self.user1['id'],
                    'r_id': self.role1['id']})
            # authorization for the first user should now fail
            self.head('/auth/tokens',
                      headers={'X-Subject-Token': user1_token},
                      expected_status=http.client.NOT_FOUND)
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user1['id'],
                    password=self.user1['password'],
                    project_id=self.projectA['id']),
                expected_status=http.client.UNAUTHORIZED)

            # authorization for the second user should still succeed
            self.head('/auth/tokens',
                      headers={'X-Subject-Token': user3_token},
                      expected_status=http.client.OK)
            self.v3_create_token(
                self.build_authentication_request(
                    user_id=self.user3['id'],
                    password=self.user3['password'],
                    project_id=self.projectA['id']))

    def test_deleting_project_deletes_grants(self):
        # This is to make it a little bit more pretty with PEP8
        role_path = ('/projects/%(project_id)s/users/%(user_id)s/'
                     'roles/%(role_id)s')
        role_path = role_path % {'user_id': self.user['id'],
                                 'project_id': self.projectA['id'],
                                 'role_id': self.role['id']}

        # grant the user a role on the project
        self.put(role_path)

        # delete the project, which should remove the roles
        self.delete(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']})

        # Make sure that we get a 404 Not Found when heading that role.
        self.head(role_path, expected_status=http.client.NOT_FOUND)

    def test_revoke_token_from_token(self):
        # Test that a scoped token can be requested from an unscoped token,
        # the scoped token can be revoked, and the unscoped token remains
        # valid.

        unscoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password']))

        # Get a project-scoped token from the unscoped token
        project_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                project_id=self.projectA['id']))

        # Get a domain-scoped token from the unscoped token
        domain_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                domain_id=self.domainA['id']))

        # revoke the project-scoped token.
        self.delete('/auth/tokens',
                    headers={'X-Subject-Token': project_scoped_token})

        # The project-scoped token is invalidated.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': project_scoped_token},
                  expected_status=http.client.NOT_FOUND)

        # The unscoped token should still be valid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=http.client.OK)

        # The domain-scoped token should still be valid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': domain_scoped_token},
                  expected_status=http.client.OK)

        # revoke the domain-scoped token.
        self.delete('/auth/tokens',
                    headers={'X-Subject-Token': domain_scoped_token})

        # The domain-scoped token is invalid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': domain_scoped_token},
                  expected_status=http.client.NOT_FOUND)

        # The unscoped token should still be valid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=http.client.OK)


class TestTokenRevokeApi(TestTokenRevokeById):
    """Test token revocation on the v3 Identity API."""

    def config_overrides(self):
        super(TestTokenRevokeApi, self).config_overrides()
        self.config_fixture.config(
            group='token',
            provider='fernet',
            revoke_by_id=False)
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def assertValidDeletedProjectResponse(self, events_response, project_id):
        events = events_response['events']
        self.assertEqual(1, len(events))
        self.assertEqual(project_id, events[0]['project_id'])
        self.assertIsNotNone(events[0]['issued_before'])
        self.assertIsNotNone(events_response['links'])
        del (events_response['events'][0]['issued_before'])
        del (events_response['events'][0]['revoked_at'])
        del (events_response['links'])
        expected_response = {'events': [{'project_id': project_id}]}
        self.assertEqual(expected_response, events_response)

    def assertValidRevokedTokenResponse(self, events_response, **kwargs):
        events = events_response['events']
        self.assertEqual(1, len(events))
        for k, v in kwargs.items():
            self.assertEqual(v, events[0].get(k))
        self.assertIsNotNone(events[0]['issued_before'])
        self.assertIsNotNone(events_response['links'])
        del (events_response['events'][0]['issued_before'])
        del (events_response['events'][0]['revoked_at'])
        del (events_response['links'])

        expected_response = {'events': [kwargs]}
        self.assertEqual(expected_response, events_response)

    def test_revoke_token(self):
        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        response = self.get('/auth/tokens', headers=headers).json_body['token']

        self.delete('/auth/tokens', headers=headers)
        self.head('/auth/tokens', headers=headers,
                  expected_status=http.client.NOT_FOUND)
        events_response = self.get('/OS-REVOKE/events').json_body
        self.assertValidRevokedTokenResponse(events_response,
                                             audit_id=response['audit_ids'][0])

    def test_get_revoke_by_id_false_returns_gone(self):
        self.get('/auth/tokens/OS-PKI/revoked',
                 expected_status=http.client.GONE)

    def test_head_revoke_by_id_false_returns_gone(self):
        self.head('/auth/tokens/OS-PKI/revoked',
                  expected_status=http.client.GONE)

    def test_revoke_by_id_true_returns_forbidden(self):
        self.config_fixture.config(
            group='token',
            revoke_by_id=True)
        self.get(
            '/auth/tokens/OS-PKI/revoked',
            expected_status=http.client.FORBIDDEN
        )
        self.head(
            '/auth/tokens/OS-PKI/revoked',
            expected_status=http.client.FORBIDDEN
        )

    def test_list_delete_project_shows_in_event_list(self):
        self.role_data_fixtures()
        events = self.get('/OS-REVOKE/events').json_body['events']
        self.assertEqual([], events)
        self.delete(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']})
        events_response = self.get('/OS-REVOKE/events').json_body

        self.assertValidDeletedProjectResponse(events_response,
                                               self.projectA['id'])

    def assertEventDataInList(self, events, **kwargs):
        found = False
        for e in events:
            for key, value in kwargs.items():
                try:
                    if e[key] != value:
                        break
                except KeyError:
                    # Break the loop and present a nice error instead of
                    # KeyError
                    break
            else:
                # If the value of the event[key] matches the value of the kwarg
                # for each item in kwargs, the event was fully matched and
                # the assertTrue below should succeed.
                found = True
        self.assertTrue(found,
                        'event with correct values not in list, expected to '
                        'find event with key-value pairs. Expected: '
                        '"%(expected)s" Events: "%(events)s"' %
                        {'expected': ','.join(
                            ["'%s=%s'" % (k, v) for k, v in kwargs.items()]),
                         'events': events})

    def test_list_delete_token_shows_in_event_list(self):
        self.role_data_fixtures()
        events = self.get('/OS-REVOKE/events').json_body['events']
        self.assertEqual([], events)

        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        auth_req = self.build_authentication_request(token=scoped_token)
        response = self.v3_create_token(auth_req)
        token2 = response.json_body['token']
        headers2 = {'X-Subject-Token': response.headers['X-Subject-Token']}

        response = self.v3_create_token(auth_req)
        response.json_body['token']
        headers3 = {'X-Subject-Token': response.headers['X-Subject-Token']}

        self.head('/auth/tokens', headers=headers,
                  expected_status=http.client.OK)
        self.head('/auth/tokens', headers=headers2,
                  expected_status=http.client.OK)
        self.head('/auth/tokens', headers=headers3,
                  expected_status=http.client.OK)

        self.delete('/auth/tokens', headers=headers)
        # NOTE(ayoung): not deleting token3, as it should be deleted
        # by previous
        events_response = self.get('/OS-REVOKE/events').json_body
        events = events_response['events']
        self.assertEqual(1, len(events))
        self.assertEventDataInList(
            events,
            audit_id=token2['audit_ids'][1])
        self.head('/auth/tokens', headers=headers,
                  expected_status=http.client.NOT_FOUND)
        self.head('/auth/tokens', headers=headers2,
                  expected_status=http.client.OK)
        self.head('/auth/tokens', headers=headers3,
                  expected_status=http.client.OK)

    def test_list_with_filter(self):

        self.role_data_fixtures()
        events = self.get('/OS-REVOKE/events').json_body['events']
        self.assertEqual(0, len(events))

        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        auth = self.build_authentication_request(token=scoped_token)
        headers2 = {'X-Subject-Token': self.get_requested_token(auth)}
        self.delete('/auth/tokens', headers=headers)
        self.delete('/auth/tokens', headers=headers2)

        events = self.get('/OS-REVOKE/events').json_body['events']

        self.assertEqual(2, len(events))
        future = utils.isotime(timeutils.utcnow() +
                               datetime.timedelta(seconds=1000))

        events = self.get('/OS-REVOKE/events?since=%s' % (future)
                          ).json_body['events']
        self.assertEqual(0, len(events))


class TestAuthExternalDisabled(test_v3.RestfulTestCase):
    def config_overrides(self):
        super(TestAuthExternalDisabled, self).config_overrides()
        self.config_fixture.config(
            group='auth',
            methods=['password', 'token'])

    def test_remote_user_disabled(self):
        app = self.loadapp()
        remote_user = '%s@%s' % (self.user['name'], self.domain['name'])
        with app.test_client() as c:
            c.environ_base.update(self.build_external_auth_environ(
                remote_user))
            auth_data = self.build_authentication_request()
            c.post('/v3/auth/tokens', json=auth_data,
                   expected_status_code=http.client.UNAUTHORIZED)

# FIXME(morgan): This test case must be re-worked to function under flask. It
# has been commented out until it is re-worked ensuring no issues when webob
# classes are removed.
# https://bugs.launchpad.net/keystone/+bug/1793756
# class AuthExternalDomainBehavior(object):
#     content_type = 'json'
#
#     def test_remote_user_with_realm(self):
#         api = auth.controllers.Auth()
#         remote_user = self.user['name']
#         remote_domain = self.domain['name']
#         request, auth_info, auth_context = self.build_external_auth_request(
#             remote_user, remote_domain=remote_domain, kerberos=self.kerberos)
#
#         api.authenticate(request, auth_info, auth_context)
#         self.assertEqual(self.user['id'], auth_context['user_id'])
#
#         # Now test to make sure the user name can, itself, contain the
#         # '@' character.
#         user = {'name': 'myname@mydivision'}
#         PROVIDERS.identity_api.update_user(self.user['id'], user)
#         remote_user = user['name']
#         request, auth_info, auth_context = self.build_external_auth_request(
#             remote_user, remote_domain=remote_domain, kerberos=self.kerberos)
#
#         api.authenticate(request, auth_info, auth_context)
#         self.assertEqual(self.user['id'], auth_context['user_id'])
#
#
# FIXME(morgan): This test case must be re-worked to function under flask. It
# has been commented out until it is re-worked ensuring no issues when webob
# classes are removed.
# https://bugs.launchpad.net/keystone/+bug/1793756
# class TestAuthExternalDefaultDomain(object):
#     content_type = 'json'
#
#     def config_overrides(self):
#         super(TestAuthExternalDefaultDomain, self).config_overrides()
#         self.kerberos = False
#         self.auth_plugin_config_override(external='DefaultDomain')
#
#     def test_remote_user_with_default_domain(self):
#         api = auth.controllers.Auth()
#         remote_user = self.default_domain_user['name']
#         request, auth_info, auth_context = self.build_external_auth_request(
#             remote_user, kerberos=self.kerberos)
#
#         api.authenticate(request, auth_info, auth_context)
#         self.assertEqual(self.default_domain_user['id'],
#                          auth_context['user_id'])
#
#         # Now test to make sure the user name can, itself, contain the
#         # '@' character.
#         user = {'name': 'myname@mydivision'}
#         PROVIDERS.identity_api.update_user(
#             self.default_domain_user['id'], user
#         )
#         remote_user = user['name']
#         request, auth_info, auth_context = self.build_external_auth_request(
#             remote_user, kerberos=self.kerberos)
#
#         api.authenticate(request, auth_info, auth_context)
#         self.assertEqual(self.default_domain_user['id'],
#                          auth_context['user_id'])
#


class TestAuthJSONExternal(test_v3.RestfulTestCase):
    content_type = 'json'

    def auth_plugin_config_override(self, methods=None, **method_classes):
        self.config_fixture.config(group='auth', methods=[])

    def test_remote_user_no_method(self):
        app = self.loadapp()
        with app.test_client() as c:
            c.environ_base.update(self.build_external_auth_environ(
                self.default_domain_user['name']))
            auth_data = self.build_authentication_request()
            c.post('/v3/auth/tokens', json=auth_data,
                   expected_status_code=http.client.UNAUTHORIZED)


class TrustAPIBehavior(test_v3.RestfulTestCase):
    """Redelegation valid and secure.

    Redelegation is a hierarchical structure of trusts between initial trustor
    and a group of users allowed to impersonate trustor and act in his name.
    Hierarchy is created in a process of trusting already trusted permissions
    and organized as an adjacency list using 'redelegated_trust_id' field.
    Redelegation is valid if each subsequent trust in a chain passes 'not more'
    permissions than being redelegated.

    Trust constraints are:
     * roles - set of roles trusted by trustor
     * expiration_time
     * allow_redelegation - a flag
     * redelegation_count - decreasing value restricting length of trust chain
     * remaining_uses - DISALLOWED when allow_redelegation == True

    Trust becomes invalid in case:
     * trust roles were revoked from trustor
     * one of the users in the delegation chain was disabled or deleted
     * expiration time passed
     * one of the parent trusts has become invalid
     * one of the parent trusts was deleted

    """

    def config_overrides(self):
        super(TrustAPIBehavior, self).config_overrides()
        self.config_fixture.config(
            group='trust',
            allow_redelegation=True,
            max_redelegation_count=10
        )

    def setUp(self):
        super(TrustAPIBehavior, self).setUp()
        # Create a trustee to delegate stuff to
        self.trustee_user = unit.create_user(PROVIDERS.identity_api,
                                             domain_id=self.domain_id)

        # trustor->trustee
        self.redelegated_trust_ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id],
            allow_redelegation=True)

        # trustor->trustee (no redelegation)
        self.chained_trust_ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id],
            allow_redelegation=True)

    def _get_trust_token(self, trust):
        trust_id = trust['id']
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust_id)
        trust_token = self.get_requested_token(auth_data)
        return trust_token

    def test_depleted_redelegation_count_error(self):
        self.redelegated_trust_ref['redelegation_count'] = 0
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust.
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.chained_trust_ref},
                  token=trust_token,
                  expected_status=http.client.FORBIDDEN)

    def test_modified_redelegation_count_error(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust with incorrect
        # redelegation_count.
        correct = trust['redelegation_count'] - 1
        incorrect = correct - 1
        self.chained_trust_ref['redelegation_count'] = incorrect
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.chained_trust_ref},
                  token=trust_token,
                  expected_status=http.client.FORBIDDEN)

    def test_max_redelegation_count_constraint(self):
        incorrect = CONF.trust.max_redelegation_count + 1
        self.redelegated_trust_ref['redelegation_count'] = incorrect
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.redelegated_trust_ref},
                  expected_status=http.client.FORBIDDEN)

    def test_redelegation_expiry(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust supposed to last longer
        # than the parent trust: let's give it 10 minutes (>1 minute).
        too_long_live_chained_trust_ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=10),
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts',
                  body={'trust': too_long_live_chained_trust_ref},
                  token=trust_token,
                  expected_status=http.client.FORBIDDEN)

    def test_redelegation_remaining_uses(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust with remaining_uses defined.
        # It must fail according to specification: remaining_uses must be
        # omitted for trust redelegation. Any number here.
        self.chained_trust_ref['remaining_uses'] = 5
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.chained_trust_ref},
                  token=trust_token,
                  expected_status=http.client.BAD_REQUEST)

    def test_roles_subset(self):
        # Build second role
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        # assign a new role to the user
        PROVIDERS.assignment_api.create_grant(
            role_id=role['id'], user_id=self.user_id,
            project_id=self.project_id
        )

        # Create first trust with extended set of roles
        ref = self.redelegated_trust_ref
        ref['expires_at'] = datetime.datetime.utcnow().replace(
            year=2032).strftime(unit.TIME_FORMAT)
        ref['roles'].append({'id': role['id']})
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        # Trust created with exact set of roles (checked by role id)
        role_id_set = set(r['id'] for r in ref['roles'])
        trust_role_id_set = set(r['id'] for r in trust['roles'])
        self.assertEqual(role_id_set, trust_role_id_set)

        trust_token = self._get_trust_token(trust)

        # Chain second trust with roles subset
        self.chained_trust_ref['expires_at'] = (
            datetime.datetime.utcnow().replace(year=2028).strftime(
                unit.TIME_FORMAT))
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.chained_trust_ref},
                      token=trust_token)
        trust2 = self.assertValidTrustResponse(r)
        # First trust contains roles superset
        # Second trust contains roles subset
        role_id_set1 = set(r['id'] for r in trust['roles'])
        role_id_set2 = set(r['id'] for r in trust2['roles'])
        self.assertThat(role_id_set1, matchers.GreaterThan(role_id_set2))

    def test_trust_with_implied_roles(self):
        # Create some roles
        role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role2['id'], role2)

        # Implication
        PROVIDERS.role_api.create_implied_role(role1['id'], role2['id'])

        # Assign new roles to the user (with role2 implied)
        PROVIDERS.assignment_api.create_grant(
            role_id=role1['id'], user_id=self.user_id,
            project_id=self.project_id
        )

        # Create trust
        ref = self.redelegated_trust_ref
        ref['roles'] = [{'id': role1['id']}, {'id': role2['id']}]
        resp = self.post('/OS-TRUST/trusts',
                         body={'trust': ref})
        trust = self.assertValidTrustResponse(resp)

        # Trust created with exact set of roles (checked by role id)
        role_ids = [r['id'] for r in ref['roles']]
        trust_role_ids = [r['id'] for r in trust['roles']]
        # Compare requested roles with roles in response
        self.assertEqual(role_ids, trust_role_ids)

        # Get a trust-scoped token
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id']
        )
        resp = self.post('/auth/tokens', body=auth_data)
        trust_token_role_ids = [r['id'] for r in resp.json['token']['roles']]
        # Compare requested roles with roles given in token data
        self.assertEqual(sorted(role_ids), sorted(trust_token_role_ids))

    def test_redelegate_with_role_by_name(self):
        # For role by name testing
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_names=[self.role['name']],
            allow_redelegation=True)
        ref['expires_at'] = datetime.datetime.utcnow().replace(
            year=2032).strftime(unit.TIME_FORMAT)
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        # Ensure we can get a token with this trust
        trust_token = self._get_trust_token(trust)
        # Chain second trust with roles subset
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            role_names=[self.role['name']],
            allow_redelegation=True)
        ref['expires_at'] = datetime.datetime.utcnow().replace(
            year=2028).strftime(unit.TIME_FORMAT)
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref},
                      token=trust_token)
        trust = self.assertValidTrustResponse(r)
        # Ensure we can get a token with this trust
        self._get_trust_token(trust)

    def test_redelegate_new_role_fails(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Build second trust with a role not in parent's roles
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)
        # assign a new role to the user
        PROVIDERS.assignment_api.create_grant(
            role_id=role['id'], user_id=self.user_id,
            project_id=self.project_id
        )

        # Try to chain a trust with the role not from parent trust
        self.chained_trust_ref['roles'] = [{'id': role['id']}]

        # Bypass policy enforcement
        with mock.patch.object(policy, 'enforce', return_value=True):
            self.post('/OS-TRUST/trusts',
                      body={'trust': self.chained_trust_ref},
                      token=trust_token,
                      expected_status=http.client.FORBIDDEN)

    def test_redelegation_terminator(self):
        self.redelegated_trust_ref['expires_at'] = (
            datetime.datetime.utcnow().replace(year=2032).strftime(
                unit.TIME_FORMAT))
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Build second trust - the terminator
        self.chained_trust_ref['expires_at'] = (
            datetime.datetime.utcnow().replace(year=2028).strftime(
                unit.TIME_FORMAT))
        ref = dict(self.chained_trust_ref,
                   redelegation_count=1,
                   allow_redelegation=False)

        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref},
                      token=trust_token)

        trust = self.assertValidTrustResponse(r)
        # Check that allow_redelegation == False caused redelegation_count
        # to be set to 0, while allow_redelegation is removed
        self.assertNotIn('allow_redelegation', trust)
        self.assertEqual(0, trust['redelegation_count'])
        trust_token = self._get_trust_token(trust)

        # Build third trust, same as second
        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  token=trust_token,
                  expected_status=http.client.FORBIDDEN)

    def test_redelegation_without_impersonation(self):
        # Update trust to not allow impersonation
        self.redelegated_trust_ref['impersonation'] = False

        # Create trust
        resp = self.post('/OS-TRUST/trusts',
                         body={'trust': self.redelegated_trust_ref},
                         expected_status=http.client.CREATED)
        trust = self.assertValidTrustResponse(resp)

        # Get trusted token without impersonation
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        trust_token = self.get_requested_token(auth_data)

        # Create second user for redelegation
        trustee_user_2 = unit.create_user(PROVIDERS.identity_api,
                                          domain_id=self.domain_id)

        # Trust for redelegation
        trust_ref_2 = unit.new_trust_ref(
            trustor_user_id=self.trustee_user['id'],
            trustee_user_id=trustee_user_2['id'],
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id],
            allow_redelegation=False)

        # Creating a second trust should not be allowed since trustor does not
        # have the role to delegate thus returning 404 NOT FOUND.
        resp = self.post('/OS-TRUST/trusts',
                         body={'trust': trust_ref_2},
                         token=trust_token,
                         expected_status=http.client.NOT_FOUND)

    def test_create_unscoped_trust(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        self.assertValidTrustResponse(r, ref)

    def test_create_trust_no_roles(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id)
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http.client.FORBIDDEN)

    def _initialize_test_consume_trust(self, count):
        # Make sure remaining_uses is decremented as we consume the trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            remaining_uses=count,
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        # make sure the trust exists
        trust = self.assertValidTrustResponse(r, ref)
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']})
        # get a token for the trustee
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'])
        r = self.v3_create_token(auth_data)
        token = r.headers.get('X-Subject-Token')
        # get a trust token, consume one use
        auth_data = self.build_authentication_request(
            token=token,
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        return trust

    def test_authenticate_without_trust_dict_returns_bad_request(self):
        # Authenticate for a token to use in the request
        token = self.v3_create_token(
            self.build_authentication_request(
                user_id=self.trustee_user['id'],
                password=self.trustee_user['password']
            )
        ).headers.get('X-Subject-Token')

        auth_data = {
            'auth': {
                'identity': {
                    'methods': ['token'],
                    'token': {'id': token}
                },
                # We don't need a trust to execute this test, the
                # OS-TRUST:trust key of the request body just has to be a
                # string instead of a dictionary in order to throw a 500 when
                # it should a 400 Bad Request.
                'scope': {'OS-TRUST:trust': ''}
            }
        }
        self.admin_request(
            method='POST', path='/v3/auth/tokens', body=auth_data,
            expected_status=http.client.BAD_REQUEST
        )

    def test_consume_trust_once(self):
        trust = self._initialize_test_consume_trust(2)
        # check decremented value
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']})
        trust = r.result.get('trust')
        self.assertIsNotNone(trust)
        self.assertEqual(1, trust['remaining_uses'])
        self.assertEqual(self.role['name'], trust['roles'][0]['name'])
        self.assertEqual(self.role['id'], trust['roles'][0]['id'])

    def test_create_one_time_use_trust(self):
        trust = self._initialize_test_consume_trust(1)
        # No more uses, the trust is made unavailable
        self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=http.client.NOT_FOUND)
        # this time we can't get a trust token
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_create_unlimited_use_trust(self):
        # by default trusts are unlimited in terms of tokens that can be
        # generated from them, this test creates such a trust explicitly
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            remaining_uses=None,
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']})
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'])
        r = self.v3_create_token(auth_data)
        token = r.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            token=token,
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']})
        trust = r.result.get('trust')
        self.assertIsNone(trust['remaining_uses'])

    def test_impersonation_token_cannot_create_new_trust(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])

        trust_token = self.get_requested_token(auth_data)

        # Build second trust
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  token=trust_token,
                  expected_status=http.client.FORBIDDEN)

    def test_trust_deleted_grant(self):
        # create a new role
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        grant_url = (
            '/projects/%(project_id)s/users/%(user_id)s/'
            'roles/%(role_id)s' % {
                'project_id': self.project_id,
                'user_id': self.user_id,
                'role_id': role['id']})

        # assign a new role
        self.put(grant_url)

        # create a trust that delegates the new role
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[role['id']])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        # delete the grant
        self.delete(grant_url)

        # attempt to get a trust token with the deleted grant
        # and ensure it's unauthorized
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data,
                                 expected_status=http.client.FORBIDDEN)

    def test_trust_chained(self):
        """Test that a trust token can't be used to execute another trust.

        To do this, we create an A->B->C hierarchy of trusts, then attempt to
        execute the trusts in series (C->B->A).

        """
        # create a sub-trustee user
        sub_trustee_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=test_v3.DEFAULT_DOMAIN_ID)
        sub_trustee_user_id = sub_trustee_user['id']

        # create a new role
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        # assign the new role to trustee
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'project_id': self.project_id,
                'user_id': self.trustee_user['id'],
                'role_id': role['id']})

        # create a trust from trustor -> trustee
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust1 = self.assertValidTrustResponse(r)

        # authenticate as trustee so we can create a second trust
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            project_id=self.project_id)
        token = self.get_requested_token(auth_data)

        # create a trust from trustee -> sub-trustee
        ref = unit.new_trust_ref(
            trustor_user_id=self.trustee_user['id'],
            trustee_user_id=sub_trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[role['id']])
        r = self.post('/OS-TRUST/trusts', token=token, body={'trust': ref})
        trust2 = self.assertValidTrustResponse(r)

        # authenticate as sub-trustee and get a trust token
        auth_data = self.build_authentication_request(
            user_id=sub_trustee_user['id'],
            password=sub_trustee_user['password'],
            trust_id=trust2['id'])
        trust_token = self.get_requested_token(auth_data)

        # attempt to get the second trust using a trust token
        auth_data = self.build_authentication_request(
            token=trust_token,
            trust_id=trust1['id'])
        r = self.v3_create_token(auth_data,
                                 expected_status=http.client.FORBIDDEN)

    def assertTrustTokensRevoked(self, trust_id):
        revocation_response = self.get('/OS-REVOKE/events')
        revocation_events = revocation_response.json_body['events']
        found = False
        for event in revocation_events:
            if event.get('OS-TRUST:trust_id') == trust_id:
                found = True
        self.assertTrue(found, 'event with trust_id %s not found in list' %
                        trust_id)

    def test_delete_trust_revokes_tokens(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        trust_id = trust['id']
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust_id)
        r = self.v3_create_token(auth_data)
        self.assertValidProjectScopedTokenResponse(
            r, self.trustee_user)
        trust_token = r.headers['X-Subject-Token']
        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust_id})
        headers = {'X-Subject-Token': trust_token}
        self.head('/auth/tokens', headers=headers,
                  expected_status=http.client.NOT_FOUND)
        self.assertTrustTokensRevoked(trust_id)

    def disable_user(self, user):
        user['enabled'] = False
        PROVIDERS.identity_api.update_user(user['id'], user)

    def test_trust_get_token_fails_if_trustor_disabled(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_create_token(auth_data)

        self.disable_user(self.user)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.FORBIDDEN)

    def test_trust_get_token_fails_if_trustee_disabled(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_create_token(auth_data)

        self.disable_user(self.trustee_user)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_delete_trust(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']})

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_change_password_invalidates_trust_tokens(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_create_token(auth_data)

        self.assertValidProjectScopedTokenResponse(r, self.user)
        trust_token = r.headers.get('X-Subject-Token')

        self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.user_id, token=trust_token)

        self.assertValidUserResponse(
            self.patch('/users/%s' % self.trustee_user['id'],
                       body={'user': {'password': uuid.uuid4().hex}}))

        self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.user_id, expected_status=http.client.UNAUTHORIZED,
                 token=trust_token)

    def test_trustee_can_do_role_ops(self):
        resp = self.post('/OS-TRUST/trusts',
                         body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(resp)
        trust_token = self._get_trust_token(trust)

        resp = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles' % {
                'trust_id': trust['id']},
            token=trust_token)
        self.assertValidRoleListResponse(resp, self.role)

        self.head(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            token=trust_token,
            expected_status=http.client.OK)

        resp = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            token=trust_token)
        self.assertValidRoleResponse(resp, self.role)

    def test_do_not_consume_remaining_uses_when_get_token_fails(self):
        ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id],
            remaining_uses=3)
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        new_trust = r.result.get('trust')
        trust_id = new_trust.get('id')
        # Pass in another user's ID as the trustee, the result being a failed
        # token authenticate and the remaining_uses of the trust should not be
        # decremented.
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            trust_id=trust_id)
        self.v3_create_token(auth_data,
                             expected_status=http.client.FORBIDDEN)

        r = self.get('/OS-TRUST/trusts/%s' % trust_id)
        self.assertEqual(3, r.result.get('trust').get('remaining_uses'))


class TestTrustChain(test_v3.RestfulTestCase):

    def config_overrides(self):
        super(TestTrustChain, self).config_overrides()
        self.config_fixture.config(
            group='trust',
            allow_redelegation=True,
            max_redelegation_count=10
        )

    def setUp(self):
        super(TestTrustChain, self).setUp()
        """Create a trust chain using redelegation.

        A trust chain is a series of trusts that are redelegated. For example,
        self.user_list consists of userA, userB, and userC. The first trust in
        the trust chain is going to be established between self.user and userA,
        call it trustA. Then, userA is going to obtain a trust scoped token
        using trustA, and with that token create a trust between userA and
        userB called trustB. This pattern will continue with userB creating a
        trust with userC.
        So the trust chain should look something like:
            trustA -> trustB -> trustC
        Where:
            self.user is trusting userA with trustA
            userA is trusting userB with trustB
            userB is trusting userC with trustC

        """
        self.user_list = list()
        self.trust_chain = list()
        for _ in range(3):
            user = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain_id)
            self.user_list.append(user)

        # trustor->trustee redelegation with impersonation
        trustee = self.user_list[0]
        trust_ref = unit.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=trustee['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id],
            allow_redelegation=True,
            redelegation_count=3)

        # Create a trust between self.user and the first user in the list
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': trust_ref})

        trust = self.assertValidTrustResponse(r)
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password'],
            trust_id=trust['id'])

        # Generate a trusted token for the first user
        trust_token = self.get_requested_token(auth_data)
        self.trust_chain.append(trust)

        # Loop through the user to create a chain of redelegated trust.
        for next_trustee in self.user_list[1:]:
            trust_ref = unit.new_trust_ref(
                trustor_user_id=self.user_id,
                trustee_user_id=next_trustee['id'],
                project_id=self.project_id,
                impersonation=True,
                role_ids=[self.role_id],
                allow_redelegation=True)
            r = self.post('/OS-TRUST/trusts',
                          body={'trust': trust_ref},
                          token=trust_token)
            trust = self.assertValidTrustResponse(r)
            auth_data = self.build_authentication_request(
                user_id=next_trustee['id'],
                password=next_trustee['password'],
                trust_id=trust['id'])
            trust_token = self.get_requested_token(auth_data)
            self.trust_chain.append(trust)

        trustee = self.user_list[-1]
        trust = self.trust_chain[-1]
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password'],
            trust_id=trust['id'])

        self.last_token = self.get_requested_token(auth_data)

    def assert_user_authenticate(self, user):
        auth_data = self.build_authentication_request(
            user_id=user['id'],
            password=user['password']
        )
        r = self.v3_create_token(auth_data)
        self.assertValidTokenResponse(r)

    def assert_trust_tokens_revoked(self, trust_id):
        trustee = self.user_list[0]
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password']
        )
        r = self.v3_create_token(auth_data)
        self.assertValidTokenResponse(r)

        revocation_response = self.get('/OS-REVOKE/events')
        revocation_events = revocation_response.json_body['events']
        found = False
        for event in revocation_events:
            if event.get('OS-TRUST:trust_id') == trust_id:
                found = True
        self.assertTrue(found, 'event with trust_id %s not found in list' %
                        trust_id)

    def test_delete_trust_cascade(self):
        self.assert_user_authenticate(self.user_list[0])
        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': self.trust_chain[0]['id']})

        headers = {'X-Subject-Token': self.last_token}
        self.head('/auth/tokens', headers=headers,
                  expected_status=http.client.NOT_FOUND)
        self.assert_trust_tokens_revoked(self.trust_chain[0]['id'])

    def test_delete_broken_chain(self):
        self.assert_user_authenticate(self.user_list[0])
        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': self.trust_chain[0]['id']})

        # Verify the two remaining trust have been deleted
        for i in range(len(self.user_list) - 1):
            auth_data = self.build_authentication_request(
                user_id=self.user_list[i]['id'],
                password=self.user_list[i]['password'])

            auth_token = self.get_requested_token(auth_data)

            # Assert chained trust have been deleted
            self.get('/OS-TRUST/trusts/%(trust_id)s' % {
                'trust_id': self.trust_chain[i + 1]['id']},
                token=auth_token,
                expected_status=http.client.NOT_FOUND)

    def test_trustor_roles_revoked(self):
        self.assert_user_authenticate(self.user_list[0])

        PROVIDERS.assignment_api.remove_role_from_user_and_project(
            self.user_id, self.project_id, self.role_id
        )

        # Verify that users are not allowed to authenticate with trust
        for i in range(len(self.user_list[1:])):
            trustee = self.user_list[i]
            auth_data = self.build_authentication_request(
                user_id=trustee['id'],
                password=trustee['password'])

            # Attempt to authenticate with trust
            token = self.get_requested_token(auth_data)
            auth_data = self.build_authentication_request(
                token=token,
                trust_id=self.trust_chain[i - 1]['id'])

            # Trustee has no delegated roles
            self.v3_create_token(auth_data,
                                 expected_status=http.client.FORBIDDEN)

    def test_intermediate_user_disabled(self):
        self.assert_user_authenticate(self.user_list[0])

        disabled = self.user_list[0]
        disabled['enabled'] = False
        PROVIDERS.identity_api.update_user(disabled['id'], disabled)

        # Bypass policy enforcement
        with mock.patch.object(policy, 'enforce', return_value=True):
            headers = {'X-Subject-Token': self.last_token}
            self.head('/auth/tokens', headers=headers,
                      expected_status=http.client.FORBIDDEN)

    def test_intermediate_user_deleted(self):
        self.assert_user_authenticate(self.user_list[0])

        PROVIDERS.identity_api.delete_user(self.user_list[0]['id'])

        # Bypass policy enforcement
        # Delete trustee will invalidate the trust.
        with mock.patch.object(policy, 'enforce', return_value=True):
            headers = {'X-Subject-Token': self.last_token}
            self.head('/auth/tokens', headers=headers,
                      expected_status=http.client.NOT_FOUND)


class TestAuthContext(unit.TestCase):
    def setUp(self):
        super(TestAuthContext, self).setUp()
        self.auth_context = auth.core.AuthContext()

    def test_pick_lowest_expires_at(self):
        expires_at_1 = utils.isotime(timeutils.utcnow())
        expires_at_2 = utils.isotime(timeutils.utcnow() +
                                     datetime.timedelta(seconds=10))
        # make sure auth_context picks the lowest value
        self.auth_context['expires_at'] = expires_at_1
        self.auth_context['expires_at'] = expires_at_2
        self.assertEqual(expires_at_1, self.auth_context['expires_at'])

    def test_identity_attribute_conflict(self):
        for identity_attr in auth.core.AuthContext.IDENTITY_ATTRIBUTES:
            self.auth_context[identity_attr] = uuid.uuid4().hex
            if identity_attr == 'expires_at':
                # 'expires_at' is a special case. Will test it in a separate
                # test case.
                continue
            self.assertRaises(exception.Unauthorized,
                              operator.setitem,
                              self.auth_context,
                              identity_attr,
                              uuid.uuid4().hex)

    def test_identity_attribute_conflict_with_none_value(self):
        for identity_attr in auth.core.AuthContext.IDENTITY_ATTRIBUTES:
            self.auth_context[identity_attr] = None

            if identity_attr == 'expires_at':
                # 'expires_at' is a special case and is tested above.
                self.auth_context['expires_at'] = uuid.uuid4().hex
                continue

            self.assertRaises(exception.Unauthorized,
                              operator.setitem,
                              self.auth_context,
                              identity_attr,
                              uuid.uuid4().hex)

    def test_non_identity_attribute_conflict_override(self):
        # for attributes Keystone doesn't know about, make sure they can be
        # freely manipulated
        attr_name = uuid.uuid4().hex
        attr_val_1 = uuid.uuid4().hex
        attr_val_2 = uuid.uuid4().hex
        self.auth_context[attr_name] = attr_val_1
        self.auth_context[attr_name] = attr_val_2
        self.assertEqual(attr_val_2, self.auth_context[attr_name])


class TestAuthSpecificData(test_v3.RestfulTestCase):

    def test_get_catalog_with_project_scoped_token(self):
        """Call ``GET /auth/catalog`` with a project-scoped token."""
        r = self.get('/auth/catalog', expected_status=http.client.OK)
        self.assertValidCatalogResponse(r)

    def test_head_catalog_with_project_scoped_token(self):
        """Call ``HEAD /auth/catalog`` with a project-scoped token."""
        self.head('/auth/catalog', expected_status=http.client.OK)

    def test_get_catalog_with_domain_scoped_token(self):
        """Call ``GET /auth/catalog`` with a domain-scoped token."""
        # grant a domain role to a user
        self.put(path='/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id']))

        self.get(
            '/auth/catalog',
            auth=self.build_authentication_request(
                user_id=self.user['id'],
                password=self.user['password'],
                domain_id=self.domain['id']),
            expected_status=http.client.FORBIDDEN)

    def test_head_catalog_with_domain_scoped_token(self):
        """Call ``HEAD /auth/catalog`` with a domain-scoped token."""
        # grant a domain role to a user
        self.put(path='/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id']))

        self.head(
            '/auth/catalog',
            auth=self.build_authentication_request(
                user_id=self.user['id'],
                password=self.user['password'],
                domain_id=self.domain['id']),
            expected_status=http.client.FORBIDDEN)

    def test_get_catalog_with_unscoped_token(self):
        """Call ``GET /auth/catalog`` with an unscoped token."""
        self.get(
            '/auth/catalog',
            auth=self.build_authentication_request(
                user_id=self.default_domain_user['id'],
                password=self.default_domain_user['password']),
            expected_status=http.client.FORBIDDEN)

    def test_head_catalog_with_unscoped_token(self):
        """Call ``HEAD /auth/catalog`` with an unscoped token."""
        self.head(
            '/auth/catalog',
            auth=self.build_authentication_request(
                user_id=self.default_domain_user['id'],
                password=self.default_domain_user['password']),
            expected_status=http.client.FORBIDDEN)

    def test_get_catalog_no_token(self):
        """Call ``GET /auth/catalog`` without a token."""
        self.get(
            '/auth/catalog',
            noauth=True,
            expected_status=http.client.UNAUTHORIZED
        )

    def test_head_catalog_no_token(self):
        """Call ``HEAD /auth/catalog`` without a token."""
        self.head(
            '/auth/catalog',
            noauth=True,
            expected_status=http.client.UNAUTHORIZED
        )

    def test_get_projects_with_project_scoped_token(self):
        r = self.get('/auth/projects', expected_status=http.client.OK)
        self.assertThat(r.json['projects'], matchers.HasLength(1))
        self.assertValidProjectListResponse(r)

    def test_head_projects_with_project_scoped_token(self):
        self.head('/auth/projects', expected_status=http.client.OK)

    def test_get_projects_matches_federated_get_projects(self):
        # create at least one addition project to make sure it doesn't end up
        # in the response, since the user doesn't have any authorization on it
        ref = unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        r = self.post('/projects', body={'project': ref})
        unauthorized_project_id = r.json['project']['id']

        r = self.get('/auth/projects', expected_status=http.client.OK)
        self.assertThat(r.json['projects'], matchers.HasLength(1))
        for project in r.json['projects']:
            self.assertNotEqual(unauthorized_project_id, project['id'])

        expected_project_id = r.json['projects'][0]['id']

        # call GET /v3/OS-FEDERATION/projects
        r = self.get('/OS-FEDERATION/projects', expected_status=http.client.OK)

        # make sure the response is the same
        self.assertThat(r.json['projects'], matchers.HasLength(1))
        for project in r.json['projects']:
            self.assertEqual(expected_project_id, project['id'])

    def test_get_domains_matches_federated_get_domains(self):
        # create at least one addition domain to make sure it doesn't end up
        # in the response, since the user doesn't have any authorization on it
        ref = unit.new_domain_ref()
        r = self.post('/domains', body={'domain': ref})
        unauthorized_domain_id = r.json['domain']['id']

        ref = unit.new_domain_ref()
        r = self.post('/domains', body={'domain': ref})
        authorized_domain_id = r.json['domain']['id']

        path = '/domains/%(domain_id)s/users/%(user_id)s/roles/%(role_id)s' % {
            'domain_id': authorized_domain_id,
            'user_id': self.user_id,
            'role_id': self.role_id
        }
        self.put(path, expected_status=http.client.NO_CONTENT)

        r = self.get('/auth/domains', expected_status=http.client.OK)
        self.assertThat(r.json['domains'], matchers.HasLength(1))
        self.assertEqual(authorized_domain_id, r.json['domains'][0]['id'])
        self.assertNotEqual(unauthorized_domain_id, r.json['domains'][0]['id'])

        # call GET /v3/OS-FEDERATION/domains
        r = self.get('/OS-FEDERATION/domains', expected_status=http.client.OK)

        # make sure the response is the same
        self.assertThat(r.json['domains'], matchers.HasLength(1))
        self.assertEqual(authorized_domain_id, r.json['domains'][0]['id'])
        self.assertNotEqual(unauthorized_domain_id, r.json['domains'][0]['id'])

    def test_get_domains_with_project_scoped_token(self):
        self.put(path='/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id']))

        r = self.get('/auth/domains', expected_status=http.client.OK)
        self.assertThat(r.json['domains'], matchers.HasLength(1))
        self.assertValidDomainListResponse(r)

    def test_head_domains_with_project_scoped_token(self):
        self.put(path='/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id']))

        self.head('/auth/domains', expected_status=http.client.OK)

    def test_get_system_roles_with_unscoped_token(self):
        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        unscoped_request = self.build_authentication_request(
            user_id=self.user['id'], password=self.user['password']
        )
        r = self.post('/auth/tokens', body=unscoped_request)
        unscoped_token = r.headers.get('X-Subject-Token')
        self.assertValidUnscopedTokenResponse(r)
        response = self.get('/auth/system', token=unscoped_token)
        self.assertTrue(response.json_body['system'][0]['all'])
        self.head(
            '/auth/system', token=unscoped_token,
            expected_status=http.client.OK
        )

    def test_get_system_roles_returns_empty_list_without_system_roles(self):
        # A user without a system role assignment shouldn't expect an empty
        # list when calling /v3/auth/system regardless of calling the API with
        # an unscoped token or a project-scoped token.
        unscoped_request = self.build_authentication_request(
            user_id=self.user['id'], password=self.user['password']
        )
        r = self.post('/auth/tokens', body=unscoped_request)
        unscoped_token = r.headers.get('X-Subject-Token')
        self.assertValidUnscopedTokenResponse(r)
        response = self.get('/auth/system', token=unscoped_token)
        self.assertEqual(response.json_body['system'], [])
        self.head(
            '/auth/system', token=unscoped_token,
            expected_status=http.client.OK
        )

        project_scoped_request = self.build_authentication_request(
            user_id=self.user['id'], password=self.user['password'],
            project_id=self.project_id
        )
        r = self.post('/auth/tokens', body=project_scoped_request)
        project_scoped_token = r.headers.get('X-Subject-Token')
        self.assertValidProjectScopedTokenResponse(r)
        response = self.get('/auth/system', token=project_scoped_token)
        self.assertEqual(response.json_body['system'], [])
        self.head(
            '/auth/system', token=project_scoped_token,
            expected_status=http.client.OK
        )

    def test_get_system_roles_with_project_scoped_token(self):
        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        self.put(path='/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id']))

        domain_scoped_request = self.build_authentication_request(
            user_id=self.user['id'], password=self.user['password'],
            domain_id=self.domain['id']
        )
        r = self.post('/auth/tokens', body=domain_scoped_request)
        domain_scoped_token = r.headers.get('X-Subject-Token')
        self.assertValidDomainScopedTokenResponse(r)
        response = self.get('/auth/system', token=domain_scoped_token)
        self.assertTrue(response.json_body['system'][0]['all'])
        self.head(
            '/auth/system', token=domain_scoped_token,
            expected_status=http.client.OK
        )

    def test_get_system_roles_with_domain_scoped_token(self):
        path = '/system/users/%(user_id)s/roles/%(role_id)s' % {
            'user_id': self.user['id'],
            'role_id': self.role_id
        }
        self.put(path=path)

        project_scoped_request = self.build_authentication_request(
            user_id=self.user['id'], password=self.user['password'],
            project_id=self.project_id
        )
        r = self.post('/auth/tokens', body=project_scoped_request)
        project_scoped_token = r.headers.get('X-Subject-Token')
        self.assertValidProjectScopedTokenResponse(r)
        response = self.get('/auth/system', token=project_scoped_token)
        self.assertTrue(response.json_body['system'][0]['all'])
        self.head(
            '/auth/system', token=project_scoped_token,
            expected_status=http.client.OK
        )


class TestTrustAuthFernetTokenProvider(TrustAPIBehavior, TestTrustChain):
    def config_overrides(self):
        super(TestTrustAuthFernetTokenProvider, self).config_overrides()
        self.config_fixture.config(group='token',
                                   provider='fernet',
                                   revoke_by_id=False)
        self.config_fixture.config(group='trust')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )


class TestAuthTOTP(test_v3.RestfulTestCase):

    def setUp(self):
        super(TestAuthTOTP, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

        ref = unit.new_totp_credential(
            user_id=self.default_domain_user['id'],
            project_id=self.default_domain_project['id'])

        self.secret = ref['blob']

        r = self.post('/credentials', body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

        self.addCleanup(self.cleanup)

    def auth_plugin_config_override(self):
        methods = ['totp', 'token', 'password']
        super(TestAuthTOTP, self).auth_plugin_config_override(methods)

    def _make_credentials(self, cred_type, count=1, user_id=None,
                          project_id=None, blob=None):
        user_id = user_id or self.default_domain_user['id']
        project_id = project_id or self.default_domain_project['id']

        creds = []
        for __ in range(count):
            if cred_type == 'totp':
                ref = unit.new_totp_credential(
                    user_id=user_id, project_id=project_id, blob=blob)
            else:
                ref = unit.new_credential_ref(
                    user_id=user_id, project_id=project_id)
            resp = self.post('/credentials', body={'credential': ref})
            creds.append(resp.json['credential'])
        return creds

    def _make_auth_data_by_id(self, passcode, user_id=None):
        return self.build_authentication_request(
            user_id=user_id or self.default_domain_user['id'],
            passcode=passcode,
            project_id=self.project['id'])

    def _make_auth_data_by_name(self, passcode, username, user_domain_id):
        return self.build_authentication_request(
            username=username,
            user_domain_id=user_domain_id,
            passcode=passcode,
            project_id=self.project['id'])

    def cleanup(self):
        totp_creds = PROVIDERS.credential_api.list_credentials_for_user(
            self.default_domain_user['id'], type='totp')

        other_creds = PROVIDERS.credential_api.list_credentials_for_user(
            self.default_domain_user['id'], type='other')

        for cred in itertools.chain(other_creds, totp_creds):
            self.delete('/credentials/%s' % cred['id'],
                        expected_status=http.client.NO_CONTENT)

    def test_with_a_valid_passcode(self):
        creds = self._make_credentials('totp')
        secret = creds[-1]['blob']

        # Stop the clock otherwise there is a chance of auth failure due to
        # getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        auth_data = self._make_auth_data_by_id(
            totp._generate_totp_passcodes(secret)[0])

        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_with_an_expired_passcode(self):
        creds = self._make_credentials('totp')
        secret = creds[-1]['blob']

        past = datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
        with freezegun.freeze_time(past):
            auth_data = self._make_auth_data_by_id(
                totp._generate_totp_passcodes(secret)[0])

        # Stop the clock otherwise there is a chance of accidental success due
        # to getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_with_an_expired_passcode_no_previous_windows(self):
        self.config_fixture.config(group='totp',
                                   included_previous_windows=0)
        creds = self._make_credentials('totp')
        secret = creds[-1]['blob']

        past = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        with freezegun.freeze_time(past):
            auth_data = self._make_auth_data_by_id(
                totp._generate_totp_passcodes(secret)[0])

        # Stop the clock otherwise there is a chance of accidental success due
        # to getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_with_passcode_no_previous_windows(self):
        self.config_fixture.config(group='totp',
                                   included_previous_windows=0)
        creds = self._make_credentials('totp')
        secret = creds[-1]['blob']

        auth_data = self._make_auth_data_by_id(
            totp._generate_totp_passcodes(secret)[0])

        # Stop the clock otherwise there is a chance of auth failure due to
        # getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_with_passcode_in_previous_windows_default(self):
        """Confirm previous window default of 1 works."""
        creds = self._make_credentials('totp')
        secret = creds[-1]['blob']

        past = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        with freezegun.freeze_time(past):
            auth_data = self._make_auth_data_by_id(
                totp._generate_totp_passcodes(secret)[0])

        # Stop the clock otherwise there is a chance of auth failure due to
        # getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_with_passcode_in_previous_windows_extended(self):
        self.config_fixture.config(group='totp',
                                   included_previous_windows=4)
        creds = self._make_credentials('totp')
        secret = creds[-1]['blob']

        past = datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
        self.useFixture(fixture.TimeFixture(past))
        auth_data = self._make_auth_data_by_id(
            totp._generate_totp_passcodes(secret)[0])

        # Stop the clock otherwise there is a chance of auth failure due to
        # getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_with_an_invalid_passcode_and_user_credentials(self):
        self._make_credentials('totp')
        auth_data = self._make_auth_data_by_id('000000')
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_with_an_invalid_passcode_with_no_user_credentials(self):
        auth_data = self._make_auth_data_by_id('000000')
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_with_a_corrupt_totp_credential(self):
        self._make_credentials('totp', count=1, blob='0')
        auth_data = self._make_auth_data_by_id('000000')
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_with_multiple_credentials(self):
        self._make_credentials('other', 3)
        creds = self._make_credentials('totp', count=3)
        secret = creds[-1]['blob']

        # Stop the clock otherwise there is a chance of auth failure due to
        # getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        auth_data = self._make_auth_data_by_id(
            totp._generate_totp_passcodes(secret)[0])
        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_with_multiple_users(self):
        # make some credentials for the existing user
        self._make_credentials('totp', count=3)

        # create a new user and their credentials
        user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=user['id'], project_id=self.project['id']
        )
        creds = self._make_credentials('totp', count=1, user_id=user['id'])
        secret = creds[-1]['blob']

        # Stop the clock otherwise there is a chance of auth failure due to
        # getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        auth_data = self._make_auth_data_by_id(
            totp._generate_totp_passcodes(secret)[0], user_id=user['id'])
        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_with_multiple_users_and_invalid_credentials(self):
        """Prevent logging in with someone else's credentials.

        It's very easy to forget to limit the credentials query by user.
        Let's just test it for a sanity check.
        """
        # make some credentials for the existing user
        self._make_credentials('totp', count=3)

        # create a new user and their credentials
        new_user = unit.create_user(PROVIDERS.identity_api,
                                    domain_id=self.domain_id)
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=new_user['id'],
            project_id=self.project['id']
        )
        user2_creds = self._make_credentials(
            'totp', count=1, user_id=new_user['id'])

        user_id = self.default_domain_user['id']  # user1
        secret = user2_creds[-1]['blob']

        auth_data = self._make_auth_data_by_id(
            totp._generate_totp_passcodes(secret)[0], user_id=user_id)
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_with_username_and_domain_id(self):
        creds = self._make_credentials('totp')
        secret = creds[-1]['blob']

        # Stop the clock otherwise there is a chance of auth failure due to
        # getting a different TOTP between the call here and the call in the
        # auth plugin.
        self.useFixture(fixture.TimeFixture())

        auth_data = self._make_auth_data_by_name(
            totp._generate_totp_passcodes(secret)[0],
            username=self.default_domain_user['name'],
            user_domain_id=self.default_domain_user['domain_id'])

        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_generated_passcode_is_correct_format(self):
        secret = self._make_credentials('totp')[-1]['blob']
        passcode = totp._generate_totp_passcodes(secret)[0]
        reg = re.compile(r'^-?[0-9]+$')
        self.assertTrue(reg.match(passcode))


class TestFetchRevocationList(test_v3.RestfulTestCase):
    """Test fetch token revocation list on the v3 Identity API."""

    def config_overrides(self):
        super(TestFetchRevocationList, self).config_overrides()
        self.config_fixture.config(group='token', revoke_by_id=True)

    def test_get_ids_no_tokens_returns_forbidden(self):
        # NOTE(vishakha): Since this API is deprecated and isn't supported.
        # Returning a 403 till API is removed. If API is removed a 410
        # can be returned.
        self.get(
            '/auth/tokens/OS-PKI/revoked',
            expected_status=http.client.FORBIDDEN
        )

    def test_head_ids_no_tokens_returns_forbidden(self):
        # NOTE(vishakha): Since this API is deprecated and isn't supported.
        # Returning a 403 till API is removed. If API is removed a 410
        # can be returned.
        self.head(
            '/auth/tokens/OS-PKI/revoked',
            expected_status=http.client.FORBIDDEN
        )


class ApplicationCredentialAuth(test_v3.RestfulTestCase):

    def setUp(self):
        super(ApplicationCredentialAuth, self).setUp()
        self.app_cred_api = PROVIDERS.application_credential_api

    def config_overrides(self):
        super(ApplicationCredentialAuth, self).config_overrides()
        self.auth_plugin_config_override(
            methods=['application_credential', 'password', 'token'])

    def _make_app_cred(self, expires=None, access_rules=None):
        roles = [{'id': self.role_id}]
        data = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'user_id': self.user['id'],
            'project_id': self.project['id'],
            'description': uuid.uuid4().hex,
            'roles': roles
        }
        if expires:
            data['expires_at'] = expires
        if access_rules:
            data['access_rules'] = access_rules
        return data

    def _validate_token(self, token, headers=None,
                        expected_status=http.client.OK):
        path = '/v3/auth/tokens'
        headers = headers or {}
        headers.update({'X-Auth-Token': token, 'X-Subject-Token': token})
        with self.test_client() as c:
            resp = c.get(path, headers=headers,
                         expected_status_code=expected_status)
        return resp

    def test_valid_application_credential_succeeds(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_validate_application_credential_token_populates_restricted(self):
        self.config_fixture.config(group='token', cache_on_issue=False)
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        auth_response = self.v3_create_token(
            auth_data, expected_status=http.client.CREATED)
        self.assertTrue(
            auth_response.json['token']['application_credential']['restricted']
        )
        token_id = auth_response.headers.get('X-Subject-Token')
        headers = {'X-Auth-Token': token_id, 'X-Subject-Token': token_id}
        validate_response = self.get(
            '/auth/tokens', headers=headers
        ).json_body
        self.assertTrue(
            validate_response['token']['application_credential']['restricted']
        )

    def test_valid_application_credential_with_name_succeeds(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_name=app_cred_ref['name'], secret=app_cred_ref['secret'],
            user_id=self.user['id'])
        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_valid_application_credential_name_and_username_succeeds(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_name=app_cred_ref['name'], secret=app_cred_ref['secret'],
            username=self.user['name'], user_domain_id=self.user['domain_id'])
        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_application_credential_with_invalid_secret_fails(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret='badsecret')
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_unexpired_application_credential_succeeds(self):
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
        app_cred = self._make_app_cred(expires=expires_at)
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_expired_application_credential_fails(self):
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
        app_cred = self._make_app_cred(expires=expires_at)
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        future = datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
        with freezegun.freeze_time(future):
            self.v3_create_token(auth_data,
                                 expected_status=http.client.UNAUTHORIZED)

    def test_application_credential_fails_when_user_deleted(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        PROVIDERS.identity_api.delete_user(self.user['id'])
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data, expected_status=http.client.NOT_FOUND)

    def test_application_credential_fails_when_user_disabled(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        PROVIDERS.identity_api.update_user(self.user['id'],
                                           {'enabled': False})
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_application_credential_fails_when_project_deleted(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        PROVIDERS.resource_api.delete_project(self.project['id'])
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data, expected_status=http.client.NOT_FOUND)

    def test_application_credential_fails_when_role_deleted(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        PROVIDERS.role_api.delete_role(self.role_id)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data, expected_status=http.client.NOT_FOUND)

    def test_application_credential_fails_when_role_unassigned(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        PROVIDERS.assignment_api.remove_role_from_user_and_project(
            self.user['id'], self.project['id'],
            self.role_id)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data, expected_status=http.client.NOT_FOUND)

    def test_application_credential_through_group_membership(self):
        user1 = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )

        group1 = unit.new_group_ref(domain_id=self.domain_id)
        group1 = PROVIDERS.identity_api.create_group(group1)

        PROVIDERS.identity_api.add_user_to_group(
            user1['id'], group1['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_id, group_id=group1['id'], project_id=self.project_id
        )

        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'user_id': user1['id'],
            'project_id': self.project_id,
            'description': uuid.uuid4().hex,
            'roles': [{'id': self.role_id}]
        }

        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)

        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        self.v3_create_token(auth_data, expected_status=http.client.CREATED)

    def test_application_credential_cannot_scope(self):
        app_cred = self._make_app_cred()
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        new_project_ref = unit.new_project_ref(domain_id=self.domain_id)
        # Create a new project and assign the user a valid role on it
        new_project = PROVIDERS.resource_api.create_project(
            new_project_ref['id'], new_project_ref)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user['id'], new_project['id'], self.role_id)
        # Check that a password auth would work
        password_auth = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=new_project['id'])
        password_response = self.v3_create_token(password_auth)
        self.assertValidProjectScopedTokenResponse(password_response)
        # Should not be able to use that scope with an application credential
        # even though the user has a valid assignment on it
        app_cred_auth = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'],
            project_id=new_project['id'])
        self.v3_create_token(app_cred_auth,
                             expected_status=http.client.UNAUTHORIZED)

    def test_application_credential_with_access_rules(self):
        access_rules = [
            {
                'id': uuid.uuid4().hex,
                'path': '/v2.1/servers',
                'method': 'POST',
                'service': uuid.uuid4().hex,
            }
        ]
        app_cred = self._make_app_cred(access_rules=access_rules)
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        resp = self.v3_create_token(auth_data,
                                    expected_status=http.client.CREATED)
        token = resp.headers.get('X-Subject-Token')
        headers = {'OpenStack-Identity-Access-Rules': '1.0'}
        self._validate_token(token, headers=headers)

    def test_application_credential_access_rules_without_header_fails(self):
        access_rules = [
            {
                'id': uuid.uuid4().hex,
                'path': '/v2.1/servers',
                'method': 'POST',
                'service': uuid.uuid4().hex,
            }
        ]
        app_cred = self._make_app_cred(access_rules=access_rules)
        app_cred_ref = self.app_cred_api.create_application_credential(
            app_cred)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_ref['id'], secret=app_cred_ref['secret'])
        resp = self.v3_create_token(auth_data,
                                    expected_status=http.client.CREATED)
        token = resp.headers.get('X-Subject-Token')
        self._validate_token(token, expected_status=http.client.NOT_FOUND)
