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
import uuid

import http.client

from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class DomainConfigTestCase(test_v3.RestfulTestCase):
    """Test domain config support."""

    def setUp(self):
        super(DomainConfigTestCase, self).setUp()

        self.domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domain['id'], self.domain)
        self.config = {'ldap': {'url': uuid.uuid4().hex,
                                'user_tree_dn': uuid.uuid4().hex},
                       'identity': {'driver': uuid.uuid4().hex}}

    def test_create_config(self):
        """Call ``PUT /domains/{domain_id}/config``."""
        url = '/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']}
        r = self.put(url, body={'config': self.config},
                     expected_status=http.client.CREATED)
        res = PROVIDERS.domain_config_api.get_config(self.domain['id'])
        self.assertEqual(self.config, r.result['config'])
        self.assertEqual(self.config, res)

    def test_create_config_invalid_domain(self):
        """Call ``PUT /domains/{domain_id}/config``.

        While creating Identity API-based domain config with an invalid domain
        id provided, the request shall be rejected with a response, 404 domain
        not found.
        """
        invalid_domain_id = uuid.uuid4().hex
        url = '/domains/%(domain_id)s/config' % {
            'domain_id': invalid_domain_id}
        self.put(url, body={'config': self.config},
                 expected_status=exception.DomainNotFound.code)

    def test_create_config_twice(self):
        """Check multiple creates don't throw error."""
        self.put('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            body={'config': self.config},
            expected_status=http.client.CREATED)
        self.put('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            body={'config': self.config},
            expected_status=http.client.OK)

    def test_delete_config(self):
        """Call ``DELETE /domains{domain_id}/config``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        self.delete('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']})
        self.get('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            expected_status=exception.DomainConfigNotFound.code)

    def test_delete_config_invalid_domain(self):
        """Call ``DELETE /domains{domain_id}/config``.

        While deleting Identity API-based domain config with an invalid domain
        id provided, the request shall be rejected with a response, 404 domain
        not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        invalid_domain_id = uuid.uuid4().hex
        self.delete('/domains/%(domain_id)s/config' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_delete_config_by_group(self):
        """Call ``DELETE /domains{domain_id}/config/{group}``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        self.delete('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': self.domain['id']})
        res = PROVIDERS.domain_config_api.get_config(self.domain['id'])
        self.assertNotIn('ldap', res)

    def test_delete_config_by_group_invalid_domain(self):
        """Call ``DELETE /domains{domain_id}/config/{group}``.

        While deleting Identity API-based domain config by group with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        invalid_domain_id = uuid.uuid4().hex
        self.delete('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_get_head_config(self):
        """Call ``GET & HEAD for /domains{domain_id}/config``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        url = '/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']}
        r = self.get(url)
        self.assertEqual(self.config, r.result['config'])
        self.head(url, expected_status=http.client.OK)

    def test_get_head_config_by_group(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        url = '/domains/%(domain_id)s/config/ldap' % {
            'domain_id': self.domain['id']}
        r = self.get(url)
        self.assertEqual({'ldap': self.config['ldap']}, r.result['config'])
        self.head(url, expected_status=http.client.OK)

    def test_get_head_config_by_group_invalid_domain(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}``.

        While retrieving Identity API-based domain config by group with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        invalid_domain_id = uuid.uuid4().hex
        url = ('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': invalid_domain_id}
        )
        self.get(url, expected_status=exception.DomainNotFound.code)
        self.head(url, expected_status=exception.DomainNotFound.code)

    def test_get_head_config_by_option(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}/{option}``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        url = '/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': self.domain['id']}
        r = self.get(url)
        self.assertEqual({'url': self.config['ldap']['url']},
                         r.result['config'])
        self.head(url, expected_status=http.client.OK)

    def test_get_head_config_by_option_invalid_domain(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}/{option}``.

        While retrieving Identity API-based domain config by option with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        invalid_domain_id = uuid.uuid4().hex
        url = ('/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': invalid_domain_id}
        )
        self.get(url, expected_status=exception.DomainNotFound.code)
        self.head(url, expected_status=exception.DomainNotFound.code)

    def test_get_head_non_existant_config(self):
        """Call ``GET /domains{domain_id}/config when no config defined``."""
        url = ('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']}
        )
        self.get(url, expected_status=http.client.NOT_FOUND)
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_get_head_non_existant_config_invalid_domain(self):
        """Call ``GET & HEAD /domains/{domain_id}/config with invalid domain``.

        While retrieving non-existent Identity API-based domain config with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        invalid_domain_id = uuid.uuid4().hex
        url = ('/domains/%(domain_id)s/config' % {
            'domain_id': invalid_domain_id}
        )
        self.get(url, expected_status=exception.DomainNotFound.code)
        self.head(url, expected_status=exception.DomainNotFound.code)

    def test_get_head_non_existant_config_group(self):
        """Call ``GET /domains/{domain_id}/config/{group_not_exist}``."""
        config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(self.domain['id'], config)
        url = ('/domains/%(domain_id)s/config/identity' % {
            'domain_id': self.domain['id']}
        )
        self.get(url, expected_status=http.client.NOT_FOUND)
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_get_head_non_existant_config_group_invalid_domain(self):
        """Call ``GET & HEAD /domains/{domain_id}/config/{group}``.

        While retrieving non-existent Identity API-based domain config group
        with an invalid domain id provided, the request shall be rejected with
        a response, 404 domain not found.
        """
        config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(self.domain['id'], config)
        invalid_domain_id = uuid.uuid4().hex
        url = ('/domains/%(domain_id)s/config/identity' % {
            'domain_id': invalid_domain_id}
        )
        self.get(url, expected_status=exception.DomainNotFound.code)
        self.head(url, expected_status=exception.DomainNotFound.code)

    def test_get_head_non_existant_config_option(self):
        """Test that Not Found is returned when option doesn't exist.

        Call ``GET & HEAD /domains/{domain_id}/config/{group}/{opt_not_exist}``
        and ensure a Not Found is returned because the option isn't defined
        within the group.
        """
        config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(self.domain['id'], config)
        url = ('/domains/%(domain_id)s/config/ldap/user_tree_dn' % {
            'domain_id': self.domain['id']}
        )
        self.get(url, expected_status=http.client.NOT_FOUND)
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_get_head_non_existant_config_option_with_invalid_domain(self):
        """Test that Domain Not Found is returned with invalid domain.

        Call ``GET & HEAD /domains/{domain_id}/config/{group}/{opt_not_exist}``

        While retrieving non-existent Identity API-based domain config option
        with an invalid domain id provided, the request shall be rejected with
        a response, 404 domain not found.
        """
        config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(self.domain['id'], config)
        invalid_domain_id = uuid.uuid4().hex
        url = ('/domains/%(domain_id)s/config/ldap/user_tree_dn' % {
            'domain_id': invalid_domain_id}
        )
        self.get(url, expected_status=exception.DomainNotFound.code)
        self.head(url, expected_status=exception.DomainNotFound.code)

    def test_update_config(self):
        """Call ``PATCH /domains/{domain_id}/config``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        new_config = {'ldap': {'url': uuid.uuid4().hex},
                      'identity': {'driver': uuid.uuid4().hex}}
        r = self.patch('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            body={'config': new_config})
        res = PROVIDERS.domain_config_api.get_config(self.domain['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['ldap']['url']
        expected_config['identity']['driver'] = (
            new_config['identity']['driver'])
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config``.

        While updating Identity API-based domain config with an invalid domain
        id provided, the request shall be rejected with a response, 404 domain
        not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        new_config = {'ldap': {'url': uuid.uuid4().hex},
                      'identity': {'driver': uuid.uuid4().hex}}
        invalid_domain_id = uuid.uuid4().hex
        self.patch('/domains/%(domain_id)s/config' % {
            'domain_id': invalid_domain_id},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_update_config_group(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        r = self.patch('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': self.domain['id']},
            body={'config': new_config})
        res = PROVIDERS.domain_config_api.get_config(self.domain['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['ldap']['url']
        expected_config['ldap']['user_filter'] = (
            new_config['ldap']['user_filter'])
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_group_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}``.

        While updating Identity API-based domain config group with an invalid
        domain id provided, the request shall be rejected with a response,
        404 domain not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        invalid_domain_id = uuid.uuid4().hex
        self.patch('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': invalid_domain_id},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_update_config_invalid_group(self):
        """Call ``PATCH /domains/{domain_id}/config/{invalid_group}``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )

        # Trying to update a group that is neither whitelisted or sensitive
        # should result in Forbidden.
        invalid_group = uuid.uuid4().hex
        new_config = {invalid_group: {'url': uuid.uuid4().hex,
                                      'user_filter': uuid.uuid4().hex}}
        self.patch('/domains/%(domain_id)s/config/%(invalid_group)s' % {
            'domain_id': self.domain['id'], 'invalid_group': invalid_group},
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN)
        # Trying to update a valid group, but one that is not in the current
        # config should result in NotFound
        config = {'ldap': {'suffix': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(self.domain['id'], config)
        new_config = {'identity': {'driver': uuid.uuid4().hex}}
        self.patch('/domains/%(domain_id)s/config/identity' % {
            'domain_id': self.domain['id']},
            body={'config': new_config},
            expected_status=http.client.NOT_FOUND)

    def test_update_config_invalid_group_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{invalid_group}``.

        While updating Identity API-based domain config with an invalid group
        and an invalid domain id provided, the request shall be rejected
        with a response, 404 domain not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        invalid_group = uuid.uuid4().hex
        new_config = {invalid_group: {'url': uuid.uuid4().hex,
                                      'user_filter': uuid.uuid4().hex}}
        invalid_domain_id = uuid.uuid4().hex
        self.patch('/domains/%(domain_id)s/config/%(invalid_group)s' % {
            'domain_id': invalid_domain_id,
            'invalid_group': invalid_group},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_update_config_option(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}/{option}``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        new_config = {'url': uuid.uuid4().hex}
        r = self.patch('/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': self.domain['id']},
            body={'config': new_config})
        res = PROVIDERS.domain_config_api.get_config(self.domain['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['url']
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_option_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}/{option}``.

        While updating Identity API-based domain config option with an invalid
        domain id provided, the request shall be rejected with a response, 404
        domain not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        new_config = {'url': uuid.uuid4().hex}
        invalid_domain_id = uuid.uuid4().hex
        self.patch('/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': invalid_domain_id},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_update_config_invalid_option(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}/{invalid}``."""
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        invalid_option = uuid.uuid4().hex
        new_config = {'ldap': {invalid_option: uuid.uuid4().hex}}
        # Trying to update an option that is neither whitelisted or sensitive
        # should result in Forbidden.
        self.patch(
            '/domains/%(domain_id)s/config/ldap/%(invalid_option)s' % {
                'domain_id': self.domain['id'],
                'invalid_option': invalid_option},
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN)
        # Trying to update a valid option, but one that is not in the current
        # config should result in NotFound
        new_config = {'suffix': uuid.uuid4().hex}
        self.patch(
            '/domains/%(domain_id)s/config/ldap/suffix' % {
                'domain_id': self.domain['id']},
            body={'config': new_config},
            expected_status=http.client.NOT_FOUND)

    def test_update_config_invalid_option_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}/{invalid}``.

        While updating Identity API-based domain config with an invalid option
        and an invalid domain id provided, the request shall be rejected
        with a response, 404 domain not found.
        """
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        invalid_option = uuid.uuid4().hex
        new_config = {'ldap': {invalid_option: uuid.uuid4().hex}}
        invalid_domain_id = uuid.uuid4().hex
        self.patch(
            '/domains/%(domain_id)s/config/ldap/%(invalid_option)s' % {
                'domain_id': invalid_domain_id,
                'invalid_option': invalid_option},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_get_head_config_default(self):
        """Call ``GET & HEAD /domains/config/default``."""
        # Create a config that overrides a few of the options so that we can
        # check that only the defaults are returned.
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        url = '/domains/config/default'
        r = self.get(url)
        default_config = r.result['config']
        for group in default_config:
            for option in default_config[group]:
                self.assertEqual(getattr(getattr(CONF, group), option),
                                 default_config[group][option])
        self.head(url, expected_status=http.client.OK)

    def test_get_head_config_default_by_group(self):
        """Call ``GET & HEAD /domains/config/{group}/default``."""
        # Create a config that overrides a few of the options so that we can
        # check that only the defaults are returned.
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        url = '/domains/config/ldap/default'
        r = self.get(url)
        default_config = r.result['config']
        for option in default_config['ldap']:
            self.assertEqual(getattr(CONF.ldap, option),
                             default_config['ldap'][option])
        self.head(url, expected_status=http.client.OK)

    def test_get_head_config_default_by_option(self):
        """Call ``GET & HEAD /domains/config/{group}/{option}/default``."""
        # Create a config that overrides a few of the options so that we can
        # check that only the defaults are returned.
        PROVIDERS.domain_config_api.create_config(
            self.domain['id'], self.config
        )
        url = '/domains/config/ldap/url/default'
        r = self.get(url)
        default_config = r.result['config']
        self.assertEqual(CONF.ldap.url, default_config['url'])
        self.head(url, expected_status=http.client.OK)

    def test_get_head_config_default_by_invalid_group(self):
        """Call ``GET & HEAD for /domains/config/{bad-group}/default``."""
        # First try a valid group, but one we don't support for domain config
        self.get('/domains/config/resource/default',
                 expected_status=http.client.FORBIDDEN)
        self.head('/domains/config/resource/default',
                  expected_status=http.client.FORBIDDEN)

        # Now try a totally invalid group
        url = '/domains/config/%s/default' % uuid.uuid4().hex
        self.get(url, expected_status=http.client.FORBIDDEN)
        self.head(url, expected_status=http.client.FORBIDDEN)

    def test_get_head_config_default_for_unsupported_group(self):
        # It should not be possible to expose configuration information for
        # groups that the domain configuration API backlists explicitly. Doing
        # so would be a security vulnerability because it would leak sensitive
        # information over the API.
        self.get('/domains/config/ldap/password/default',
                 expected_status=http.client.FORBIDDEN)
        self.head('/domains/config/ldap/password/default',
                  expected_status=http.client.FORBIDDEN)

    def test_get_head_config_default_for_invalid_option(self):
        """Returning invalid configuration options is invalid."""
        url = '/domains/config/ldap/%s/default' % uuid.uuid4().hex
        self.get(url, expected_status=http.client.FORBIDDEN)
        self.head(url, expected_status=http.client.FORBIDDEN)


class SecurityRequirementsTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(SecurityRequirementsTestCase, self).setUp()

        # Create a user in the default domain
        self.non_admin_user = unit.create_user(
            PROVIDERS.identity_api,
            CONF.identity.default_domain_id
        )

        # Create an admin in the default domain
        self.admin_user = unit.create_user(
            PROVIDERS.identity_api,
            CONF.identity.default_domain_id
        )

        # Create a project in the default domain and a non-admin role
        self.project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        PROVIDERS.resource_api.create_project(self.project['id'], self.project)
        self.non_admin_role = unit.new_role_ref(name='not_admin')
        PROVIDERS.role_api.create_role(
            self.non_admin_role['id'],
            self.non_admin_role
        )

        # Give the non-admin user a role on the project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.non_admin_user['id'],
            self.project['id'],
            self.role['id']
        )

        # Give the user the admin role on the project, which is technically
        # `self.role` because RestfulTestCase sets that up for us.
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.admin_user['id'],
            self.project['id'],
            self.role_id
        )

    def _get_non_admin_token(self):
        non_admin_auth_data = self.build_authentication_request(
            user_id=self.non_admin_user['id'],
            password=self.non_admin_user['password'],
            project_id=self.project['id']
        )
        return self.get_requested_token(non_admin_auth_data)

    def _get_admin_token(self):
        non_admin_auth_data = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id']
        )
        return self.get_requested_token(non_admin_auth_data)

    def test_get_head_security_compliance_config_for_default_domain(self):
        """Ask for all security compliance configuration options.

        Support for enforcing security compliance per domain currently doesn't
        exist. Make sure when we ask for security compliance information, it's
        only for the default domain and that it only returns whitelisted
        options.
        """
        password_regex = uuid.uuid4().hex
        password_regex_description = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex=password_regex
        )
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=password_regex_description
        )
        expected_response = {
            'security_compliance': {
                'password_regex': password_regex,
                'password_regex_description': password_regex_description
            }
        }
        url = (
            '/domains/%(domain_id)s/config/%(group)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': 'security_compliance',
            }
        )

        # Make sure regular users and administrators can get security
        # requirement information.
        regular_response = self.get(url, token=self._get_non_admin_token())
        self.assertEqual(regular_response.result['config'], expected_response)
        admin_response = self.get(url, token=self._get_admin_token())
        self.assertEqual(admin_response.result['config'], expected_response)

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            token=self._get_non_admin_token(),
            expected_status=http.client.OK
        )
        self.head(
            url,
            token=self._get_admin_token(),
            expected_status=http.client.OK
        )

    def test_get_security_compliance_config_for_non_default_domain_fails(self):
        """Getting security compliance opts for other domains should fail.

        Support for enforcing security compliance rules per domain currently
        does not exist, so exposing security compliance information for any
        domain other than the default domain should not be allowed.
        """
        # Create a new domain that is not the default domain
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        # Set the security compliance configuration options
        password_regex = uuid.uuid4().hex
        password_regex_description = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex=password_regex
        )
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=password_regex_description
        )
        url = (
            '/domains/%(domain_id)s/config/%(group)s' %
            {
                'domain_id': domain['id'],
                'group': 'security_compliance',
            }
        )

        # Make sure regular users and administrators are forbidden from doing
        # this.
        self.get(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.get(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.head(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_get_non_whitelisted_security_compliance_opt_fails(self):
        """We only support exposing a subset of security compliance options.

        Given that security compliance information is sensitive in nature, we
        should make sure that only the options we want to expose are readable
        via the API.
        """
        # Set a security compliance configuration that isn't whitelisted
        self.config_fixture.config(
            group='security_compliance',
            lockout_failure_attempts=1
        )
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': 'security_compliance',
                'option': 'lockout_failure_attempts'
            }
        )

        # Make sure regular users and administrators are unable to ask for
        # sensitive information.
        self.get(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.get(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.head(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_get_security_compliance_password_regex(self):
        """Ask for the security compliance password regular expression."""
        password_regex = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex=password_regex
        )
        group = 'security_compliance'
        option = 'password_regex'
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
                'option': option
            }
        )

        # Make sure regular users and administrators can ask for the
        # password regular expression.
        regular_response = self.get(url, token=self._get_non_admin_token())
        self.assertEqual(
            regular_response.result['config'][option],
            password_regex
        )
        admin_response = self.get(url, token=self._get_admin_token())
        self.assertEqual(
            admin_response.result['config'][option],
            password_regex
        )

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            token=self._get_non_admin_token(),
            expected_status=http.client.OK
        )
        self.head(
            url,
            token=self._get_admin_token(),
            expected_status=http.client.OK
        )

    def test_get_security_compliance_password_regex_description(self):
        """Ask for the security compliance password regex description."""
        password_regex_description = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=password_regex_description
        )
        group = 'security_compliance'
        option = 'password_regex_description'
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
                'option': option
            }
        )

        # Make sure regular users and administrators can ask for the
        # password regular expression.
        regular_response = self.get(url, token=self._get_non_admin_token())
        self.assertEqual(
            regular_response.result['config'][option],
            password_regex_description
        )
        admin_response = self.get(url, token=self._get_admin_token())
        self.assertEqual(
            admin_response.result['config'][option],
            password_regex_description
        )

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            token=self._get_non_admin_token(),
            expected_status=http.client.OK
        )
        self.head(
            url,
            token=self._get_admin_token(),
            expected_status=http.client.OK
        )

    def test_get_security_compliance_password_regex_returns_none(self):
        """When an option isn't set, we should explicitly return None."""
        group = 'security_compliance'
        option = 'password_regex'
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
                'option': option
            }
        )

        # Make sure regular users and administrators can ask for the password
        # regular expression, but since it isn't set the returned value should
        # be None.
        regular_response = self.get(url, token=self._get_non_admin_token())
        self.assertIsNone(regular_response.result['config'][option])
        admin_response = self.get(url, token=self._get_admin_token())
        self.assertIsNone(admin_response.result['config'][option])

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            token=self._get_non_admin_token(),
            expected_status=http.client.OK
        )
        self.head(
            url,
            token=self._get_admin_token(),
            expected_status=http.client.OK
        )

    def test_get_security_compliance_password_regex_desc_returns_none(self):
        """When an option isn't set, we should explicitly return None."""
        group = 'security_compliance'
        option = 'password_regex_description'
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
                'option': option
            }
        )

        # Make sure regular users and administrators can ask for the password
        # regular expression description, but since it isn't set the returned
        # value should be None.
        regular_response = self.get(url, token=self._get_non_admin_token())
        self.assertIsNone(regular_response.result['config'][option])
        admin_response = self.get(url, token=self._get_admin_token())
        self.assertIsNone(admin_response.result['config'][option])

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            token=self._get_non_admin_token(),
            expected_status=http.client.OK
        )
        self.head(
            url,
            token=self._get_admin_token(),
            expected_status=http.client.OK
        )

    def test_get_security_compliance_config_with_user_from_other_domain(self):
        """Make sure users from other domains can access password requirements.

        Even though a user is in a separate domain, they should be able to see
        the security requirements for the deployment. This is because security
        compliance is not yet implemented on a per domain basis. Once that
        happens, then this should no longer be possible since a user should
        only care about the security compliance requirements for the domain
        that they are in.
        """
        # Make a new domain
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        # Create a user in the new domain
        user = unit.create_user(PROVIDERS.identity_api, domain['id'])

        # Create a project in the new domain
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)

        # Give the new user a non-admin role on the project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'],
            project['id'],
            self.non_admin_role['id']
        )

        # Set our security compliance config values, we do this after we've
        # created our test user otherwise password validation will fail with a
        # uuid type regex.
        password_regex = uuid.uuid4().hex
        password_regex_description = uuid.uuid4().hex
        group = 'security_compliance'
        self.config_fixture.config(
            group=group,
            password_regex=password_regex
        )
        self.config_fixture.config(
            group=group,
            password_regex_description=password_regex_description
        )

        # Get a token for the newly created user scoped to the project in the
        # non-default domain and use it to get the password security
        # requirements.
        user_token = self.build_authentication_request(
            user_id=user['id'],
            password=user['password'],
            project_id=project['id']
        )
        user_token = self.get_requested_token(user_token)
        url = (
            '/domains/%(domain_id)s/config/%(group)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
            }
        )
        response = self.get(url, token=user_token)
        self.assertEqual(
            response.result['config'][group]['password_regex'],
            password_regex
        )
        self.assertEqual(
            response.result['config'][group]['password_regex_description'],
            password_regex_description
        )

        # Ensure HEAD requests behave the same way
        self.head(
            url,
            token=user_token,
            expected_status=http.client.OK
        )

    def test_update_security_compliance_config_group_fails(self):
        """Make sure that updates to the entire security group section fail.

        We should only allow the ability to modify a deployments security
        compliance rules through configuration. Especially since it's only
        enforced on the default domain.
        """
        new_config = {
            'security_compliance': {
                'password_regex': uuid.uuid4().hex,
                'password_regex_description': uuid.uuid4().hex
            }
        }
        url = (
            '/domains/%(domain_id)s/config/%(group)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': 'security_compliance',
            }
        )

        # Make sure regular users and administrators aren't allowed to modify
        # security compliance configuration through the API.
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_update_security_compliance_password_regex_fails(self):
        """Make sure any updates to security compliance options fail."""
        group = 'security_compliance'
        option = 'password_regex'
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
                'option': option
            }
        )
        new_config = {
            group: {
                option: uuid.uuid4().hex
            }
        }

        # Make sure regular users and administrators aren't allowed to modify
        # security compliance configuration through the API.
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_update_security_compliance_password_regex_description_fails(self):
        """Make sure any updates to security compliance options fail."""
        group = 'security_compliance'
        option = 'password_regex_description'
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
                'option': option
            }
        )
        new_config = {
            group: {
                option: uuid.uuid4().hex
            }
        }

        # Make sure regular users and administrators aren't allowed to modify
        # security compliance configuration through the API.
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_update_non_whitelisted_security_compliance_option_fails(self):
        """Updating security compliance options through the API is not allowed.

        Requests to update anything in the security compliance group through
        the API should be Forbidden. This ensures that we are covering cases
        where the option being updated isn't in the white list.
        """
        group = 'security_compliance'
        option = 'lockout_failure_attempts'
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': group,
                'option': option
            }
        )
        new_config = {
            group: {
                option: 1
            }
        }

        # Make sure this behavior is not possible for regular users or
        # administrators.
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.patch(
            url,
            body={'config': new_config},
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_delete_security_compliance_group_fails(self):
        """The security compliance group shouldn't be deleteable."""
        url = (
            '/domains/%(domain_id)s/config/%(group)s/' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': 'security_compliance',
            }
        )

        # Make sure regular users and administrators can't delete the security
        # compliance configuration group.
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_delete_security_compliance_password_regex_fails(self):
        """The security compliance options shouldn't be deleteable."""
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': 'security_compliance',
                'option': 'password_regex'
            }
        )

        # Make sure regular users and administrators can't delete the security
        # compliance configuration group.
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_delete_security_compliance_password_regex_description_fails(self):
        """The security compliance options shouldn't be deleteable."""
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': 'security_compliance',
                'option': 'password_regex_description'
            }
        )

        # Make sure regular users and administrators can't delete the security
        # compliance configuration group.
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )

    def test_delete_non_whitelisted_security_compliance_options_fails(self):
        """The security compliance options shouldn't be deleteable."""
        url = (
            '/domains/%(domain_id)s/config/%(group)s/%(option)s' %
            {
                'domain_id': CONF.identity.default_domain_id,
                'group': 'security_compliance',
                'option': 'lockout_failure_attempts'
            }
        )

        # Make sure regular users and administrators can't delete the security
        # compliance configuration group.
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_non_admin_token()
        )
        self.delete(
            url,
            expected_status=http.client.FORBIDDEN,
            token=self._get_admin_token()
        )
