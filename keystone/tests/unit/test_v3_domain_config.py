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

from oslo_config import cfg
from six.moves import http_client

from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = cfg.CONF


class DomainConfigTestCase(test_v3.RestfulTestCase):
    """Test domain config support."""

    def setUp(self):
        super(DomainConfigTestCase, self).setUp()

        self.domain = unit.new_domain_ref()
        self.resource_api.create_domain(self.domain['id'], self.domain)
        self.config = {'ldap': {'url': uuid.uuid4().hex,
                                'user_tree_dn': uuid.uuid4().hex},
                       'identity': {'driver': uuid.uuid4().hex}}

    def test_create_config(self):
        """Call ``PUT /domains/{domain_id}/config``."""
        url = '/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']}
        r = self.put(url, body={'config': self.config},
                     expected_status=http_client.CREATED)
        res = self.domain_config_api.get_config(self.domain['id'])
        self.assertEqual(self.config, r.result['config'])
        self.assertEqual(self.config, res)

    def test_create_config_invalid_domain(self):
        """Call ``PUT /domains/{domain_id}/config``

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
        """Check multiple creates don't throw error"""
        self.put('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            body={'config': self.config},
            expected_status=http_client.CREATED)
        self.put('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            body={'config': self.config},
            expected_status=http_client.OK)

    def test_delete_config(self):
        """Call ``DELETE /domains{domain_id}/config``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        self.delete('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']})
        self.get('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            expected_status=exception.DomainConfigNotFound.code)

    def test_delete_config_invalid_domain(self):
        """Call ``DELETE /domains{domain_id}/config``

        While deleting Identity API-based domain config with an invalid domain
        id provided, the request shall be rejected with a response, 404 domain
        not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        invalid_domain_id = uuid.uuid4().hex
        self.delete('/domains/%(domain_id)s/config' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_delete_config_by_group(self):
        """Call ``DELETE /domains{domain_id}/config/{group}``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        self.delete('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': self.domain['id']})
        res = self.domain_config_api.get_config(self.domain['id'])
        self.assertNotIn('ldap', res)

    def test_delete_config_by_group_invalid_domain(self):
        """Call ``DELETE /domains{domain_id}/config/{group}``

        While deleting Identity API-based domain config by group with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        invalid_domain_id = uuid.uuid4().hex
        self.delete('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_get_head_config(self):
        """Call ``GET & HEAD for /domains{domain_id}/config``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        url = '/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']}
        r = self.get(url)
        self.assertEqual(self.config, r.result['config'])
        self.head(url, expected_status=http_client.OK)

    def test_get_config_by_group(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        url = '/domains/%(domain_id)s/config/ldap' % {
            'domain_id': self.domain['id']}
        r = self.get(url)
        self.assertEqual({'ldap': self.config['ldap']}, r.result['config'])
        self.head(url, expected_status=http_client.OK)

    def test_get_config_by_group_invalid_domain(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}``

        While retrieving Identity API-based domain config by group with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        invalid_domain_id = uuid.uuid4().hex
        self.get('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_get_config_by_option(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}/{option}``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        url = '/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': self.domain['id']}
        r = self.get(url)
        self.assertEqual({'url': self.config['ldap']['url']},
                         r.result['config'])
        self.head(url, expected_status=http_client.OK)

    def test_get_config_by_option_invalid_domain(self):
        """Call ``GET & HEAD /domains{domain_id}/config/{group}/{option}``

        While retrieving Identity API-based domain config by option with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        invalid_domain_id = uuid.uuid4().hex
        self.get('/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_get_non_existant_config(self):
        """Call ``GET /domains{domain_id}/config when no config defined``."""
        self.get('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            expected_status=http_client.NOT_FOUND)

    def test_get_non_existant_config_invalid_domain(self):
        """Call ``GET /domains{domain_id}/config when no config defined``

        While retrieving non-existent Identity API-based domain config with an
        invalid domain id provided, the request shall be rejected with a
        response 404 domain not found.
        """
        invalid_domain_id = uuid.uuid4().hex
        self.get('/domains/%(domain_id)s/config' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_get_non_existant_config_group(self):
        """Call ``GET /domains{domain_id}/config/{group_not_exist}``."""
        config = {'ldap': {'url': uuid.uuid4().hex}}
        self.domain_config_api.create_config(self.domain['id'], config)
        self.get('/domains/%(domain_id)s/config/identity' % {
            'domain_id': self.domain['id']},
            expected_status=http_client.NOT_FOUND)

    def test_get_non_existant_config_group_invalid_domain(self):
        """Call ``GET /domains{domain_id}/config/{group_not_exist}``

        While retrieving non-existent Identity API-based domain config group
        with an invalid domain id provided, the request shall be rejected with
        a response, 404 domain not found.
        """
        config = {'ldap': {'url': uuid.uuid4().hex}}
        self.domain_config_api.create_config(self.domain['id'], config)
        invalid_domain_id = uuid.uuid4().hex
        self.get('/domains/%(domain_id)s/config/identity' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_get_non_existant_config_option(self):
        """Call ``GET /domains{domain_id}/config/group/{option_not_exist}``."""
        config = {'ldap': {'url': uuid.uuid4().hex}}
        self.domain_config_api.create_config(self.domain['id'], config)
        self.get('/domains/%(domain_id)s/config/ldap/user_tree_dn' % {
            'domain_id': self.domain['id']},
            expected_status=http_client.NOT_FOUND)

    def test_get_non_existant_config_option_invalid_domain(self):
        """Call ``GET /domains{domain_id}/config/group/{option_not_exist}``

        While retrieving non-existent Identity API-based domain config option
        with an invalid domain id provided, the request shall be rejected with
        a response, 404 domain not found.
        """
        config = {'ldap': {'url': uuid.uuid4().hex}}
        self.domain_config_api.create_config(self.domain['id'], config)
        invalid_domain_id = uuid.uuid4().hex
        self.get('/domains/%(domain_id)s/config/ldap/user_tree_dn' % {
            'domain_id': invalid_domain_id},
            expected_status=exception.DomainNotFound.code)

    def test_update_config(self):
        """Call ``PATCH /domains/{domain_id}/config``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        new_config = {'ldap': {'url': uuid.uuid4().hex},
                      'identity': {'driver': uuid.uuid4().hex}}
        r = self.patch('/domains/%(domain_id)s/config' % {
            'domain_id': self.domain['id']},
            body={'config': new_config})
        res = self.domain_config_api.get_config(self.domain['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['ldap']['url']
        expected_config['identity']['driver'] = (
            new_config['identity']['driver'])
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config``

        While updating Identity API-based domain config with an invalid domain
        id provided, the request shall be rejected with a response, 404 domain
        not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        new_config = {'ldap': {'url': uuid.uuid4().hex},
                      'identity': {'driver': uuid.uuid4().hex}}
        invalid_domain_id = uuid.uuid4().hex
        self.patch('/domains/%(domain_id)s/config' % {
            'domain_id': invalid_domain_id},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_update_config_group(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        r = self.patch('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': self.domain['id']},
            body={'config': new_config})
        res = self.domain_config_api.get_config(self.domain['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['ldap']['url']
        expected_config['ldap']['user_filter'] = (
            new_config['ldap']['user_filter'])
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_group_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}``

        While updating Identity API-based domain config group with an invalid
        domain id provided, the request shall be rejected with a response,
        404 domain not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        invalid_domain_id = uuid.uuid4().hex
        self.patch('/domains/%(domain_id)s/config/ldap' % {
            'domain_id': invalid_domain_id},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_update_config_invalid_group(self):
        """Call ``PATCH /domains/{domain_id}/config/{invalid_group}``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)

        # Trying to update a group that is neither whitelisted or sensitive
        # should result in Forbidden.
        invalid_group = uuid.uuid4().hex
        new_config = {invalid_group: {'url': uuid.uuid4().hex,
                                      'user_filter': uuid.uuid4().hex}}
        self.patch('/domains/%(domain_id)s/config/%(invalid_group)s' % {
            'domain_id': self.domain['id'], 'invalid_group': invalid_group},
            body={'config': new_config},
            expected_status=http_client.FORBIDDEN)
        # Trying to update a valid group, but one that is not in the current
        # config should result in NotFound
        config = {'ldap': {'suffix': uuid.uuid4().hex}}
        self.domain_config_api.create_config(self.domain['id'], config)
        new_config = {'identity': {'driver': uuid.uuid4().hex}}
        self.patch('/domains/%(domain_id)s/config/identity' % {
            'domain_id': self.domain['id']},
            body={'config': new_config},
            expected_status=http_client.NOT_FOUND)

    def test_update_config_invalid_group_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{invalid_group}``

        While updating Identity API-based domain config with an invalid group
        and an invalid domain id provided, the request shall be rejected
        with a response, 404 domain not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
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
        self.domain_config_api.create_config(self.domain['id'], self.config)
        new_config = {'url': uuid.uuid4().hex}
        r = self.patch('/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': self.domain['id']},
            body={'config': new_config})
        res = self.domain_config_api.get_config(self.domain['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['url']
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_option_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}/{option}``

        While updating Identity API-based domain config option with an invalid
        domain id provided, the request shall be rejected with a response, 404
        domain not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        new_config = {'url': uuid.uuid4().hex}
        invalid_domain_id = uuid.uuid4().hex
        self.patch('/domains/%(domain_id)s/config/ldap/url' % {
            'domain_id': invalid_domain_id},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_update_config_invalid_option(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}/{invalid}``."""
        self.domain_config_api.create_config(self.domain['id'], self.config)
        invalid_option = uuid.uuid4().hex
        new_config = {'ldap': {invalid_option: uuid.uuid4().hex}}
        # Trying to update an option that is neither whitelisted or sensitive
        # should result in Forbidden.
        self.patch(
            '/domains/%(domain_id)s/config/ldap/%(invalid_option)s' % {
                'domain_id': self.domain['id'],
                'invalid_option': invalid_option},
            body={'config': new_config},
            expected_status=http_client.FORBIDDEN)
        # Trying to update a valid option, but one that is not in the current
        # config should result in NotFound
        new_config = {'suffix': uuid.uuid4().hex}
        self.patch(
            '/domains/%(domain_id)s/config/ldap/suffix' % {
                'domain_id': self.domain['id']},
            body={'config': new_config},
            expected_status=http_client.NOT_FOUND)

    def test_update_config_invalid_option_invalid_domain(self):
        """Call ``PATCH /domains/{domain_id}/config/{group}/{invalid}``

        While updating Identity API-based domain config with an invalid option
        and an invalid domain id provided, the request shall be rejected
        with a response, 404 domain not found.
        """
        self.domain_config_api.create_config(self.domain['id'], self.config)
        invalid_option = uuid.uuid4().hex
        new_config = {'ldap': {invalid_option: uuid.uuid4().hex}}
        invalid_domain_id = uuid.uuid4().hex
        self.patch(
            '/domains/%(domain_id)s/config/ldap/%(invalid_option)s' % {
                'domain_id': invalid_domain_id,
                'invalid_option': invalid_option},
            body={'config': new_config},
            expected_status=exception.DomainNotFound.code)

    def test_get_config_default(self):
        """Call ``GET /domains/config/default``."""
        # Create a config that overrides a few of the options so that we can
        # check that only the defaults are returned.
        self.domain_config_api.create_config(self.domain['id'], self.config)
        url = '/domains/config/default'
        r = self.get(url)
        default_config = r.result['config']
        for group in default_config:
            for option in default_config[group]:
                self.assertEqual(getattr(getattr(CONF, group), option),
                                 default_config[group][option])

    def test_get_config_default_by_group(self):
        """Call ``GET /domains/config/{group}/default``."""
        # Create a config that overrides a few of the options so that we can
        # check that only the defaults are returned.
        self.domain_config_api.create_config(self.domain['id'], self.config)
        url = '/domains/config/ldap/default'
        r = self.get(url)
        default_config = r.result['config']
        for option in default_config['ldap']:
            self.assertEqual(getattr(CONF.ldap, option),
                             default_config['ldap'][option])

    def test_get_config_default_by_option(self):
        """Call ``GET /domains/config/{group}/{option}/default``."""
        # Create a config that overrides a few of the options so that we can
        # check that only the defaults are returned.
        self.domain_config_api.create_config(self.domain['id'], self.config)
        url = '/domains/config/ldap/url/default'
        r = self.get(url)
        default_config = r.result['config']
        self.assertEqual(CONF.ldap.url, default_config['url'])

    def test_get_config_default_by_invalid_group(self):
        """Call ``GET for /domains/config/{bad-group}/default``."""
        # First try a valid group, but one we don't support for domain config
        self.get('/domains/config/resouce/default',
                 expected_status=http_client.FORBIDDEN)

        # Now try a totally invalid group
        url = '/domains/config/%s/default' % uuid.uuid4().hex
        self.get(url, expected_status=http_client.FORBIDDEN)

    def test_get_config_default_by_invalid_option(self):
        """Call ``GET for /domains/config/{group}/{bad-option}/default``."""
        # First try a valid option, but one we don't support for domain config,
        # i.e. one that is in the sensitive options list
        self.get('/domains/config/ldap/password/default',
                 expected_status=http_client.FORBIDDEN)

        # Now try a totally invalid option
        url = '/domains/config/ldap/%s/default' % uuid.uuid4().hex
        self.get(url, expected_status=http_client.FORBIDDEN)
