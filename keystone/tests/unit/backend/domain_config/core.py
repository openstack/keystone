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

from keystone import exception


class DomainConfigTests(object):

    def setUp(self):
        self.domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(self.domain['id'], self.domain)
        self.addCleanup(self.clean_up_domain)

    def clean_up_domain(self):
        # NOTE(henry-nash): Deleting the domain will also delete any domain
        # configs for this domain.
        self.domain['enabled'] = False
        self.resource_api.update_domain(self.domain['id'], self.domain)
        self.resource_api.delete_domain(self.domain['id'])
        del self.domain

    def _domain_config_crud(self, sensitive):
        group = uuid.uuid4().hex
        option = uuid.uuid4().hex
        value = uuid.uuid4().hex
        self.domain_config_api.create_config_option(
            self.domain['id'], group, option, value, sensitive)
        res = self.domain_config_api.get_config_option(
            self.domain['id'], group, option, sensitive)
        config = {'group': group, 'option': option, 'value': value}
        self.assertEqual(config, res)

        value = uuid.uuid4().hex
        self.domain_config_api.update_config_option(
            self.domain['id'], group, option, value, sensitive)
        res = self.domain_config_api.get_config_option(
            self.domain['id'], group, option, sensitive)
        config = {'group': group, 'option': option, 'value': value}
        self.assertEqual(config, res)

        self.domain_config_api.delete_config_options(
            self.domain['id'], group, option, sensitive)
        self.assertRaises(exception.DomainConfigNotFound,
                          self.domain_config_api.get_config_option,
                          self.domain['id'], group, option, sensitive)
        # ...and silent if we try to delete it again
        self.domain_config_api.delete_config_options(
            self.domain['id'], group, option, sensitive)

    def test_whitelisted_domain_config_crud(self):
        self._domain_config_crud(sensitive=False)

    def test_sensitive_domain_config_crud(self):
        self._domain_config_crud(sensitive=True)

    def _list_domain_config(self, sensitive):
        """Test listing by combination of domain, group & option."""

        config1 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        # Put config2 in the same group as config1
        config2 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        config3 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': 100}
        for config in [config1, config2, config3]:
            self.domain_config_api.create_config_option(
                self.domain['id'], config['group'], config['option'],
                config['value'], sensitive)

        # Try listing all items from a domain
        res = self.domain_config_api.list_config_options(
            self.domain['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(3))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config2, config3])

        # Try listing by domain and group
        res = self.domain_config_api.list_config_options(
            self.domain['id'], group=config1['group'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(2))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config2])

        # Try listing by domain, group and option
        res = self.domain_config_api.list_config_options(
            self.domain['id'], group=config2['group'],
            option=config2['option'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(1))
        self.assertEqual(config2, res[0])

    def test_list_whitelisted_domain_config_crud(self):
        self._list_domain_config(False)

    def test_list_sensitive_domain_config_crud(self):
        self._list_domain_config(True)

    def _delete_domain_configs(self, sensitive):
        """Test deleting by combination of domain, group & option."""

        config1 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        # Put config2 and config3 in the same group as config1
        config2 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        config3 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        config4 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        for config in [config1, config2, config3, config4]:
            self.domain_config_api.create_config_option(
                self.domain['id'], config['group'], config['option'],
                config['value'], sensitive)

        # Try deleting by domain, group and option
        res = self.domain_config_api.delete_config_options(
            self.domain['id'], group=config2['group'],
            option=config2['option'], sensitive=sensitive)
        res = self.domain_config_api.list_config_options(
            self.domain['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(3))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config3, config4])

        # Try deleting by domain and group
        res = self.domain_config_api.delete_config_options(
            self.domain['id'], group=config4['group'], sensitive=sensitive)
        res = self.domain_config_api.list_config_options(
            self.domain['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(2))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config3])

        # Try deleting all items from a domain
        res = self.domain_config_api.delete_config_options(
            self.domain['id'], sensitive=sensitive)
        res = self.domain_config_api.list_config_options(
            self.domain['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(0))

    def test_delete_whitelisted_domain_configs(self):
        self._delete_domain_configs(False)

    def test_delete_sensitive_domain_configs(self):
        self._delete_domain_configs(True)

    def _create_domain_config_twice(self, sensitive):
        """Test conflict error thrown if create the same option twice."""

        config = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                  'value': uuid.uuid4().hex}

        self.domain_config_api.create_config_option(
            self.domain['id'], config['group'], config['option'],
            config['value'], sensitive=sensitive)
        self.assertRaises(exception.Conflict,
                          self.domain_config_api.create_config_option,
                          self.domain['id'], config['group'], config['option'],
                          config['value'], sensitive=sensitive)

    def test_create_whitelisted_domain_config_twice(self):
        self._create_domain_config_twice(False)

    def test_create_sensitive_domain_config_twice(self):
        self._create_domain_config_twice(True)

    def test_delete_domain_deletes_configs(self):
        """Test domain deletion clears the domain configs."""

        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        config1 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        # Put config2 in the same group as config1
        config2 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        self.domain_config_api.create_config_option(
            domain['id'], config1['group'], config1['option'],
            config1['value'])
        self.domain_config_api.create_config_option(
            domain['id'], config2['group'], config2['option'],
            config2['value'], sensitive=True)
        res = self.domain_config_api.list_config_options(
            domain['id'])
        self.assertThat(res, matchers.HasLength(1))
        res = self.domain_config_api.list_config_options(
            domain['id'], sensitive=True)
        self.assertThat(res, matchers.HasLength(1))

        # Now delete the domain
        domain['enabled'] = False
        self.resource_api.update_domain(domain['id'], domain)
        self.resource_api.delete_domain(domain['id'])

        # Check domain configs have also been deleted
        res = self.domain_config_api.list_config_options(
            domain['id'])
        self.assertThat(res, matchers.HasLength(0))
        res = self.domain_config_api.list_config_options(
            domain['id'], sensitive=True)
        self.assertThat(res, matchers.HasLength(0))
