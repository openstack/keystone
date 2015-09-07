# Copyright 2014 IBM Corp.
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

from testtools import matchers

from keystone.common import json_home
from keystone.tests import unit


class JsonHomeTest(unit.BaseTestCase):
    def test_build_v3_resource_relation(self):
        resource_name = self.getUniqueString()
        relation = json_home.build_v3_resource_relation(resource_name)
        exp_relation = (
            'http://docs.openstack.org/api/openstack-identity/3/rel/%s' %
            resource_name)
        self.assertThat(relation, matchers.Equals(exp_relation))

    def test_build_v3_extension_resource_relation(self):
        extension_name = self.getUniqueString()
        extension_version = self.getUniqueString()
        resource_name = self.getUniqueString()
        relation = json_home.build_v3_extension_resource_relation(
            extension_name, extension_version, resource_name)
        exp_relation = (
            'http://docs.openstack.org/api/openstack-identity/3/ext/%s/%s/rel/'
            '%s' % (extension_name, extension_version, resource_name))
        self.assertThat(relation, matchers.Equals(exp_relation))

    def test_build_v3_parameter_relation(self):
        parameter_name = self.getUniqueString()
        relation = json_home.build_v3_parameter_relation(parameter_name)
        exp_relation = (
            'http://docs.openstack.org/api/openstack-identity/3/param/%s' %
            parameter_name)
        self.assertThat(relation, matchers.Equals(exp_relation))

    def test_build_v3_extension_parameter_relation(self):
        extension_name = self.getUniqueString()
        extension_version = self.getUniqueString()
        parameter_name = self.getUniqueString()
        relation = json_home.build_v3_extension_parameter_relation(
            extension_name, extension_version, parameter_name)
        exp_relation = (
            'http://docs.openstack.org/api/openstack-identity/3/ext/%s/%s/'
            'param/%s' % (extension_name, extension_version, parameter_name))
        self.assertThat(relation, matchers.Equals(exp_relation))

    def test_translate_urls(self):
        href_rel = self.getUniqueString()
        href = self.getUniqueString()
        href_template_rel = self.getUniqueString()
        href_template = self.getUniqueString()
        href_vars = {self.getUniqueString(): self.getUniqueString()}
        original_json_home = {
            'resources': {
                href_rel: {'href': href},
                href_template_rel: {
                    'href-template': href_template,
                    'href-vars': href_vars}
            }
        }

        new_json_home = copy.deepcopy(original_json_home)
        new_prefix = self.getUniqueString()
        json_home.translate_urls(new_json_home, new_prefix)

        exp_json_home = {
            'resources': {
                href_rel: {'href': new_prefix + href},
                href_template_rel: {
                    'href-template': new_prefix + href_template,
                    'href-vars': href_vars}
            }
        }

        self.assertThat(new_json_home, matchers.Equals(exp_json_home))
