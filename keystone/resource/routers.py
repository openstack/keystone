# Copyright 2013 Metacloud, Inc.
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

"""WSGI Routers for the Resource service."""

from keystone.common import json_home
from keystone.common import router
from keystone.common import wsgi
from keystone.resource import controllers


class Routers(wsgi.RoutersBase):

    _path_prefixes = ('domains', 'projects')

    def append_v3_routers(self, mapper, routers):
        routers.append(
            router.Router(controllers.DomainV3(),
                          'domains', 'domain',
                          resource_descriptions=self.v3_resources))

        config_controller = controllers.DomainConfigV3()
        tag_controller = controllers.ProjectTagV3()

        self._add_resource(
            mapper, config_controller,
            path='/domains/{domain_id}/config',
            get_head_action='get_domain_config',
            put_action='create_domain_config',
            patch_action='update_domain_config_only',
            delete_action='delete_domain_config',
            rel=json_home.build_v3_resource_relation('domain_config'),
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID
            })

        config_group_param = (
            json_home.build_v3_parameter_relation('config_group'))
        self._add_resource(
            mapper, config_controller,
            path='/domains/{domain_id}/config/{group}',
            get_head_action='get_domain_config_wrapper',
            patch_action='update_domain_config_group',
            delete_action='delete_domain_config',
            rel=json_home.build_v3_resource_relation('domain_config_group'),
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group': config_group_param
            })

        self._add_resource(
            mapper, config_controller,
            path='/domains/{domain_id}/config/{group}/{option}',
            get_head_action='get_domain_config_wrapper',
            patch_action='update_domain_config',
            delete_action='delete_domain_config',
            rel=json_home.build_v3_resource_relation('domain_config_option'),
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group': config_group_param,
                'option': json_home.build_v3_parameter_relation(
                    'config_option')
            })

        self._add_resource(
            mapper, config_controller,
            path='/domains/config/default',
            get_head_action='get_domain_config_default',
            rel=json_home.build_v3_resource_relation('domain_config_default'))

        self._add_resource(
            mapper, config_controller,
            path='/domains/config/{group}/default',
            get_head_action='get_domain_config_default',
            rel=json_home.build_v3_resource_relation(
                'domain_config_default_group'),
            path_vars={
                'group': config_group_param
            })

        self._add_resource(
            mapper, config_controller,
            path='/domains/config/{group}/{option}/default',
            get_head_action='get_domain_config_default',
            rel=json_home.build_v3_resource_relation(
                'domain_config_default_option'),
            path_vars={
                'group': config_group_param,
                'option': json_home.build_v3_parameter_relation(
                    'config_option')
            })

        routers.append(
            router.Router(controllers.ProjectV3(),
                          'projects', 'project',
                          resource_descriptions=self.v3_resources))

        self._add_resource(
            mapper, tag_controller,
            path='/projects/{project_id}/tags',
            get_head_action='list_project_tags',
            put_action='update_project_tags',
            delete_action='delete_project_tags',
            rel=json_home.build_v3_resource_relation(
                'project_tags'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID
            })

        self._add_resource(
            mapper, tag_controller,
            path='/projects/{project_id}/tags/{value}',
            get_head_action='get_project_tag',
            put_action='create_project_tag',
            delete_action='delete_project_tag',
            rel=json_home.build_v3_resource_relation(
                'project_tags'),
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'value': json_home.Parameters.TAG_VALUE
            })
