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

import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.endpoint_policy import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-ENDPOINT-POLICY', extension_version='1.0')


class Routers(wsgi.RoutersBase):

    PATH_PREFIX = '/OS-ENDPOINT-POLICY'

    def append_v3_routers(self, mapper, routers):
        endpoint_policy_controller = controllers.EndpointPolicyV3Controller()

        self._add_resource(
            mapper, endpoint_policy_controller,
            path='/endpoints/{endpoint_id}' + self.PATH_PREFIX + '/policy',
            get_head_action='get_policy_for_endpoint',
            rel=build_resource_relation(resource_name='endpoint_policy'),
            path_vars={'endpoint_id': json_home.Parameters.ENDPOINT_ID})
        self._add_resource(
            mapper, endpoint_policy_controller,
            path='/policies/{policy_id}' + self.PATH_PREFIX + '/endpoints',
            get_action='list_endpoints_for_policy',
            rel=build_resource_relation(resource_name='policy_endpoints'),
            path_vars={'policy_id': json_home.Parameters.POLICY_ID})
        self._add_resource(
            mapper, endpoint_policy_controller,
            path=('/policies/{policy_id}' + self.PATH_PREFIX +
                  '/endpoints/{endpoint_id}'),
            get_head_action='check_policy_association_for_endpoint',
            put_action='create_policy_association_for_endpoint',
            delete_action='delete_policy_association_for_endpoint',
            rel=build_resource_relation(
                resource_name='endpoint_policy_association'),
            path_vars={
                'policy_id': json_home.Parameters.POLICY_ID,
                'endpoint_id': json_home.Parameters.ENDPOINT_ID,
            })
        self._add_resource(
            mapper, endpoint_policy_controller,
            path=('/policies/{policy_id}' + self.PATH_PREFIX +
                  '/services/{service_id}'),
            get_head_action='check_policy_association_for_service',
            put_action='create_policy_association_for_service',
            delete_action='delete_policy_association_for_service',
            rel=build_resource_relation(
                resource_name='service_policy_association'),
            path_vars={
                'policy_id': json_home.Parameters.POLICY_ID,
                'service_id': json_home.Parameters.SERVICE_ID,
            })
        self._add_resource(
            mapper, endpoint_policy_controller,
            path=('/policies/{policy_id}' + self.PATH_PREFIX +
                  '/services/{service_id}/regions/{region_id}'),
            get_head_action='check_policy_association_for_region_and_service',
            put_action='create_policy_association_for_region_and_service',
            delete_action='delete_policy_association_for_region_and_service',
            rel=build_resource_relation(
                resource_name='region_and_service_policy_association'),
            path_vars={
                'policy_id': json_home.Parameters.POLICY_ID,
                'service_id': json_home.Parameters.SERVICE_ID,
                'region_id': json_home.Parameters.REGION_ID,
            })
