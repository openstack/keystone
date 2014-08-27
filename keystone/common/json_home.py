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


def build_v3_resource_relation(resource_name):
    return ('http://docs.openstack.org/api/openstack-identity/3/rel/%s' %
            resource_name)


def build_v3_extension_resource_relation(extension_name, extension_version,
                                         resource_name):
    return (
        'http://docs.openstack.org/api/openstack-identity/3/ext/%s/%s/rel/%s' %
        (extension_name, extension_version, resource_name))


def build_v3_parameter_relation(parameter_name):
    return ('http://docs.openstack.org/api/openstack-identity/3/param/%s' %
            parameter_name)


def build_v3_extension_parameter_relation(extension_name, extension_version,
                                          parameter_name):
    return (
        'http://docs.openstack.org/api/openstack-identity/3/ext/%s/%s/param/'
        '%s' % (extension_name, extension_version, parameter_name))


class Parameters(object):
    """Relationships for Common parameters."""

    DOMAIN_ID = build_v3_parameter_relation('domain_id')
    ENDPOINT_ID = build_v3_parameter_relation('endpoint_id')
    GROUP_ID = build_v3_parameter_relation('group_id')
    PROJECT_ID = build_v3_parameter_relation('project_id')
    ROLE_ID = build_v3_parameter_relation('role_id')
    USER_ID = build_v3_parameter_relation('user_id')
