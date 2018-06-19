# Copyright 2018 Huawei
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

from keystone.common import validation
from keystone.common.validation import parameter_types

_registered_limit_properties = {
    'service_id': parameter_types.id_string,
    'region_id': {
        'type': 'string'
    },
    'resource_name': {
        'type': 'string'
    },
    'default_limit': {
        'type': 'integer'
    },
    'description': validation.nullable(parameter_types.description)
}

_registered_limit_create = {
    'type': 'object',
    'properties': _registered_limit_properties,
    'additionalProperties': False,
    'required': ['service_id', 'resource_name', 'default_limit']
}

registered_limit_create = {
    'type': 'array',
    'items': _registered_limit_create,
    'minItems': 1
}
registered_limit_update = {
    'type': 'object',
    'properties': _registered_limit_properties,
    'additionalProperties': False,
}

_limit_create_properties = {
    'project_id': parameter_types.id_string,
    'service_id': parameter_types.id_string,
    'region_id': {
        'type': 'string'
    },
    'resource_name': {
        'type': 'string'
    },
    'resource_limit': {
        'type': 'integer'
    },
    'description': validation.nullable(parameter_types.description)
}

_limit_create = {
    'type': 'object',
    'properties': _limit_create_properties,
    'additionalProperties': False,
    'required': ['project_id', 'service_id', 'resource_name', 'resource_limit']
}

limit_create = {
    'type': 'array',
    'items': _limit_create,
    'minItems': 1
}

_limit_update_properties = {
    'resource_limit': {
        'type': 'integer'
    },
    'description': validation.nullable(parameter_types.description)
}

limit_update = {
    'type': 'object',
    'properties': _limit_update_properties,
    'additionalProperties': False
}
