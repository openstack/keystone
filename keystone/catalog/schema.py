# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import validation
from keystone.common.validation import parameter_types

_service_properties_type = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 255
}

_region_properties = {
    'description': validation.nullable(parameter_types.description),
    # NOTE(lbragstad): Regions use ID differently. The user can specify the ID
    # or it will be generated automatically.
    'id': {
        'type': 'string'
    },
    'parent_region_id': {
        'type': ['string', 'null']
    }
}

region_create = {
    'type': 'object',
    'properties': _region_properties,
    'additionalProperties': True
    # NOTE(lbragstad): No parameters are required for creating regions.
}

region_update = {
    'type': 'object',
    'properties': _region_properties,
    'minProperties': 1,
    'additionalProperties': True
}

# Schema for Service v3

_service_properties = {
    'enabled': parameter_types.boolean,
    'name': parameter_types.name,
    'type': _service_properties_type
}

service_create = {
    'type': 'object',
    'properties': _service_properties,
    'required': ['type'],
    'additionalProperties': True
}

service_update = {
    'type': 'object',
    'properties': _service_properties,
    'minProperties': 1,
    'additionalProperties': True
}

_endpoint_properties = {
    'enabled': parameter_types.boolean,
    'interface': {
        'type': 'string',
        'enum': ['admin', 'internal', 'public']
    },
    'region_id': {
        'type': 'string'
    },
    'region': {
        'type': 'string'
    },
    'service_id': {
        'type': 'string'
    },
    'url': parameter_types.url
}

endpoint_create = {
    'type': 'object',
    'properties': _endpoint_properties,
    'required': ['interface', 'service_id', 'url'],
    'additionalProperties': True
}

endpoint_update = {
    'type': 'object',
    'properties': _endpoint_properties,
    'minProperties': 1,
    'additionalProperties': True
}

_endpoint_group_properties = {
    'description': validation.nullable(parameter_types.description),
    'filters': {
        'type': 'object'
    },
    'name': parameter_types.name
}

endpoint_group_create = {
    'type': 'object',
    'properties': _endpoint_group_properties,
    'required': ['name', 'filters']
}

endpoint_group_update = {
    'type': 'object',
    'properties': _endpoint_group_properties,
    'minProperties': 1
}
