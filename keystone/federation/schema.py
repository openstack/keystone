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


basic_property_id = {
    'type': 'object',
    'properties': {
        'id': {
            'type': 'string'
        }
    },
    'required': ['id'],
    'additionalProperties': False
}

saml_create = {
    'type': 'object',
    'properties': {
        'identity': {
            'type': 'object',
            'properties': {
                'token': basic_property_id,
                'methods': {
                    'type': 'array'
                }
            },
            'required': ['token'],
            'additionalProperties': False
        },
        'scope': {
            'type': 'object',
            'properties': {
                'service_provider': basic_property_id
            },
            'required': ['service_provider'],
            'additionalProperties': False
        },
    },
    'required': ['identity', 'scope'],
    'additionalProperties': False
}

_service_provider_properties = {
    # NOTE(rodrigods): The database accepts URLs with 256 as max length,
    # but parameter_types.url uses 225 as max length.
    'auth_url': parameter_types.url,
    'sp_url': parameter_types.url,
    'description': validation.nullable(parameter_types.description),
    'enabled': parameter_types.boolean,
    'relay_state_prefix': validation.nullable(parameter_types.description)
}

service_provider_create = {
    'type': 'object',
    'properties': _service_provider_properties,
    # NOTE(rodrigods): 'id' is not required since it is passed in the URL
    'required': ['auth_url', 'sp_url'],
    'additionalProperties': False
}

service_provider_update = {
    'type': 'object',
    'properties': _service_provider_properties,
    # Make sure at least one property is being updated
    'minProperties': 1,
    'additionalProperties': False
}
