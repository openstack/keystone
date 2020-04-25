# Copyright 2018 SUSE Linux GmbH
#
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

_role_properties = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'id': parameter_types.id_string,
            'name': parameter_types.name
        },
        'minProperties': 1,
        'maxProperties': 1,
        'additionalProperties': False
    }
}

_access_rules_properties = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'path': {
                'type': 'string',
                'minLength': 0,
                'maxLength': 225,
                'pattern': r'^\/.*'
            },
            'method': {
                'type': 'string',
                'pattern': r'^(POST|GET|HEAD|PATCH|PUT|DELETE)$'
            },
            'service': parameter_types.id_string,
            'id': parameter_types.id_string,
        },
        'additionalProperties': False
    }
}

_application_credential_properties = {
    'name': parameter_types.name,
    'description': validation.nullable(parameter_types.description),
    'secret': {
        'type': ['null', 'string']
    },
    'expires_at': {
        'type': ['null', 'string']
    },
    'roles': _role_properties,
    'unrestricted': parameter_types.boolean,
    'access_rules': _access_rules_properties
}

application_credential_create = {
    'type': 'object',
    'properties': _application_credential_properties,
    'required': ['name'],
    'additionalProperties': True
}
