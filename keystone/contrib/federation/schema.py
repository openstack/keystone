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
                'region': basic_property_id
            },
            'required': ['region'],
            'additionalProperties': False
        },
    },
    'required': ['identity', 'scope'],
    'additionalProperties': False
}
