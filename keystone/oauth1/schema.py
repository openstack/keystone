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

_consumer_properties = {
    'description': validation.nullable(parameter_types.description)
}

consumer_create = {
    'type': 'object',
    'properties': _consumer_properties,
    'additionalProperties': True
}

consumer_update = {
    'type': 'object',
    'properties': _consumer_properties,
    'not': {
        'required': ['secret']
    },
    'minProperties': 1,
    'additionalProperties': True
}

request_token_authorize = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'id': parameter_types.id_string,
            'name': parameter_types.name,
        },
        'minProperties': 1,
        'maxProperties': 1,
        'additionalProperties': False
    }
}
