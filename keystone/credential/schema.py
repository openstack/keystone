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


_credential_properties = {
    'blob': {
        'type': 'string'
    },
    'project_id': {
        'type': 'string'
    },
    'type': {
        'type': 'string'
    },
    'user_id': {
        'type': 'string'
    }
}

credential_create = {
    'type': 'object',
    'properties': _credential_properties,
    'required': ['blob', 'type', 'user_id'],
    'additionalProperties': True
}

credential_update = {
    'type': 'object',
    'properties': _credential_properties,
    'minProperties': 1,
    'additionalProperties': True
}
