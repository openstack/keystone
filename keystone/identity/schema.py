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
import keystone.conf
from keystone.identity.backends import resource_options as ro


CONF = keystone.conf.CONF


_identity_name = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 255,
    'pattern': r'[\S]+'
}

# Schema for Identity v3 API

_user_properties = {
    'default_project_id': validation.nullable(parameter_types.id_string),
    'description': validation.nullable(parameter_types.description),
    'domain_id': parameter_types.id_string,
    'enabled': parameter_types.boolean,
    'federated': {
        'type': 'array',
        'items':
            {
                'type': 'object',
                'properties': {
                    'idp_id': {'type': 'string'},
                    'protocols': {
                        'type': 'array',
                        'items':
                            {
                                'type': 'object',
                                'properties': {
                                    'protocol_id': {'type': 'string'},
                                    'unique_id': {'type': 'string'}
                                },
                                'required': ['protocol_id', 'unique_id']
                            },
                        'minItems': 1
                    }
                },
                'required': ['idp_id', 'protocols']
            },
    },
    'name': _identity_name,
    'password': {
        'type': ['string', 'null']
    },
    'options': ro.USER_OPTIONS_REGISTRY.json_schema
}

# TODO(notmorgan): Provide a mechanism for options to supply real jsonschema
# validation based upon the option object and the option validator(s)
user_create = {
    'type': 'object',
    'properties': _user_properties,
    'required': ['name'],
    'options': {
        'type': 'object'
    },
    'additionalProperties': True
}

user_update = {
    'type': 'object',
    'properties': _user_properties,
    'minProperties': 1,
    'options': {
        'type': 'object'
    },
    'additionalProperties': True
}

_group_properties = {
    'description': validation.nullable(parameter_types.description),
    'domain_id': parameter_types.id_string,
    'name': _identity_name
}

group_create = {
    'type': 'object',
    'properties': _group_properties,
    'required': ['name'],
    'additionalProperties': True
}

group_update = {
    'type': 'object',
    'properties': _group_properties,
    'minProperties': 1,
    'additionalProperties': True
}

_password_change_properties = {
    'original_password': {
        'type': 'string'
    },
    'password': {
        'type': 'string'
    }
}
if getattr(CONF, 'strict_password_check', None):
    _password_change_properties['password']['maxLength'] = \
        CONF.identity.max_password_length

if getattr(CONF, 'security_compliance', None):
    if getattr(CONF.security_compliance, 'password_regex', None):
        _password_change_properties['password']['pattern'] = \
            CONF.security_compliance.password_regex

password_change = {
    'type': 'object',
    'properties': _password_change_properties,
    'required': ['original_password', 'password'],
    'additionalProperties': False
}
