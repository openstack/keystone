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

import copy
from typing import Any

from keystone.api.validation import parameter_types
from keystone.api.validation import response_types
from keystone.common import validation
import keystone.conf
from keystone.identity.backends import resource_options as ro

CONF = keystone.conf.CONF


_identity_name: dict[str, Any] = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 255,
    'pattern': r'[\S]+',
}

# Schema for Identity v3 API

user_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "domain_id": parameter_types.domain_id,
        "enabled": {
            "description": "Whether the identity provider is enabled or not",
            **parameter_types.boolean,
        },
        "idp_id": {
            "type": "string",
            "description": "Filters the response by an identity provider ID.",
        },
        "name": parameter_types.name,
        "password_expires_at": {
            "type": "string",
            "description": (
                "Filter results based on which user passwords have "
                "expired. The query should include an operator and "
                "a timestamp with a colon (:) separating the two, for "
                "example: `password_expires_at={operator}:{timestamp}`\n"
                "Valid operators are: lt, lte, gt, gte, eq, and neq\n"
                "  - lt: expiration time lower than the timestamp\n"
                "  - lte: expiration time lower than or equal to the timestamp\n"
                "  - gt: expiration time higher than the timestamp\n"
                "  - gte: expiration time higher than or equal to the timestamp\n"
                "  - eq: expiration time equal to the timestamp\n"
                "  - neq: expiration time not equal to the timestamp\n\n"
                "Valid timestamps are of the form: `YYYY-MM-DDTHH:mm:ssZ`."
                "For example:"
                "`/v3/users?password_expires_at=lt:2016-12-08T22:02:00Z`\n"
                "The example would return a list of users whose password "
                "expired before the timestamp `(2016-12-08T22:02:00Z).`"
            ),
        },
        "protocol_id": {
            "type": "string",
            "description": "Filters the response by a protocol ID.",
        },
        "unique_id": {
            "type": "string",
            "description": "Filters the response by a unique ID.",
        },
        "marker": {
            "type": "string",
            "description": "ID of the last fetched entry",
        },
        "limit": {"type": ["integer", "string"]},
        "sort_key": parameter_types.sort_key,
        "sort_dir": parameter_types.sort_dir,
    },
    "additionalProperties": True,
}

_user_properties: dict[str, Any] = {
    'id': {"type": "string", "description": "The user ID.", "readOnly": True},
    'default_project_id': validation.nullable(parameter_types.id_string),
    'description': validation.nullable(parameter_types.description),
    'domain_id': parameter_types.id_string,
    'enabled': parameter_types.boolean,
    'federated': {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': {
                'idp_id': {'type': 'string'},
                'protocols': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'properties': {
                            'protocol_id': {'type': 'string'},
                            'unique_id': {'type': 'string'},
                        },
                        'required': ['protocol_id', 'unique_id'],
                    },
                    'minItems': 1,
                },
            },
            'required': ['idp_id', 'protocols'],
        },
    },
    'links': response_types.links,
    'name': _identity_name,
    'password_expires_at': {
        "type": ["string", "null"],
        "format": "date-time",
        "description": (
            "The date and time when the password expires. The time zone is UTC. "
            "This is a response object attribute; not valid for requests. A "
            "null value indicates that the password never expires."
        ),
        "readOnly": True,
    },
    'options': ro.USER_OPTIONS_REGISTRY.json_schema,
}

user_schema: dict[str, Any] = {
    "type": "object",
    "properties": _user_properties,
    # NOTE(gtema) User resource supports additional attributes which are stored
    # in the `extra` DB field
    "additionalProperties": True,
}

user_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "users": {"type": "array", "items": user_schema},
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

user_get_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"user": user_schema},
    "required": ["user"],
    "additionalProperties": False,
}

user_create_request: dict[str, Any] = {
    "type": "object",
    "properties": {
        "user": {
            "type": "object",
            "properties": {
                "password": {"type": ["string", "null"]},
                **_user_properties,
            },
            "required": ["name"],
            "additionalProperties": True,
        }
    },
    "required": ["user"],
    "additionalProperties": False,
}

user_create_response_body: dict[str, Any] = user_get_response_body

user_update_properties = copy.deepcopy(_user_properties)
# It is not allowed anymore to update domain of the existing user
user_update_properties.pop("domain_id", None)
user_update_request: dict[str, Any] = {
    'type': 'object',
    'properties': {
        'user': {
            'type': 'object',
            'properties': {
                'password': {'type': ['string', 'null']},
                **user_update_properties,
            },
            'minProperties': 1,
            'additionalProperties': True,
        }
    },
    'required': ['user'],
    'additionalProperties': False,
}

user_update_response_body: dict[str, Any] = user_get_response_body

group_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "domain_id": parameter_types.domain_id,
        "name": parameter_types.name,
        "marker": {
            "type": "string",
            "description": "ID of the last fetched entry",
        },
        "limit": {"type": ["integer", "string"]},
        "sort_key": parameter_types.sort_key,
        "sort_dir": parameter_types.sort_dir,
    },
    "additionalProperties": False,
}

_group_properties: dict[str, Any] = {
    'description': validation.nullable(parameter_types.description),
    'domain_id': parameter_types.id_string,
    'id': {"type": "string", "description": "The user ID.", "readOnly": True},
    'name': _identity_name,
}

group_schema: dict[str, Any] = {
    "type": "object",
    "properties": _group_properties,
    # NOTE(gtema) Group resource supports additional attributes which are stored
    # in the `extra` DB field
    "additionalProperties": True,
}

group_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "groups": {
            "type": "array",
            "items": group_schema,
            "description": "A list of group objects",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "required": ["groups"],
    "additionalProperties": False,
}

group_get_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"group": group_schema},
    "required": ["group"],
    "additionalProperties": False,
}

group_create_request_body: dict[str, Any] = {
    'type': 'object',
    'properties': {
        'group': {
            'type': 'object',
            'properties': _group_properties,
            'required': ['name'],
            'additionalProperties': True,
        }
    },
    "required": ["group"],
    "additionalProperties": False,
}

group_create_response_body = group_get_response_body

group_update_properties = copy.deepcopy(_group_properties)
# It is not allowed anymore to update domain of the existing group
group_update_properties.pop("domain_id", None)
group_update_request_body: dict[str, Any] = {
    'type': 'object',
    'properties': {
        'group': {
            'type': 'object',
            'properties': group_update_properties,
            'minProperties': 1,
            'additionalProperties': True,
        }
    },
    "required": ["group"],
    'additionalProperties': False,
}

group_update_response_body = group_get_response_body

_password_change_properties = {
    'original_password': {'type': 'string'},
    'password': {'type': 'string'},
}
if getattr(CONF, 'strict_password_check', None):
    _password_change_properties['password']['maxLength'] = (
        CONF.identity.max_password_length
    )

if getattr(CONF, 'security_compliance', None):
    if getattr(CONF.security_compliance, 'password_regex', None):
        _password_change_properties['password']['pattern'] = (
            CONF.security_compliance.password_regex
        )

password_change = {
    'type': 'object',
    'properties': _password_change_properties,
    'required': ['original_password', 'password'],
    'additionalProperties': False,
}
