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

from typing import Any

from keystone.api.validation import parameter_types
from keystone.api.validation import response_types
from keystone.common import validation
from keystone.common.validation import parameter_types as ks_parameter_types

_role_properties = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'id': parameter_types.id_string,
            'name': parameter_types.name,
        },
        'minProperties': 1,
        'maxProperties': 1,
        'additionalProperties': False,
    },
}

# Individual properties of 'Access Rule'
_access_rules_properties = {
    "path": {
        "type": "string",
        "minLength": 0,
        "maxLength": 225,
        "pattern": r'^/\.*',
        "description": (
            "The API path that the application credential is "
            "permitted to access."
        ),
    },
    "service": {
        **parameter_types.id_string,
        "description": (
            "The service type identifier for the service that the application"
            " credential is permitted to access. Must be a service type that"
            " is listed in the service catalog and not a code name for a"
            " service."
        ),
    },
    "method": {
        "type": "string",
        "enum": ["DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"],
        "description": (
            "The request method that the application credential is "
            "permitted to use for a given API endpoint."
        ),
    },
}

# Common schema of the `Access Rule` resource
access_rule_schema: dict[str, Any] = {
    "type": "object",
    "description": "An access rule object.",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The UUID of the access rule",
        },
        "links": response_types.resource_links,
        **_access_rules_properties,
    },
    "additionalProperties": False,
}

# Query parameters of the `/users/{user_d}/access_rules` API
index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

# Response of the `/access_rules` API
rule_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "access_rules": {
            "type": "array",
            "items": access_rule_schema,
            "description": "A list of access_rule objects.",
        },
        "links": response_types.links,
    },
    "additionalProperties": False,
}

# /access/rules/{access_rule_id}
# GET request query parameters
rule_show_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

# Response of `/access_rules/{access_rule_id}` API returning
# single access rule
rule_show_response_body: dict[str, Any] = {
    "type": "object",
    "description": "An access rule object.",
    "properties": {"access_rule": access_rule_schema},
    "additionalProperties": False,
}

_application_credential_properties = {
    'name': ks_parameter_types.name,
    'description': validation.nullable(ks_parameter_types.description),
    'secret': {'type': ['null', 'string']},
    'expires_at': {'type': ['null', 'string']},
    'roles': _role_properties,
    'unrestricted': ks_parameter_types.boolean,
    'access_rules': _access_rules_properties,
}

application_credential_create = {
    'type': 'object',
    'properties': _application_credential_properties,
    'required': ['name'],
    'additionalProperties': True,
}
