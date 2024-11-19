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

from typing import Any

from keystone.api.validation import parameter_types
from keystone.api.validation import response_types
from keystone.common import validation
from keystone.common.validation import parameter_types as old_parameter_types

_registered_limit_properties = {
    'service_id': old_parameter_types.id_string,
    'region_id': {'type': ['null', 'string']},
    'resource_name': {'type': 'string', 'minLength': 1, 'maxLength': 255},
    'default_limit': {
        'type': 'integer',
        'minimum': -1,
        'maximum': 0x7FFFFFFF,  # The maximum value a signed INT may have
    },
    'description': validation.nullable(old_parameter_types.description),
}

_registered_limit_create = {
    'type': 'object',
    'properties': _registered_limit_properties,
    'additionalProperties': False,
    'required': ['service_id', 'resource_name', 'default_limit'],
}

registered_limit_create = {
    'type': 'array',
    'items': _registered_limit_create,
    'minItems': 1,
}
registered_limit_update = {
    'type': 'object',
    'properties': _registered_limit_properties,
    'additionalProperties': False,
}

_limit_integer_type = {
    "type": "integer",
    "minimum": -1,
    "maximum": 0x7FFFFFFF,  # The maximum value a signed INT may have
}

# Individual properties of the `Limit`
_limit_properties = {
    "resource_name": parameter_types.name,
    "region_id": {
        "description": (
            "The ID of the region that contains the service endpoint."
        ),
        **parameter_types.region_id,
    },
    "service_id": {
        "type": "string",
        "format": "uuid",
        "description": "The UUID of the service to which the limit belongs.",
    },
    "resource_limit": {
        "description": "The override limit.",
        **_limit_integer_type,
    },
    "description": validation.nullable(parameter_types.description),
}

# Common schema of `Limit` resource
limit_schema: dict[str, Any] = {
    "type": "object",
    "description": "A limit object.",
    "properties": {
        "id": {
            "type": "string",
            "format": "uuid",
            "description": "The limit ID.",
            "readOnly": True,
        },
        "project_id": validation.nullable(parameter_types.project_id),
        "domain_id": validation.nullable(parameter_types.domain_id),
        "links": response_types.resource_links,
        **_limit_properties,
    },
    "additionalProperties": False,
}

# Response body of API operations returning a single limit
# `GET /limits/{limit_id}` and `PATCH /limits/{limit_id}`
limit_show_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"limit": limit_schema},
    "additionalProperties": False,
}

# Query parameters of the `GET /limits` API operation
# returning a list of limits
limits_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "service_id": {
            "type": "string",
            "format": "uuid",
            "description": "Filters the response by a service ID.",
        },
        "region_id": {
            "description": "Filters the response by a region ID.",
            **parameter_types.region_id,
        },
        "resource_name": {
            "description": (
                "Filters the response by a specified resource name."
            ),
            **parameter_types.name,
        },
        "project_id": {
            "description": "Filters the response by a project ID.",
            **parameter_types.project_id,
        },
        "domain_id": {
            "description": "Filters the response by a domain ID.",
            **parameter_types.domain_id,
        },
    },
    "additionalProperties": False,
}

# Response body of the `GET /limits` API operation
# returning a list of limits
limits_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "links": response_types.links,
        "limits": {
            "type": "array",
            "items": limit_schema,
            "description": "A list of limit objects.",
        },
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

# Response body of the `GET /limits/model` API operation
# returning an enforcement model
limit_model_show_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "model": {
            "type": "object",
            "description": (
                "A model object describing the configured enforcement model "
                "used by the deployment."
            ),
            "properties": {
                "description": {
                    "type": "string",
                    "description": (
                        "A short description of the enforcement model used."
                    ),
                },
                "name": {
                    **parameter_types.name,
                    "description": "The name of the enforcement model.",
                },
            },
        },
        "additionalProperties": False,
    },
    "additionalProperties": False,
}

# Individual properties for creating a new limit
_limit_create = {
    "type": "object",
    "properties": {
        "project_id": validation.nullable(parameter_types.project_id),
        "domain_id": validation.nullable(parameter_types.domain_id),
        **_limit_properties,
    },
    "required": ["service_id", "resource_name", "resource_limit"],
    "oneOf": [
        {
            "required": [
                "service_id",
                "resource_name",
                "resource_limit",
                "domain_id",
            ]
        },
        {
            "required": [
                "service_id",
                "resource_name",
                "resource_limit",
                "project_id",
            ]
        },
    ],
    "additionalProperties": False,
}

# Request body of the `POST /limits` API operation
limits_create_request_body = {
    "type": "object",
    "properties": {
        "limits": {
            "type": "array",
            "items": _limit_create,
            "minItems": 1,
            "description": "A list of limit objects.",
        }
    },
    "required": ["limits"],
    "additionalProperties": False,
}

# Response body of the `POST /limits` API operation
limits_create_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "limits": {
            "type": "array",
            "items": limit_schema,
            "description": "A list of limit objects.",
        }
    },
    "additionalProperties": False,
}

# Request body of the `PATCH /limits/{limit_id}` operation
limit_update_request_body = {
    "type": "object",
    "properties": {
        "limit": {
            "type": "object",
            "description": "Updates to make to a limit.",
            "properties": {
                "resource_limit": {
                    "description": "The override limit.",
                    **_limit_integer_type,
                },
                "description": validation.nullable(
                    parameter_types.description
                ),
            },
            "additionalProperties": False,
        }
    },
    "additionalProperties": False,
    "required": ["limit"],
}
