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

from keystone.api.validation import response_types

# Individual properties of the `Credential`
_credential_properties = {
    "blob": {
        "type": "string",
        "description": "The credential itself, as a serialized blob.",
    },
    "project_id": {
        "type": ["string", "null"],
        "description": "The ID for the project. Mandatory for `EC2` type.",
    },
    "type": {
        "type": "string",
        "description": (
            "The credential type, such as ec2 or cert. The implementation"
            " determines the list of supported types."
        ),
    },
    "user_id": {
        "type": "string",
        "format": "uuid",
        "description": "The ID of the user who owns the credential.",
    },
}

# Common schema of the `Credential` resource
credential_schema: dict[str, Any] = {
    "type": "object",
    "description": "A credential object.",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The UUID for the credential.",
        },
        "links": response_types.resource_links,
        **_credential_properties,
    },
    "additionalProperties": True,
}

# Query parameters of the `/credentials` API
index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "user_id": {
            "type": "string",
            "format": "uuid",
            "description": "Filters the response by a user ID.",
        },
        "type": {
            "type": "string",
            "description": (
                "The credential type, such as ec2 or cert. The implementation"
                " determines the list of supported types."
            ),
        },
    },
}

# Response of the `/credentials` API
index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "credentials": {
            "type": "array",
            "items": credential_schema,
            "description": "A list of credential objects.",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

# Response of the diverse `/credentials` APIs returning single
# credential
credential_response_body: dict[str, Any] = {
    "type": "object",
    "description": "A credential object.",
    "properties": {"credential": credential_schema},
    "additionalProperties": False,
}

# Request body of the `POST /credentials` operation
create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "A credential object.",
    "properties": {
        "credential": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "The UUID for the credential.",
                },
                **_credential_properties,
            },
            "additionalProperties": True,
            "required": ["blob", "type", "user_id"],
            # Generating client code for conditionally optional parameters is
            # hard. Use if-then-else for validation keeping the schema itself
            # static.
            "if": {"properties": {"type": {"const": "ec2"}}},
            "then": {
                "title": "ec2 credential requires project_id",
                "required": ["blob", "type", "user_id", "project_id"],
            },
        }
    },
    "required": ["credential"],
}

# Request body of the `PATCH /credentials/{credential_id}` operation
update_request_body: dict[str, Any] = {
    "type": "object",
    "description": "A credential object.",
    "properties": {
        "credential": {
            "type": "object",
            "properties": _credential_properties,
            "additionalProperties": True,
            "minProperties": 1,
        }
    },
    "required": ["credential"],
}
