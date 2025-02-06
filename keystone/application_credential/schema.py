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

import copy
from typing import Any

from keystone.api.validation import parameter_types
from keystone.api.validation import response_types

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

# Query parameters of the `/users/{user_id}/access_rules` and
# `/application_credentials/{application_credential_id}` APIs
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

# Individual properties of 'Application Credential'
_application_credential_properties = {
    "name": {
        **parameter_types.name,
        "description": (
            "The name of the application credential. Must be unique to a user."
        ),
    },
    "description": {
        "type": ["string", "null"],
        "description": (
            "A description of the application credential's purpose."
        ),
    },
    "expires_at": {
        "type": ["string", "null"],
        "description": (
            "The expiration time of the application credential, if one "
            "was specified."
        ),
    },
    "project_id": {
        "type": "string",
        "description": (
            "The ID of the project the application credential was "
            "created for and that authentication requests using this "
            "application credential will be scoped to."
        ),
    },
    "access_rules": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "id": parameter_types.id_string,
                **_access_rules_properties,
            },
        },
        "description": "A list of access_rules objects.",
    },
    "unrestricted": {
        "type": ["boolean", "null"],
        "description": (
            "A flag indicating whether the application credential "
            "may be used for creation or destruction of other "
            "application credentials or trusts."
        ),
    },
    "system": {"type": ["string", "null"]},
}

# Common schema of `Application Credential` resource
application_credential_schema: dict[str, Any] = {
    "type": "object",
    "description": "An application credential object.",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The UUID of the application credential",
        },
        "roles": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": parameter_types.id_string,
                    "name": parameter_types.name,
                    "domain_id": {
                        "type": ["string", "null"],
                        "description": "The ID of the domain of the role.",
                    },
                    "description": {
                        "type": ["string", "null"],
                        "description": "A description about the role.",
                    },
                    "options": {
                        "type": ["object", "null"],
                        "description": (
                            "The resource options for the role. "
                            "Available resource options are immutable."
                        ),
                    },
                },
                "additionalProperties": False,
            },
            "description": (
                "A list of one or more roles that this application "
                "credential has associated with its project. A token "
                "using this application credential will have these "
                "same roles."
            ),
        },
        "user_id": {"type": "string", "description": "The ID of the user."},
        "links": response_types.resource_links,
        **_application_credential_properties,
    },
    "additionalProperties": False,
}

# Query parameters of `/application_credentials` API
application_credential_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": (
                "The name of the application credential. "
                "Must be unique to a user."
            ),
        }
    },
    "additionalProperties": False,
}

# Response of the `/application_credentials` API
application_credential_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "application_credentials": {
            "type": "array",
            "items": application_credential_schema,
            "description": "A list of application credentials",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

application_credential_request_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string",
            "description": "The UUID of the application credential",
        }
    },
    "additionalProperties": False,
}

# Response of `/application_credentials/{application_credential_id}`
# API returning single access rule
application_credential_response_body: dict[str, Any] = {
    "type": "object",
    "description": "An application credential object.",
    "properties": {"application_credential": application_credential_schema},
    "additionalProperties": False,
}

# Request body of the `POST /application_credentials` operation
application_credential_create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "An application credential object.",
    "properties": {
        "application_credential": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "The UUID for the credential.",
                },
                "secret": {
                    "type": ["string", "null"],
                    "description": (
                        "The secret that the application credential "
                        "will be created with. If not provided, one "
                        "will be generated."
                    ),
                },
                **_application_credential_properties,
                "roles": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": parameter_types.id_string,
                            "name": parameter_types.name,
                        },
                        "minProperties": 1,
                        "maxProperties": 1,
                        "additionalProperties": False,
                    },
                    "description": (
                        "A list of one or more roles that this application "
                        "credential has associated with its project. A token "
                        "using this application credential will have these "
                        "same roles."
                    ),
                },
            },
            "additionalProperties": False,
            "required": ["name"],
        }
    },
    "required": ["application_credential"],
    "additionalProperties": False,
}

application_credential_create_response_body = copy.deepcopy(
    application_credential_response_body
)
application_credential_create_response_body["properties"][
    "application_credential"
]["properties"]["secret"] = {
    "type": "string",
    "description": (
        "The secret that the application credential will be created with."
    ),
}
