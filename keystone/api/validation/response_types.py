# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Common field types for validating API responses."""

from typing import Any

# Common schema for resource `link` attribute
links: dict[str, Any] = {
    "type": "object",
    "description": "Links for the collection of resources.",
    "properties": {
        "next": {"type": ["string", "null"], "format": "uri"},
        "previous": {"type": ["string", "null"], "format": "uri"},
        "self": {"type": "string", "format": "uri"},
    },
    "required": ["self"],
    "additionalProperties": False,
    "readOnly": True,
}

# Resource `links` attribute schema
resource_links: dict[str, Any] = {
    "type": "object",
    "description": "The link to the resource in question.",
    "properties": {"self": {"type": "string", "format": "uri"}},
    "additionalProperties": False,
    "readOnly": True,
}

truncated: dict[str, Any] = {
    "type": "boolean",
    "description": (
        "Flag indicating that the amount of entities exceeds global "
        "response limit"
    ),
}

tags: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tags": {"type": "array", "items": {"type": "string"}},
        "links": links,
    },
    "additionalProperties": False,
}
