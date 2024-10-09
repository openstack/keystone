# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Common parameter types for validating API requests."""

from typing import Any

empty: dict[str, Any] = {"type": "null"}

name: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "pattern": r"[\S]+",
}

boolean = {
    "type": ["boolean", "string"],
    "enum": [True, "True", "TRUE", "true", False, "False", "FALSE", "false"],
}


domain_id: dict[str, str] = {"type": "string"}

parent_id: dict[str, str] = {"type": "string", "format": "uuid"}

_tag_name_property = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    # NOTE(gagehugo) This pattern is for tags which follows the
    # guidelines as set by the API-WG, which matches anything that
    # does not contain a '/' or ','.
    # https://specs.openstack.org/openstack/api-wg/guidelines/tags.html
    "pattern": "^[^,/]*$",
}

tags: dict[str, Any] = {
    "type": "string",
    "x-openstack": {
        # As OpenAPI request parameters this is an array of string serialized
        # as csv
        "openapi": {
            "schema": {"type": "array", "items": _tag_name_property},
            "style": "form",
            "explode": False,
        }
    },
}
