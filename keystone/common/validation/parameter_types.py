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
"""Common parameter types for validating a request reference."""

boolean = {
    'type': 'boolean',
    'enum': [True, False]
}

# NOTE(lbragstad): Be mindful of this pattern as it might require changes
# once this is used on user names, LDAP-based user names specifically since
# commas aren't allowed in the following pattern. Here we are only going to
# check the length of the name and ensure that it's a string. Right now we are
# not going to validate on a naming pattern for issues with
# internationalization.
name = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 255,
    'pattern': r'[\S]+'
}

external_id_string = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 64
}

id_string = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 64,
    # TODO(lbragstad): Find a way to make this configurable such that the end
    # user chooses how much control they want over id_strings with a regex
    'pattern': r'^[a-zA-Z0-9-]+$'
}

mapping_id_string = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 64,
    'pattern': '^[a-zA-Z0-9-_]+$'
}

description = {
    'type': 'string'
}

url = {
    'type': 'string',
    'minLength': 0,
    'maxLength': 225,
    # NOTE(edmondsw): we could do more to validate per various RFCs, but
    # decision was made to err on the side of leniency. The following is based
    # on rfc1738 section 2.1
    'pattern': '^[a-zA-Z0-9+.-]+:.+'
}

email = {
    'type': 'string',
    'format': 'email'
}

integer_min0 = {
    'type': 'integer',
    'minimum': 0
}
