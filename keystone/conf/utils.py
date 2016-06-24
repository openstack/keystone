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


def fmt(docstr):
    """Format a docstring for use as documentation in sample config."""
    # Replace newlines with spaces, as docstrings contain literal newlines that
    # should not be rendered into the sample configuration file (instead, line
    # wrappings should be applied automatically).
    docstr = docstr.replace('\n', ' ')

    # Because it's common for docstrings to begin and end with a newline, there
    # is now whitespace at the beginning and end of the documentation as a side
    # effect of replacing newlines with spaces.
    docstr = docstr.strip()

    return docstr
