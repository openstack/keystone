#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Not Yet PEP8 standardized
#API

endpoint_template = None
group = None
role = None
tenant_group = None
tenant = None
token = None
user = None

# Function to dynamically set module references.
def set_value(variable_name, value):
    if variable_name == 'endpoint_template':
        global endpoint_template
        endpoint_template = value
    elif variable_name == 'group':
        global group
        group = value
    elif variable_name == 'role':
        global role
        role = value
    elif variable_name == 'tenant_group':
        global tenant_group
        tenant_group = value
    elif variable_name == 'tenant':
        global tenant
        tenant = value
    elif variable_name == 'token':
        global token
        token = value
    elif variable_name == 'user':
        global user
        user = value
