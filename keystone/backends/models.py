# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
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

#Current Models
UserRoleAssociation = None
Endpoints = None
Role = None
Tenant = None
User = None
Credentials = None
Token = None
EndpointTemplates = None
Service = None


# Function to dynamically set model references.
def set_value(variable_name, value):
    if variable_name == 'UserRoleAssociation':
        global UserRoleAssociation
        UserRoleAssociation = value
    elif variable_name == 'Endpoints':
        global Endpoints
        Endpoints = value
    elif variable_name == 'Role':
        global Role
        Role = value
    elif variable_name == 'Tenant':
        global Tenant
        Tenant = value
    elif variable_name == 'User':
        global User
        User = value
    elif variable_name == 'Credentials':
        global Credentials
        Credentials = value
    elif variable_name == 'Token':
        global Token
        Token = value
    elif variable_name == 'EndpointTemplates':
        global EndpointTemplates
        EndpointTemplates = value
    elif variable_name == 'Service':
        global Service
        Service = value
