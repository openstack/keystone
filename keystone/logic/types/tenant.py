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


class Tenant(object):
    "Describes a tenant in the auth system"

    def __init__(self, tenant_id, description, enabled):
        self.__tenant_id = tenant_id
        self.__description = description
        self.__enabled = enabled

    @property
    def tenant_id(self):
        return self.__tenant_id

    @property
    def description(self):
        return self.__description

    @property
    def enabled(self):
        return self.__enabled


class Tenants(object):
    "A collection of tenants."

    def __init__(self, values, links):
        self.__values = values
        self.__links = links

    @property
    def values(self):
        return self.__values

    @property
    def links(self):
        return self.__links
