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

import string as s
import simplejson as json
import keystone.logic.types.fault as fault
from lxml import etree


class Tenant(object):
    "Describes a tenant in the auth system"

    def __init__(self, tenant_id, description, enabled):
        self.__tenant_id = tenant_id
        self.__description = description
        self.__enabled = enabled

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append (etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/idm/api/v1.0}tenant")
            if root == None:
                raise fault.BadRequestFault("Expecting Tenant")
            tenant_id=root.get("id")
            if tenant_id == None:
                raise fault.BadRequestFault("Expecting a unique Tenant Id")
            enabled=root.get("enabled")
            if enabled == None or enabled == "true" or enabled == "yes":
                set_enabled=True
            elif enabled == "false" or enabled == "no":
                set_enabled=False
            else:
                raise fault.BadRequestFault("Bad enabled attribute!")
            desc = root.find("{http://docs.openstack.org/idm/api/v1.0}description")
            if desc == None:
                raise fault.BadRequestFault("Expecting Tenant Description")
            return Tenant(tenant_id, desc.text, set_enabled)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse Tenant", e.__str__())

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "tenant" in obj:
                raise fault.BadRequestFault("Expecting tenant")
            tenant = obj["tenant"]
            if not "id" in tenant:
                raise fault.BadRequestFault("Expecting a unique Tenant Id")
            tenant_id = tenant["id"]
            set_enabled=True
            if "enabled" in tenant:
                set_enabled = tenant["enabled"]
                if not isinstance(set_enabled, bool):
                    raise fault.BadRequestFault ("Bad enabled attribute!")
            if not "description" in tenant:
                raise fault.BadRequestFault("Expecting Tenant Description")
            description = tenant["description"]
            return Tenant(tenant_id, description, set_enabled)
        except (json.decoder.JSONDecodeError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse Tenant", e.__str__())

    @property
    def tenant_id(self):
        return self.__tenant_id

    @property
    def description(self):
        return self.__description

    @property
    def enabled(self):
        return self.__enabled

    def to_dom(self):
        dom = etree.Element("tenant",
                            xmlns="http://docs.openstack.org/idm/api/v1.0",
                            enabled=s.lower(self.__enabled.__str__()))
        dom.set("id", self.__tenant_id)
        desc = etree.Element("description")
        desc.text = self.__description
        dom.append(desc)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        tenant = {}
        tenant["id"] = self.__tenant_id
        tenant["description"] = self.__description
        tenant["enabled"] = s.lower(self.__enabled.__str__())
        ret = {}
        ret["tenant"] = tenant
        return ret

    def to_json(self):
        return json.dumps(self.to_dict())


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

    def to_xml(self):
        dom = etree.Element("tenants",
                            xmlns="http://docs.openstack.org/idm/api/v1.0")
        for t in self.__values:
            dom.append(t.to_dom())
        return etree.tostring(dom)

    def to_json(self):
        values=[]
        for t in self.__values:
            values.append(t.to_dict()["tenant"])
        v = {}
        v["values"] = values
        ret = {}
        ret["tenants"] = values
        return json.dumps(ret)
