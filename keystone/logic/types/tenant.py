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

import json
from lxml import etree
import string

from keystone.logic.types import fault


class Tenant(object):
    """Describes a tenant in the auth system"""

    def __init__(self, tenant_id, description, enabled):
        self.tenant_id = tenant_id
        self.description = description
        self.enabled = enabled

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find(
                "{http://docs.openstack.org/identity/api/v2.0}tenant")
            if root == None:
                raise fault.BadRequestFault("Expecting Tenant")
            tenant_id = root.get("id")
            enabled = root.get("enabled")
            if enabled == None or enabled == "true" or enabled == "yes":
                set_enabled = True
            elif enabled == "false" or enabled == "no":
                set_enabled = False
            else:
                raise fault.BadRequestFault("Bad enabled attribute!")
            desc = root.find("{http://docs.openstack.org/identity/api/v2.0}"
                             "description")
            if desc == None:
                raise fault.BadRequestFault("Expecting Tenant Description")
            return Tenant(tenant_id, desc.text, set_enabled)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse Tenant", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "tenant" in obj:
                raise fault.BadRequestFault("Expecting tenant")
            tenant = obj["tenant"]
            if not "id" in tenant:
                tenant_id = None
            else:
                tenant_id = tenant["id"]
            set_enabled = True
            if "enabled" in tenant:
                set_enabled = tenant["enabled"]
                if not isinstance(set_enabled, bool):
                    raise fault.BadRequestFault("Bad enabled attribute!")
            if not "description" in tenant:
                raise fault.BadRequestFault("Expecting Tenant Description")
            description = tenant["description"]
            return Tenant(tenant_id, description, set_enabled)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse Tenant", str(e))

    def to_dom(self):
        dom = etree.Element("tenant",
                        xmlns="http://docs.openstack.org/identity/api/v2.0",
                        enabled=string.lower(str(self.enabled)))
        if self.tenant_id:
            dom.set("id", self.tenant_id)
        desc = etree.Element("description")
        desc.text = self.description
        dom.append(desc)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        tenant = {}
        if self.tenant_id:
            tenant["id"] = self.tenant_id
        tenant["description"] = self.description
        tenant["enabled"] = self.enabled
        return {'tenant': tenant}

    def to_json(self):
        return json.dumps(self.to_dict())


class Tenants(object):
    """A collection of tenants."""

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("tenants")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["tenant"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"tenants": {"values": values, "links": links}})


class User(object):
    """Describes a user in the auth system

    TODO: This is basically a duplicate of keystone.logic.types.user.User and
    should be considered deprecated.
    """

    def __init__(self, user_id, email, enabled, tenant_id=''):
        self.user_id = user_id
        if tenant_id:
            self.tenant_id = tenant_id
        else:
            self.tenant_id = None
        self.email = email
        self.enabled = enabled and True or False

    def to_dom(self):
        dom = etree.Element("user",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.user_id:
            dom.set("id", self.user_id)
        if self.tenant_id:
            dom.set("tenantId", self.tenant_id)
        if self.email:
            dom.set("email", self.email)
        if self.enabled:
            dom.set("enabled", string.lower(str(self.enabled)))
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        user = {}
        user["id"] = self.user_id
        user["email"] = self.email
        user["enabled"] = string.lower(str(self.enabled))
        if self.tenant_id:
            user["tenantId"] = self.tenant_id
        return {'user': user}

    def to_json(self):
        return json.dumps(self.to_dict())
