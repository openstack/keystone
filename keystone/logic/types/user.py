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


class User(object):
    """Document me!"""

    def __init__(self, password, user_id, tenant_id, email, enabled,
            tenant_roles=None):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.password = password
        self.email = email
        self.enabled = enabled and True or False
        self.tenant_roles = tenant_roles

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
                            "user")
            if root == None:
                raise fault.BadRequestFault("Expecting User")
            user_id = root.get("id")
            tenant_id = root.get("tenantId")
            email = root.get("email")
            password = root.get("password")
            enabled = root.get("enabled")
            if user_id == None or len(user_id.strip()) == 0:
                raise fault.BadRequestFault("Expecting User")
            elif password == None or len(password.strip()) == 0:
                raise fault.BadRequestFault("Expecting User password")
            elif email == None:
                raise fault.BadRequestFault("Expecting User email")
            if enabled == None or enabled == "true" or enabled == "yes":
                set_enabled = True
            elif enabled == "false" or enabled == "no":
                set_enabled = False
            else:
                raise fault.BadRequestFault("Bad enabled attribute!")
            if password == '':
                password = user_id
            return User(password, user_id, tenant_id, email, set_enabled)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse User", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "user" in obj:
                raise fault.BadRequestFault("Expecting User")
            user = obj["user"]
            if not "id" in user:
                user_id = None
            else:
                user_id = user["id"]

            if not "password" in user:
                raise fault.BadRequestFault("Expecting User Password")
            password = user["password"]

            if user_id == None or len(user_id.strip()) == 0:
                raise fault.BadRequestFault("Expecting User")
            elif password == None or len(password.strip()) == 0:
                raise fault.BadRequestFault("Expecting User password")

            if "tenantId" in user:
                tenant_id = user["tenantId"]
            else:
                tenant_id = None
            if not "email" in user:
                raise fault.BadRequestFault("Expecting User Email")
            email = user["email"]
            if "enabled" in user:
                set_enabled = user["enabled"]
                if not isinstance(set_enabled, bool):
                    raise fault.BadRequestFault("Bad enabled attribute!")
            else:
                set_enabled = True
            return User(password, user_id, tenant_id, email, set_enabled)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse Tenant", str(e))

    def to_dom(self):
        dom = etree.Element("user",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.email:
            dom.set("email", self.email)
        if self.tenant_id:
            dom.set("tenantId", self.tenant_id)
        if self.user_id:
            dom.set("id", self.user_id)
        if self.enabled:
            dom.set("enabled", string.lower(str(self.enabled)))
        if self.password:
            dom.set("password", self.password)
        if self.tenant_roles:
            dom_roles = etree.Element("tenantRoles")
            for role in self.tenant_roles:
                dom_role = etree.Element("tenantRole")
                dom_role.text = role
                dom_roles.append(dom_role)
            dom.append(dom_roles)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        user = {}

        if self.user_id:
            user["id"] = self.user_id
        if self.tenant_id:
            user["tenantId"] = self.tenant_id
        if self.password:
            user["password"] = self.password
        user["email"] = self.email
        user["enabled"] = self.enabled
        if self.tenant_roles:
            user["tenantRoles"] = list(self.tenant_roles)
        return {'user': user}

    def to_json(self):
        return json.dumps(self.to_dict())


class User_Update(object):
    """Document me!"""

    def __init__(self, password, user_id, tenant_id, email,
            enabled):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.password = password
        self.email = email
        self.enabled = enabled and True or False

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
                            "user")
            if root == None:
                raise fault.BadRequestFault("Expecting User")
            user_id = root.get("id")
            tenant_id = root.get("tenantId")
            email = root.get("email")
            password = root.get("password")
            enabled = root.get("enabled")
            if enabled == None or enabled == "true" or enabled == "yes":
                set_enabled = True
            elif enabled == "false" or enabled == "no":
                set_enabled = False
            else:
                raise fault.BadRequestFault("Bad enabled attribute!")
            if password == '':
                password = user_id
            return User(password, user_id, tenant_id, email, set_enabled)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse User", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "user" in obj:
                raise fault.BadRequestFault("Expecting User")
            user = obj["user"]
            if not "id" in user:
                user_id = None
            else:
                user_id = user["id"]
            if not "password" in user:
                password = None
            else:
                password = user["password"]
            if not "tenantId" in user:
                tenant_id = None
            else:
                tenant_id = user["tenantId"]
            if not "email" in user:
                email = None
            else:
                email = user["email"]
            if "enabled" in user:
                set_enabled = user["enabled"]
                if not isinstance(set_enabled, bool):
                    raise fault.BadRequestFault("Bad enabled attribute!")
            else:
                set_enabled = True
            if password == '':
                password = user_id
            return User(password, user_id, tenant_id, email, set_enabled)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse Tenant", str(e))

    def to_dom(self):
        dom = etree.Element("user",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.email:
            dom.set("email", self.email)
        if self.tenant_id:
            dom.set("tenantId", self.tenant_id)
        if self.user_id:
            dom.set("id", self.user_id)
        if self.enabled is not None:
            dom.set("enabled", string.lower(str(self.enabled)))
        if self.password:
            dom.set("password", self.password)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        user = {}

        if self.user_id:
            user["id"] = self.user_id
        if self.tenant_id:
            user["tenantId"] = self.tenant_id
        if self.password:
            user["password"] = self.password
        if self.email:
            user["email"] = self.email
        if self.enabled is not None:
            user["enabled"] = self.enabled
        return {'user': user}

    def to_json(self):
        return json.dumps(self.to_dict())


class Users(object):
    """A collection of users."""

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("users")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")
        for t in self.values:
            dom.append(t.to_dom())
        for t in self.links:
            dom.append(t.to_dom())
        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["user"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"users": {"values": values, "links": links}})
