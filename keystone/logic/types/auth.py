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

from abc import ABCMeta
from datetime import datetime
import json
from lxml import etree

import keystone.logic.types.fault as fault
import keystone.logic.types.role as roles


class PasswordCredentials(object):
    """Credentials based on username, password, and (optional) tenant_id.
        To handle multiple token for a user depending on tenants.
    """

    def __init__(self, username, password, tenant_id):
        self.username = username
        self.password = password
        self.tenant_id = tenant_id

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                            "passwordCredentials")
            if root == None:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            username = root.get("username")
            if username == None:
                raise fault.BadRequestFault("Expecting a username")
            password = root.get("password")
            if password == None:
                raise fault.BadRequestFault("Expecting a password")
            tenant_id = root.get("tenantId")
            return PasswordCredentials(username, password, tenant_id)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse password credentials",
                                        str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "passwordCredentials" in obj:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            cred = obj["passwordCredentials"]
            # Check that fields are valid
            invalid = [key for key in cred if key not in\
                       ['username', 'tenantId', 'password']]
            if invalid != []:
                raise fault.BadRequestFault("Invalid attribute(s): %s"
                                            % invalid)
            if not "username" in cred:
                raise fault.BadRequestFault("Expecting a username")
            username = cred["username"]
            if not "password" in cred:
                raise fault.BadRequestFault("Expecting a password")
            password = cred["password"]
            if "tenantId" in cred:
                tenant_id = cred["tenantId"]
            else:
                tenant_id = None
            return PasswordCredentials(username, password, tenant_id)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse password credentials",
                                        str(e))


class Token(object):
    "An auth token."

    def __init__(self, expires, token_id, tenant_id=None):
        self.expires = expires
        self.token_id = token_id
        self.tenant_id = tenant_id


class Group(object):
    "A group, optionally belonging to a tenant."

    def __init__(self, group_id, tenant_id):
        self.tenant_id = tenant_id
        self.group_id = group_id


class Groups(object):
    "A collection of groups."

    def __init__(self, values, links):
        self.values = values
        self.links = links


class User(object):
    "A user."

    def __init__(self, username, tenant_id, groups, role_refs=None):
        self.username = username
        self.tenant_id = tenant_id
        self.groups = groups
        self.role_refs = role_refs


class AuthData(object):
    "Authentation Information returned upon successful login."

    def __init__(self, token, base_urls=None):
        self.token = token
        self.base_urls = base_urls
        self.d = {}
        if self.base_urls != None:
            self.__convert_baseurls_to_dict()

    def to_xml(self):
        dom = etree.Element("auth",
            xmlns="http://docs.openstack.org/identity/api/v2.0")
        token = etree.Element("token",
                             expires=self.token.expires.isoformat())
        token.set("id", self.token.token_id)
        dom.append(token)
        if self.base_urls != None:
            service_catalog = etree.Element("serviceCatalog")
            for key, key_base_urls in self.d.items():
                service = etree.Element("service",
                                 name=key)
                for base_url in key_base_urls:
                    endpoint = etree.Element("endpoint")
                    if base_url.region:
                        endpoint.set("region", base_url.region)
                    if base_url.public_url:
                        endpoint.set("publicURL", base_url.public_url.replace(
                            '%tenant_id%', self.token.tenant_id))
                    if base_url.admin_url:
                        endpoint.set("adminURL", base_url.admin_url.replace(
                            '%tenant_id%', self.token.tenant_id))
                    if base_url.internal_url:
                        endpoint.set("internalURL",
                            base_url.internal_url.replace('%tenant_id%',
                                self.token.tenant_id))
                    service.append(endpoint)
                service_catalog.append(service)
            dom.append(service_catalog)
        return etree.tostring(dom)

    def __convert_baseurls_to_dict(self):
        for base_url in self.base_urls:
            if base_url.service not in self.d:
                self.d[base_url.service] = list()
            self.d[base_url.service].append(base_url)

    def to_json(self):
        token = {}
        token["id"] = self.token.token_id
        token["expires"] = self.token.expires.isoformat()
        auth = {}
        auth["token"] = token
        if self.base_urls != None:
            service_catalog = {}
            for key, key_base_urls in self.d.items():
                endpoints = []
                for base_url in key_base_urls:
                    endpoint = {}
                    if base_url.region:
                        endpoint["region"] = base_url.region
                    if base_url.public_url:
                        endpoint["publicURL"] = base_url.public_url.replace(
                            '%tenant_id%', self.token.tenant_id)
                    if base_url.admin_url:
                        endpoint["adminURL"] = base_url.admin_url.replace(
                            '%tenant_id%', self.token.tenant_id)
                    if base_url.internal_url:
                        endpoint["internalURL"] = base_url.internal_url.replace
                        ('%tenant_id%', self.token.tenant_id)
                    endpoints.append(endpoint)
                service_catalog[key] = endpoints
            auth["serviceCatalog"] = service_catalog
        ret = {}
        ret["auth"] = auth
        return json.dumps(ret)


class ValidateData(object):
    "Authentation Information returned upon successful token validation."

    def __init__(self, token, user):
        self.token = token
        self.user = user

    def to_xml(self):
        dom = etree.Element("auth",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        token = etree.Element("token",
                             expires=self.token.expires.isoformat())
        token.set("id", self.token.token_id)
        if self.token.tenant_id:
            token.set("tenantId", self.token.tenant_id)
        user = etree.Element("user",
                             username=self.user.username,
                             tenantId=str(self.user.tenant_id))
        """groups = etree.Element("groups")
        for group in self.user.groups.values:
            g = etree.Element("group",
                             tenantId=group.tenant_id)
            g.set("id", group.group_id)
            groups.append(g)
        user.append(groups)
        """
        if self.user.role_refs != None:
            user.append(self.user.role_refs.to_dom())
        dom.append(token)
        dom.append(user)
        return etree.tostring(dom)

    def to_json(self):
        token = {}
        token["id"] = self.token.token_id
        token["expires"] = self.token.expires.isoformat()
        if self.token.tenant_id:
            token["tenantId"] = self.token.tenant_id
        user = {}
        user["username"] = self.user.username
        user["tenantId"] = self.user.tenant_id
        if self.user.role_refs != None:
            user["roleRefs"] = self.user.role_refs.to_json_values()

        """group = []
        for g in self.user.groups.values:
            grp = {}
            grp["tenantId"] = g.tenant_id
            grp["id"] = g.group_id
            group.append(grp)
        groups = {}
        groups["group"] = group
        user["groups"] = groups
        """
        auth = {}
        auth["token"] = token
        auth["user"] = user
        ret = {}
        ret["auth"] = auth
        return json.dumps(ret)
