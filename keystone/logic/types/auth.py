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

from datetime import datetime

from abc import ABCMeta
import simplejson as json
import keystone.logic.types.fault as fault
from lxml import etree


class PasswordCredentials(object):
    "Credentials based on username, password, and (optional) tenant_id."

    def __init__(self, username, password, tenant_id):
        self.username = username
        self.password = password
        self.tenant_id = tenant_id

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/idm/api/v1.0}"
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
        except (json.decoder.JSONDecodeError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse password credentials",
                                        str(e))


class Token(object):
    "An auth token."

    def __init__(self, expires, token_id):
        self.expires = expires
        self.token_id = token_id


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

    def __init__(self, username, tenant_id, groups):
        self.username = username
        self.tenant_id = tenant_id
        self.groups = groups


class AuthData(object):
    "Authentation Infor returned upon successful login."

    def __init__(self, token, user):
        self.token = token
        self.user = user

    def to_xml(self):
        dom = etree.Element("auth",
                             xmlns="http://docs.openstack.org/idm/api/v1.0")
        token = etree.Element("token",
                             expires=self.token.expires.isoformat())
        token.set("id", self.__token.token_id)
        user = etree.Element("user",
                             username=self.user.username,
                             tenantId=self.user.tenant_id)
        groups = etree.Element("groups")
        for group in self.user.groups.values:
            g = etree.Element("group",
                             tenantId=group.tenant_id)
            g.set("id", group.group_id)
            groups.append(g)
        user.append(groups)
        dom.append(token)
        dom.append(user)
        return etree.tostring(dom)

    def to_json(self):
        token = {}
        token["id"] = self.token.token_id
        token["expires"] = self.token.expires.isoformat()
        user = {}
        user["username"] = self.user.username
        user["tenantId"] = self.user.tenant_id
        group = []
        for g in self.user.groups.values:
            grp = {}
            grp["tenantId"] = g.tenant_id
            grp["id"] = g.group_id
            group.append(grp)
        groups = {}
        groups["group"] = group
        user["groups"] = groups
        auth = {}
        auth["token"] = token
        auth["user"] = user
        ret = {}
        ret["auth"] = auth
        return json.dumps(ret)
