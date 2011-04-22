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


class Credentials(object):
    "Base class for all auth credentials."
    __metaclass__ = ABCMeta


class PasswordCredentials(Credentials):
    "Credentials based on username, password, and (optional) tenant_id."

    def __init__(self, username, password, tenant_id):
        self.__username = username
        self.__password = password
        self.__tenant_id = tenant_id

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append (etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/idm/api/v1.0}passwordCredentials")
            if root == None:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            username=root.get("username")
            if username == None:
                raise fault.BadRequestFault("Expecting a username")
            password=root.get("password")
            if password == None:
                raise fault.BadRequestFault("Expecting a password")
            tenant_id=root.get("tenantId")
            return PasswordCredentials (username, password, tenant_id)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse password credentials", e.__str__())

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "passwordCredentials" in obj:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            cred = obj["passwordCredentials"]
            if not "username" in cred:
                raise fault.BadRequestFault("Expecting a username")
            username=cred["username"]
            if not "password" in cred:
                raise fault.BadRequestFault("Expecting a password")
            password=cred["password"]
            if "tenantId" in cred:
                tenant_id = cred["tenantId"]
            else:
                tenant_id = None
            return PasswordCredentials (username, password, tenant_id)
        except (json.decoder.JSONDecodeError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse password credentials", e.__str__())

    @property
    def username(self):
        return self.__username

    @property
    def password(self):
        return self.__password

    @property
    def tenant_id(self):
        return self.__password


class Token(object):
    "An auth token."

    def __init__(self, expires, token_id):
        self.__expires = expires
        self.__token_id = token_id

    @property
    def expires(self):
        return self.__expires

    @property
    def token_id(self):
        return self.__token_id


class Group(object):
    "A group, optionally belonging to a tenant."

    def __init__(self, group_id, tenant_id):
        self.__tenant_id = tenant_id
        self.__group_id = group_id

    @property
    def group_id(self):
        return self.__group_id

    @property
    def tenant_id(self):
        return self.__tenant_id


class Groups(object):
    "A collection of groups."

    def __init__(self, values, links):
        self.__values = values
        self.__links = links

    @property
    def values(self):
        return self.__values

    @property
    def links(self):
        return self.__links


class User(object):
    "A user."

    def __init__(self, username, tenant_id, groups):
        self.__username = username
        self.__tenant_id = tenant_id
        self.__groups = groups

    @property
    def username(self):
        return self.__username

    @property
    def tenant_id(self):
        return self.__tenant_id

    @property
    def groups(self):
        return self.__groups


class AuthData(object):
    "Authentation Infor returned upon successful login."

    def __init__(self, token, user):
        self.__token = token
        self.__user = user

    @property
    def user(self):
        return self.__user

    @property
    def token(self):
        return self.__token

    def to_xml(self):
        dom = etree.Element("auth",
                             xmlns="http://docs.openstack.org/idm/api/v1.0")
        token = etree.Element("token",
                             expires=self.__token.expires.isoformat())
        token.set("id", self.__token.token_id)
        user = etree.Element("user",
                             username=self.__user.username,
                             tenantId=self.__user.tenant_id)
        groups = etree.Element("groups")
        for group in self.__user.groups.values:
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
        token["id"] = self.__token.token_id
        token["expires"] = self.__token.expires.isoformat()
        user = {}
        user["username"] = self.__user.username
        user["tenantId"] = self.__user.tenant_id
        group = []
        for g in self.__user.groups.values:
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
