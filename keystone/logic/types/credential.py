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

from keystone.logic.types import fault


class PasswordCredentials(object):
    def __init__(self, user_name, password):
        self.user_name = user_name
        self.password = password

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
                "passwordCredentials")
            if root == None:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            user_name = root.get("username")
            password = root.get("password")
            if password is None:
                raise fault.BadRequestFault("Expecting password")
            return PasswordCredentials(user_name, password)
        except etree.LxmlError as e:
            raise fault.BadRequestFault(
                "Cannot parse passwordCredentials", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "passwordCredentials" in obj:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            password_credentials = obj["passwordCredentials"]

            user_name = password_credentials.get('username')
            password = password_credentials.get('password')
            if password is None:
                raise fault.BadRequestFault("Expecting password.")
            return PasswordCredentials(user_name, password)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault(
                "Cannot parse passwordCredentials", str(e))

    def to_dom(self):
        dom = etree.Element("passwordCredentials",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.user_name:
            dom.set("username", unicode(self.user_name))
        if self.password:
            dom.set("password", unicode(self.password))
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        password_credentials = {}
        if self.user_name:
            password_credentials["username"] = unicode(self.user_name)
        if self.password:
            password_credentials['password'] = unicode(self.password)
        return {'passwordCredentials': password_credentials}

    def to_json(self):
        return json.dumps(self.to_dict())


class Credentials(object):
    "A collection of credentials."

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("credentials")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_dom(self):
        dom = etree.Element("credentials")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return dom

    def to_json(self):
        values = [t.to_dict() for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"credentials": values, "credentials_links": links})
