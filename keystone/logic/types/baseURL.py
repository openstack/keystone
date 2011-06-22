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

import keystone.logic.types.fault as fault


class BaseURL(object):
    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
                            "baseURL")
            if root == None:
                raise fault.BadRequestFault("Expecting baseURL")
            id = root.get("id")
            region = root.get("region")
            service = root.get("serviceName")
            public_url = root.get("publicURL")
            admin_url = root.get("adminURL")
            internal_url = root.get("internalURL")
            enabled = root.get("enabled")
            return BaseURL(id, region, service, public_url, admin_url,
                           internal_url, enabled)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse baseURL", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            region = None
            service = None
            public_url = None
            admin_url = None
            internal_url = None
            enabled = None

            if not "baseURL" in obj:
                raise fault.BadRequestFault("Expecting baseURL")
            baseURL = obj["baseURL"]
            if not "id" in baseURL:
                id = None
            else:
                id = baseURL["id"]
            if id == None:
                raise fault.BadRequestFault("Expecting BaseURL")

            if 'region' in baseURL:
                region = baseURL["region"]
            if 'serviceName' in baseURL:
                service = baseURL["serviceName"]
            if 'publicURL' in baseURL:
                public_url = baseURL["publicURL"]
            if 'adminURL' in baseURL:
                admin_url = baseURL["adminURL"]
            if 'internalURL' in baseURL:
                internal_url = baseURL["internalURL"]
            if 'enabled' in baseURL:
                enabled = baseURL["enabled"]

            return BaseURL(id, region, service, public_url, admin_url,
                           internal_url, enabled)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse baseURL", str(e))

    def __init__(self, id, region, service, public_url, admin_url,
                 internal_url, enabled):
        self.id = id
        self.region = region
        self.service = service
        self.public_url = public_url
        self.admin_url = admin_url
        self.internal_url = internal_url
        self.enabled = enabled

    def to_dom(self):
        dom = etree.Element("baseURL",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.id:
            dom.set("id", str(self.id))
        if self.region:
            dom.set("region", self.region)
        if self.service:
            dom.set("serviceName", self.service)
        if self.public_url:
            dom.set("publicURL", self.public_url)
        if self.admin_url:
            dom.set("adminURL", self.admin_url)
        if self.internal_url:
            dom.set("internalURL", self.internal_url)
        if self.enabled:
            dom.set("enabled", 'true')
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        baseURL = {}
        if self.id:
            baseURL["id"] = self.id
        if self.region:
            baseURL["region"] = self.region
        if self.service:
            baseURL["serviceName"] = self.service
        if self.public_url:
            baseURL["publicURL"] = self.public_url
        if self.admin_url:
            baseURL["adminURL"] = self.admin_url
        if self.internal_url:
            baseURL["internalURL"] = self.internal_url
        if self.enabled:
            baseURL["enabled"] = self.enabled
        return {'baseURL': baseURL}

    def to_json(self):
        return json.dumps(self.to_dict())


class BaseURLs(object):
    "A collection of baseURls."

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("baseURLs")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["baseURL"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"baseURLs": {"values": values, "links": links}})


class BaseURLRef(object):
    def __init__(self, id, href):
        self.id = id
        self.href = href

    def to_dom(self):
        dom = etree.Element("baseURLRef",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.id:
            dom.set("id", str(self.id))
        if self.href:
            dom.set("href", self.href)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        baseURLRef = {}
        if self.id:
            baseURLRef["id"] = self.id
        if self.href:
            baseURLRef["href"] = self.href
        return {'baseURLRef': baseURLRef}

    def to_json(self):
        return json.dumps(self.to_dict())


class BaseURLRefs(object):
    "A collection of baseURlRefs."

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("baseURLRefs")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["baseURLRef"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"baseURLRefs": {"values": values, "links": links}})
