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


class Service(object):
    def __init__(self, service_id, desc):
        self.service_id = service_id
        self.desc = desc

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
                            "service")
            if root == None:
                raise fault.BadRequestFault("Expecting Service")
            service_id = root.get("id")
            desc = root.get("description")
            if service_id == None:
                raise fault.BadRequestFault("Expecting Service")
            return Service(service_id, desc)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse service", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "service" in obj:
                raise fault.BadRequestFault("Expecting service")
            service = obj["service"]
            if not "id" in service:
                service_id = None
            else:
                service_id = service["id"]
            if service_id == None:
                raise fault.BadRequestFault("Expecting service")
            desc = service["description"]
            return Service(service_id, desc)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse service", str(e))

    def to_dom(self):
        dom = etree.Element("service",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.service_id:
            dom.set("id", self.service_id)
        if self.desc:
            dom.set("description", string.lower(str(self.desc)))
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        service = {}
        if self.service_id:
            service["id"] = self.service_id
        if self.desc:
            service["description"] = self.desc
        return {'service': service}

    def to_json(self):
        return json.dumps(self.to_dict())


class Services(object):
    "A collection of services."

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("services")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["service"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"services": {"values": values, "links": links}})
