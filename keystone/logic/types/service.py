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
from keystone import utils


class Service(object):
    def __init__(self, id, name, type, description):
        self.id = id
        self.name = name
        self.type = type
        self.description = description

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find(
                "{http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0}"\
                "service")
            if root is None:
                raise fault.BadRequestFault("Expecting Service")
            id = root.get("id")
            name = root.get("name")
            type = root.get("type")
            description = root.get("description")
            utils.check_empty_string(name, "Expecting Service Name")
            utils.check_empty_string(type, "Expecting Service Type")
            return Service(id, name, type, description)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse service", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            if not "OS-KSADM:service" in obj:
                raise fault.BadRequestFault("Expecting service")
            service = obj["OS-KSADM:service"]

            # Check that fields are valid
            invalid = [key for key in service if key not in\
                       ['id', 'name', 'type', 'description']]
            if invalid != []:
                raise fault.BadRequestFault("Invalid attribute(s): %s"
                                            % invalid)

            id = service.get('id')
            name = service.get('name')
            type = service.get('type')
            description = service.get('description')
            utils.check_empty_string(name, "Expecting Service Name")
            utils.check_empty_string(type, "Expecting Service Type")
            return Service(id, name, type, description)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse service", str(e))

    def to_dom(self):
        dom = etree.Element("service",
            xmlns="http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0")
        if self.id:
            dom.set("id", unicode(self.id))
        if self.name:
            dom.set("name", unicode(self.name))
        if self.type:
            dom.set("type", unicode(self.type))
        if self.description:
            dom.set("description", unicode(self.description).lower())
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        service = {}
        if self.id:
            service["id"] = unicode(self.id)
        if self.name:
            service["name"] = unicode(self.name)
        if self.type:
            service["type"] = unicode(self.type)
        if self.description:
            service["description"] = unicode(self.description).lower()
        return {'OS-KSADM:service': service}

    def to_json(self):
        return json.dumps(self.to_dict())


class Services(object):
    "A collection of services."

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("services")
        dom.set(u"xmlns",
            "http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        services = [t.to_dict()["OS-KSADM:service"] for t in self.values]
        services_links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"OS-KSADM:services": services,
            "OS-KSADM:services_links": services_links})
