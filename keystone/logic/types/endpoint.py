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


class EndpointTemplate(object):
    """Document me!"""

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}" \
                            "endpointTemplate")
            if root == None:
                raise fault.BadRequestFault("Expecting endpointTemplate")
            id = root.get("id")
            region = root.get("region")
            service = root.get("serviceId")
            public_url = root.get("publicURL")
            admin_url = root.get("adminURL")
            internal_url = root.get("internalURL")
            enabled = root.get("enabled")
            is_global = root.get("global")
            return EndpointTemplate(id, region, service, public_url, admin_url,
                internal_url, enabled, is_global)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse endpointTemplate",
                str(e))

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
            is_global = None

            if not "endpointTemplate" in obj:
                raise fault.BadRequestFault("Expecting endpointTemplate")
            endpoint_template = obj["endpointTemplate"]

            # Check that fields are valid
            invalid = [key for key in endpoint_template if key not in
                       ['id', 'region', 'serviceId', 'publicURL',
                        'adminURL', 'internalURL', 'enabled', 'global']]
            if invalid != []:
                raise fault.BadRequestFault("Invalid attribute(s): %s"
                                            % invalid)

            if not "id" in endpoint_template:
                id = None
            else:
                id = endpoint_template["id"]

            if 'region' in endpoint_template:
                region = endpoint_template["region"]
            if 'serviceId' in endpoint_template:
                service = endpoint_template["serviceId"]
            if 'publicURL' in endpoint_template:
                public_url = endpoint_template["publicURL"]
            if 'adminURL' in endpoint_template:
                admin_url = endpoint_template["adminURL"]
            if 'internalURL' in endpoint_template:
                internal_url = endpoint_template["internalURL"]
            if 'enabled' in endpoint_template:
                enabled = endpoint_template["enabled"]
            if 'global' in endpoint_template:
                is_global = endpoint_template["global"]

            return EndpointTemplate(id, region, service, public_url, admin_url,
                           internal_url, enabled, is_global)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault(\
                "Cannot parse endpointTemplate", str(e))

    def __init__(self, id, region, service, public_url, admin_url,
                 internal_url, enabled, is_global):
        self.id = id
        self.region = region
        self.service = service
        self.public_url = public_url
        self.admin_url = admin_url
        self.internal_url = internal_url
        self.enabled = bool(enabled)
        self.is_global = bool(is_global)

    def to_dom(self):
        dom = etree.Element("endpointTemplate",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.id:
            dom.set("id", str(self.id))
        if self.region:
            dom.set("region", self.region)
        if self.service:
            dom.set("serviceId", str(self.service))
        if self.public_url:
            dom.set("publicURL", self.public_url)
        if self.admin_url:
            dom.set("adminURL", self.admin_url)
        if self.internal_url:
            dom.set("internalURL", self.internal_url)
        if self.enabled:
            dom.set("enabled", str(self.enabled).lower())
        if self.is_global:
            dom.set("global", str(self.is_global).lower())
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        endpoint_template = {}
        if self.id:
            endpoint_template["id"] = unicode(self.id)
        if self.region:
            endpoint_template["region"] = self.region
        if self.service:
            endpoint_template["serviceId"] = self.service
        if self.public_url:
            endpoint_template["publicURL"] = self.public_url
        if self.admin_url:
            endpoint_template["adminURL"] = self.admin_url
        if self.internal_url:
            endpoint_template["internalURL"] = self.internal_url
        if self.enabled:
            endpoint_template["enabled"] = self.enabled
        if self.is_global:
            endpoint_template["global"] = self.is_global
        return {'endpointTemplate': endpoint_template}

    def to_json(self):
        return json.dumps(self.to_dict())


class EndpointTemplates(object):
    """A collection of endpointTemplates."""

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("endpointTemplates")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["endpointTemplate"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"endpointTemplates":\
            {"values": values, "links": links}})


class Endpoint(object):
    """Document me!"""

    def __init__(self, id, href):
        self.id = id
        self.href = href

    def to_dom(self):
        dom = etree.Element("endpoint",
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.id:
            dom.set("id", str(self.id))
        if self.href:
            dom.set("href", self.href)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        endpoint = {}
        if self.id:
            endpoint["id"] = self.id
        if self.href:
            endpoint["href"] = self.href
        return {'endpoint': endpoint}

    def to_json(self):
        return json.dumps(self.to_dict())


class Endpoints(object):
    """A collection of endpoints."""

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("endpoints")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["endpoint"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"endpoints": {"values": values, "links": links}})
