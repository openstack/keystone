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
            root = dom.find(
                "{http://docs.openstack.org/identity"\
                "/api/ext/OS-KSCATALOG/v1.0}" \
                "endpointTemplate")
            if root is None:
                raise fault.BadRequestFault("Expecting endpointTemplate")
            id = root.get("id")
            region = root.get("region")
            name = root.get("name")
            type = root.get("type")
            public_url = root.get("publicURL")
            admin_url = root.get("adminURL")
            internal_url = root.get("internalURL")
            enabled = root.get("enabled")
            is_global = root.get("global")
            version = root.find(
                "{http://docs.openstack.org/identity/"\
                "api/v2.0}" \
                "version")
            version_id = None
            version_info = None
            version_list = None
            if version is not None:
                if version.get('id'):
                    version_id = version.get("id")
                if version.get('info'):
                    version_info = version.get("info")
                if version.get('list'):
                    version_list = version.get("list")

            return EndpointTemplate(id, region,
                name, type, public_url, admin_url,
                internal_url, enabled, is_global,
                version_id, version_list, version_info)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse endpointTemplate",
                str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)
            region = None
            name = None
            type = None
            public_url = None
            admin_url = None
            internal_url = None
            enabled = None
            is_global = None
            version_id = None
            version_list = None
            version_info = None
            if not "OS-KSCATALOG:endpointTemplate" in obj:
                raise fault.BadRequestFault(
                "Expecting OS-KSCATALOG:endpointTemplate")
            endpoint_template = obj["OS-KSCATALOG:endpointTemplate"]

            # Check that fields are valid
            invalid = [key for key in endpoint_template if key not in
                       ['id', 'region', 'name', 'type', 'publicURL',
                        'adminURL', 'internalURL', 'enabled', 'global',
                        'versionId', 'versionInfo', 'versionList']]
            if invalid != []:
                raise fault.BadRequestFault("Invalid attribute(s): %s"
                                            % invalid)

            if not "id" in endpoint_template:
                id = None
            else:
                id = endpoint_template["id"]

            if 'region' in endpoint_template:
                region = endpoint_template["region"]
            if 'name' in endpoint_template:
                name = endpoint_template["name"]
            if 'type' in endpoint_template:
                type = endpoint_template["type"]
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
            if 'versionId' in endpoint_template:
                version_id = endpoint_template["versionId"]
            else:
                version_id = None
            if 'versionInfo' in endpoint_template:
                version_info = endpoint_template["versionInfo"]
            else:
                version_info = None
            if 'versionList' in endpoint_template:
                version_list = endpoint_template["versionList"]
            else:
                version_list = None

            return EndpointTemplate(
                    id, region, name, type, public_url, admin_url,
                    internal_url, enabled, is_global, version_id,
                    version_list, version_info)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault(\
                "Cannot parse endpointTemplate", str(e))

    def __init__(self, id, region, name, type, public_url, admin_url,
                 internal_url, enabled, is_global,
                 version_id=None, version_list=None, version_info=None):
        self.id = id
        self.region = region
        self.name = name
        self.type = type
        self.public_url = public_url
        self.admin_url = admin_url
        self.internal_url = internal_url
        self.enabled = bool(enabled)
        self.is_global = bool(is_global)
        self.version_id = version_id
        self.version_list = version_list
        self.version_info = version_info

    def to_dom(self):
        dom = etree.Element("endpointTemplate",
            xmlns="http://docs.openstack.org/"
            "identity/api/ext/OS-KSCATALOG/v1.0")
        if self.id:
            dom.set("id", str(self.id))
        if self.region:
            dom.set("region", self.region)
        if self.name:
            dom.set("name", str(self.name))
        if self.type:
            dom.set("type", str(self.type))
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
        version = etree.Element("version",
            xmlns="http://docs.openstack.org"
            "/identity/api/v2.0")
        if self.version_id:
            version.set("id", self.version_id)
            if self.version_info:
                version.set("info", self.version_info)
            if self.version_list:
                version.set("list", self.version_list)
            dom.append(version)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        endpoint_template = {}
        if self.id:
            endpoint_template["id"] = unicode(self.id)
        if self.region:
            endpoint_template["region"] = self.region
        if self.name:
            endpoint_template["name"] = self.name
        if self.type:
            endpoint_template["type"] = self.type
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
        if self.version_id:
            endpoint_template["versionId"] = self.version_id
            if self.version_info:
                endpoint_template["versionInfo"] = self.version_info
            if self.version_list:
                endpoint_template["versionList"] = self.version_list
        return {'OS-KSCATALOG:endpointTemplate': endpoint_template}

    def to_json(self):
        return json.dumps(self.to_dict())


class EndpointTemplates(object):
    """A collection of endpointTemplates."""

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("endpointTemplates")
        dom.set(u"xmlns",
            "http://docs.openstack.org/identity/api/ext/OS-KSCATALOG/v1.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["OS-KSCATALOG:endpointTemplate"]
            for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"OS-KSCATALOG:endpointTemplates": values,
             "OS-KSCATALOG:endpointTemplates_links": links})


class Endpoint(object):
    """Document me!"""

    def __init__(self, id, tenant_id, region,
                 name, type, public_url, admin_url,
                 internal_url, version_id=None,
                 version_list=None, version_info=None):
        self.id = id
        self.tenant_id = tenant_id
        self.region = region
        self.name = name
        self.type = type
        self.public_url = self.substitute_tenant_id(public_url)
        self.admin_url = self.substitute_tenant_id(admin_url)
        self.internal_url = self.substitute_tenant_id(internal_url)
        self.version_id = version_id
        self.version_list = version_list
        self.version_info = version_info

    def to_dom(self):
        dom = etree.Element("endpoint",
            xmlns="http://docs.openstack.org/identity/api/v2.0")
        if self.id:
            dom.set("id", str(self.id))
        if self.tenant_id:
            dom.set("tenantId", str(self.tenant_id))
        if self.region:
            dom.set("region", self.region)
        if self.name:
            dom.set("name", str(self.name))
        if self.type:
            dom.set("type", str(self.type))
        if self.public_url:
            dom.set("publicURL", self.public_url)
        if self.admin_url:
            dom.set("adminURL", self.admin_url)
        if self.internal_url:
            dom.set("internalURL", self.internal_url)
        version = etree.Element("version",
            xmlns="http://docs.openstack.org"
            "/identity/api/v2.0")
        if self.version_id:
            version.set("id", self.version_id)
            if self.version_info:
                version.set("info", self.version_info)
            if self.version_list:
                version.set("list", self.version_list)
            dom.append(version)
        return dom

    def to_xml(self):
        return etree.tostring(self.to_dom())

    def to_dict(self):
        endpoint = {}
        if self.id:
            endpoint["id"] = self.id
        if self.tenant_id:
            endpoint["tenantId"] = self.tenant_id
        if self.region:
            endpoint["region"] = self.region
        if self.name:
            endpoint["name"] = self.name
        if self.type:
            endpoint["type"] = self.type
        if self.public_url:
            endpoint["publicURL"] = self.public_url
        if self.admin_url:
            endpoint["adminURL"] = self.admin_url
        if self.internal_url:
            endpoint["internalURL"] = self.internal_url
        if self.version_id:
            endpoint["versionId"] = self.version_id
            if self.version_info:
                endpoint["versionInfo"] = self.version_info
            if self.version_list:
                endpoint["versionList"] = self.version_list
        return {'endpoint': endpoint}

    def substitute_tenant_id(self, url):
        if url:
            return url.replace('%tenant_id%',
                str(self.tenant_id))
        return url

    def to_json(self):
        return json.dumps(self.to_dict())


class Endpoints(object):
    """A collection of endpoints."""

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("endpoints")
        dom.set(u"xmlns",
            "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_json(self):
        values = [t.to_dict()["endpoint"] for t in self.values]
        links = [t.to_dict()["links"] for t in self.links]
        return json.dumps({"endpoints": values, "endpoints_links": links})
