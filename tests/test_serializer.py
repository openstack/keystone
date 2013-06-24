# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy

from keystone.common import serializer
from keystone import test


class XmlSerializerTestCase(test.TestCase):
    def assertSerializeDeserialize(self, d, xml, xmlns=None):
        self.assertEqualXML(
            serializer.to_xml(copy.deepcopy(d), xmlns),
            xml)
        self.assertEqual(serializer.from_xml(xml), d)

        # operations should be invertible
        self.assertEqual(
            serializer.from_xml(serializer.to_xml(copy.deepcopy(d), xmlns)),
            d)
        self.assertEqualXML(
            serializer.to_xml(serializer.from_xml(xml), xmlns),
            xml)

    def test_auth_request(self):
        d = {
            "auth": {
                "passwordCredentials": {
                    "username": "test_user",
                    "password": "mypass"
                },
                "tenantName": "customer-x"
            }
        }

        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <auth xmlns="http://docs.openstack.org/identity/api/v2.0"
                    tenantName="customer-x">
                <passwordCredentials
                        username="test_user"
                        password="mypass"/>
            </auth>
        """

        self.assertSerializeDeserialize(d, xml)

    def test_role_crud(self):
        d = {
            "role": {
                "id": "123",
                "name": "Guest",
                "description": "Guest Access"
            }
        }

        # TODO(dolph): examples show this description as an attribute?
        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <role xmlns="http://docs.openstack.org/identity/api/v2.0"
                    id="123"
                    name="Guest">
                <description>Guest Access</description>
            </role>
        """

        self.assertSerializeDeserialize(d, xml)

    def test_service_crud(self):
        xmlns = "http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0"

        d = {
            "OS-KSADM:service": {
                "id": "123",
                "name": "nova",
                "type": "compute",
                "description": "OpenStack Compute Service"
            }
        }

        # TODO(dolph): examples show this description as an attribute?
        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <service
                    xmlns="%(xmlns)s"
                    type="compute"
                    id="123"
                    name="nova">
                <description>OpenStack Compute Service</description>
            </service>
        """ % {'xmlns': xmlns}

        self.assertSerializeDeserialize(d, xml, xmlns=xmlns)

    def test_tenant_crud(self):
        d = {
            "tenant": {
                "id": "1234",
                "name": "ACME corp",
                "description": "A description...",
                "enabled": True
            }
        }

        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <tenant
                    xmlns="http://docs.openstack.org/identity/api/v2.0"
                    enabled="true"
                    id="1234"
                    name="ACME corp">
                <description>A description...</description>
            </tenant>
        """

        self.assertSerializeDeserialize(d, xml)

    def test_tenant_crud_no_description(self):
        d = {
            "tenant": {
                "id": "1234",
                "name": "ACME corp",
                "description": "",
                "enabled": True
            }
        }

        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <tenant
                    xmlns="http://docs.openstack.org/identity/api/v2.0"
                    enabled="true"
                    id="1234"
                    name="ACME corp">
                <description></description>
            </tenant>
        """

        self.assertSerializeDeserialize(d, xml)

    def test_policy_list(self):
        d = {"policies": [{"id": "ab12cd"}]}

        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <policies xmlns="http://docs.openstack.org/identity/api/v2.0">
                <policy id="ab12cd"/>
            </policies>
        """
        self.assertEqualXML(serializer.to_xml(d), xml)

    def test_values_list(self):
        d = {
            "objects": {
                "values": [{
                    "attribute": "value1",
                }, {
                    "attribute": "value2",
                }]
            }
        }

        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <objects xmlns="http://docs.openstack.org/identity/api/v2.0">
                <object attribute="value1"/>
                <object attribute="value2"/>
            </objects>
        """

        self.assertEqualXML(serializer.to_xml(d), xml)

    def test_collection_list(self):
        d = {
            "links": {
                "next": "http://localhost:5000/v3/objects?page=3",
                "previous": None,
                "self": "http://localhost:5000/v3/objects"
            },
            "objects": [{
                "attribute": "value1",
                "links": {
                    "self": "http://localhost:5000/v3/objects/abc123def",
                    "anotherobj": "http://localhost:5000/v3/anotherobjs/123"
                }
            }, {
                "attribute": "value2",
                "links": {
                    "self": "http://localhost:5000/v3/objects/abc456"
                }
            }]}
        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <objects xmlns="http://docs.openstack.org/identity/api/v2.0">
                <object attribute="value1">
                    <links>
                        <link rel="self"
                            href="http://localhost:5000/v3/objects/abc123def"/>
                        <link rel="anotherobj"
                            href="http://localhost:5000/v3/anotherobjs/123"/>
                    </links>
                </object>
                <object attribute="value2">
                     <links>
                         <link rel="self"
                             href="http://localhost:5000/v3/objects/abc456"/>
                     </links>
                </object>
                <links>
                    <link rel="self"
                        href="http://localhost:5000/v3/objects"/>
                    <link rel="next"
                        href="http://localhost:5000/v3/objects?page=3"/>
                </links>
            </objects>
        """
        self.assertSerializeDeserialize(d, xml)

    def test_collection_member(self):
        d = {
            "object": {
                "attribute": "value",
                "links": {
                    "self": "http://localhost:5000/v3/objects/abc123def",
                    "anotherobj": "http://localhost:5000/v3/anotherobjs/123"}}}

        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <object xmlns="http://docs.openstack.org/identity/api/v2.0"
                attribute="value">
                    <links>
                        <link rel="self"
                            href="http://localhost:5000/v3/objects/abc123def"/>
                        <link rel="anotherobj"
                            href="http://localhost:5000/v3/anotherobjs/123"/>
                    </links>
            </object>
        """
        self.assertSerializeDeserialize(d, xml)

    def test_v2_links_special_case(self):
        # There's special-case code (for backward compatibility) where if the
        # data is the v2 version data, the link elements are also added to the
        # main element.

        d = {
            "object": {
                "id": "v2.0",
                "status": "stable",
                "updated": "2013-03-06T00:00:00Z",
                "links": [{"href": "http://localhost:5000/v2.0/",
                           "rel": "self"},
                          {"href": "http://docs.openstack.org/api/openstack-"
                                   "identity-service/2.0/content/",
                           "type": "text/html", "rel": "describedby"},
                          {"href": "http://docs.openstack.org/api/openstack-"
                                   "identity-service/2.0/"
                                   "identity-dev-guide-2.0.pdf",
                           "type": "application/pdf", "rel": "describedby"}]
            }}

        xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <object xmlns="http://docs.openstack.org/identity/api/v2.0"
                id="v2.0" status="stable" updated="2013-03-06T00:00:00Z">
                    <links>
                        <link rel="self" href="http://localhost:5000/v2.0/"/>
                        <link rel="describedby"
                              href="http://docs.openstack.org/api/openstack-\
identity-service/2.0/content/" type="text/html"/>
                        <link rel="describedby"
                              href="http://docs.openstack.org/api/openstack-\
identity-service/2.0/identity-dev-guide-2.0.pdf" type="application/pdf"/>
                    </links>
                    <link rel="self" href="http://localhost:5000/v2.0/"/>
                    <link rel="describedby"
                          href="http://docs.openstack.org/api/openstack-\
identity-service/2.0/content/" type="text/html"/>
                    <link rel="describedby"
                          href="http://docs.openstack.org/api/openstack-\
identity-service/2.0/identity-dev-guide-2.0.pdf" type="application/pdf"/>
            </object>
        """
        self.assertEqualXML(serializer.to_xml(d), xml)
