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

import re

from keystone import test
from keystone.common import serializer


class XmlSerializerTestCase(test.TestCase):
    def assertEqualIgnoreWhitespace(self, a, b):
        """Splits two strings into lists and compares them.

        This provides easy-to-read failures from nose.

        """
        try:
            self.assertEqual(a, b)
        except:
            a = re.sub('[ \n]+', ' ', a).strip().split()
            b = re.sub('[ \n]+', ' ', b).strip().split()
            self.assertEqual(a, b)

    def assertSerializeDeserialize(self, d, xml, xmlns=None):
        self.assertEqualIgnoreWhitespace(serializer.to_xml(d, xmlns), xml)
        self.assertEqual(serializer.from_xml(xml), d)

        # operations should be invertable
        self.assertEqual(
                serializer.from_xml(serializer.to_xml(d, xmlns)),
                d)
        self.assertEqualIgnoreWhitespace(
                serializer.to_xml(serializer.from_xml(xml), xmlns),
                xml)

    def test_none(self):
        d = None
        xml = None

        self.assertSerializeDeserialize(d, xml)

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
            # FIXME(dolph): should be...
            # "OS-KSADM:service": {
            "service": {
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

        self.assertEqualIgnoreWhitespace(serializer.to_xml(d), xml)
