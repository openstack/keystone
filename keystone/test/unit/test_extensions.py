# Copyright (c) 2011 OpenStack, LLC.
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

from xml.etree import ElementTree
import json
import unittest2 as unittest

from keystone import config
from keystone.contrib.extensions import CONFIG_EXTENSION_PROPERTY
from keystone.contrib.extensions.admin import EXTENSION_ADMIN_PREFIX
from keystone.logic.extension_reader import ExtensionsReader
from keystone.logic.extension_reader import get_supported_extensions

CONF = config.CONF


class TestExtensionReader(unittest.TestCase):
    """Unit tests for ExtensionsReader.These
    tests check whether the returned extensions vary
    when they are configured differently."""

    def setUp(self):
        self.original_extensions = CONF.extensions
        CONF.set_override(CONFIG_EXTENSION_PROPERTY, ["osksadm"])
        self.extensions_reader = ExtensionsReader(EXTENSION_ADMIN_PREFIX)

    def tearDown(self):
        CONF.set_override(CONFIG_EXTENSION_PROPERTY, self.original_extensions)

    def test_extensions_reader_getsupportedoptions(self):
        self.assertIn('osksadm', get_supported_extensions())

    def test_extensions_with_only_osksadm_json(self):
        r = self.extensions_reader.get_extensions().to_json()
        content = json.loads(r)
        self.assertIsNotNone(content['extensions'])
        self.assertIsNotNone(content['extensions']['values'])
        found_osksadm = False
        found_oskscatalog = False
        for value in content['extensions']['values']:
            if value['extension']['alias'] == 'OS-KSADM':
                found_osksadm = True
            if value['extension']['alias'] == 'OS-KSCATALOG':
                found_oskscatalog = True
        self.assertTrue(found_osksadm,
            "Missing OS-KSADM extension.")
        self.assertFalse(found_oskscatalog,
            "Non configured OS-KSCATALOG extension returned.")

    def test_extensions_with_only_osksadm_xml(self):
        r = self.extensions_reader.get_extensions().to_xml()
        content = ElementTree.XML(r)
        extensions = content.findall(
            "{http://docs.openstack.org/common/api/v1.0}extension")
        found_osksadm = False
        found_oskscatalog = False
        for extension in extensions:
            if extension.get("alias") == 'OS-KSADM':
                found_osksadm = True
            if extension.get("alias") == 'OS-KSCATALOG':
                found_oskscatalog = True
        self.assertTrue(found_osksadm,
            "Missing OS-KSADM extension.")
        self.assertFalse(found_oskscatalog,
            "Non configured OS-KSCATALOG extension returned.")


if __name__ == '__main__':
    unittest.main()
