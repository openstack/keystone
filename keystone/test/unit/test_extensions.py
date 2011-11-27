import unittest2 as unittest
from keystone.logic.extension_reader import ExtensionsReader
from keystone.contrib.extensions import CONFIG_EXTENSION_PROPERTY
from keystone.contrib.extensions.admin import EXTENSION_ADMIN_PREFIX
from xml.etree import ElementTree
import json


class MockOptions(object):
    """ Mock object that mimics options."""
    def __init__(self, loaded_extensions):
        self.loaded_extensions = loaded_extensions

    def get(self, prop_name, default):
        if prop_name == CONFIG_EXTENSION_PROPERTY:
            return self.loaded_extensions


class TestExtensionReader(unittest.TestCase):
    """Unit tests for ExtensionsReader.These
    tests check whether the returned extensions vary
    when they are configured differently."""

    def setUp(self):
        self.options = MockOptions("osksadm")
        self.extensions_reader = ExtensionsReader(self.options,
            EXTENSION_ADMIN_PREFIX)

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
