# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

import json
import logging
from lxml import etree
import unittest2 as unittest
from webob import Request

from keystone.controllers.version import VersionController

LOGGER = logging.getLogger(__name__)


class TestVersionController(unittest.TestCase):
    def setUp(self):
        self.controller = VersionController()

    def _default_version(self, file=None):
        """ Verify default response for versions is JSON """
        if file is None:
            file = 'admin/version'
        req = Request.blank('/')
        req.environ = {}
        response = self.controller.get_version_info(req, file=file)
        self.assertEqual(response.content_type, 'application/json')
        data = json.loads(response.body)
        self.assertIsNotNone(data)

    def _json_version(self, file=None):
        """ Verify JSON response for versions

        Checks that JSON is returned when Accept is set to application/json.
        Also checks that verions and version exist and that
        values are as expected

        """
        if file is None:
            file = 'admin/version'
        req = Request.blank('/')
        req.headers['Accept'] = 'application/json'
        req.environ = {}
        response = self.controller.get_version_info(req, file=file)
        self.assertEqual(response.content_type, 'application/json')
        data = json.loads(response.body)
        self.assertIn("versions", data)
        versions = data['versions']
        self.assertIn("values", versions)
        values = versions['values']
        self.assertIsInstance(values, list)
        for version in values:
            for item in version:
                self.assertIn(item, ["id", "status", "updated", "links",
                                     "media-types"])

    def _xml_version(self, file=None):
        """ Verify XML response for versions

        Checks that XML is returned when Accept is set to application/xml.
        Also checks that verions and version tags exist and that
        attributes are as expected

        """
        if file is None:
            file = 'admin/version'
        req = Request.blank('/')
        req.headers['Accept'] = 'application/xml'
        req.environ = {}
        response = self.controller.get_version_info(req, file=file)
        self.assertEqual(response.content_type, 'application/xml')
        data = etree.fromstring(response.body)
        self.assertEqual(data.tag,
                         '{http://docs.openstack.org/common/api/v2.0}versions')
        for version in data:
            self.assertEqual(version.tag,
                         '{http://docs.openstack.org/common/api/v2.0}version')
            for attribute in version.attrib:
                self.assertIn(attribute, ["id", "status", "updated", "links",
                                     "media-types"])

    def _atom_version(self, file=None):
        """ Verify ATOM response for versions

        Checks that ATOM XML is returned when Accept is set to
        aapplication/atom+xml.
        Also checks that verions and version tags exist and that
        attributes are as expected

        """
        if file is None:
            file = 'admin/version'
        req = Request.blank('/')
        req.headers['Accept'] = 'application/atom+xml'
        req.environ = {}
        response = self.controller.get_version_info(req, file=file)
        self.assertEqual(response.content_type, 'application/atom+xml')
        data = etree.fromstring(response.body)
        self.assertEqual(data.tag,
                         '{http://www.w3.org/2005/Atom}feed')

    def test_default_version_admin(self):
        self._default_version(file='admin/version')

    def test_default_version_service(self):
        self._default_version(file='service/version')

    def test_xml_version_admin(self):
        self._xml_version(file='admin/version')

    def test_xml_version_service(self):
        self._xml_version(file='service/version')

    def test_json_version_admin(self):
        self._json_version(file='admin/version')

    def test_json_version_service(self):
        self._json_version(file='service/version')

    def test_atom_version_admin(self):
        self._atom_version(file='admin/version')

    def test_atom_version_service(self):
        self._atom_version(file='service/version')

if __name__ == '__main__':
    unittest.main()
