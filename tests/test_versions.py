# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from keystone import test

from keystone import config
from keystone import controllers
from keystone.openstack.common import jsonutils


CONF = config.CONF

v2_MEDIA_TYPES = [
    {
        "base": "application/json",
        "type": "application/"
                "vnd.openstack.identity-v2.0+json"
    }, {
        "base": "application/xml",
        "type": "application/"
                "vnd.openstack.identity-v2.0+xml"
    }
]

v2_HTML_DESCRIPTION = {
    "rel": "describedby",
    "type": "text/html",
    "href": "http://docs.openstack.org/api/"
            "openstack-identity-service/2.0/"
            "content/"
}

v2_PDF_DESCRIPTION = {
    "rel": "describedby",
    "type": "application/pdf",
    "href": "http://docs.openstack.org/api/"
            "openstack-identity-service/2.0/"
            "identity-dev-guide-2.0.pdf"
}

v2_EXPECTED_RESPONSE = {
    "id": "v2.0",
    "status": "stable",
    "updated": "2013-03-06T00:00:00Z",
    "links": [
        {
            "rel": "self",
            "href": "",     # Will get filled in after initialization
        },
        v2_HTML_DESCRIPTION,
        v2_PDF_DESCRIPTION
    ],
    "media-types": v2_MEDIA_TYPES
}

v2_VERSION_RESPONSE = {
    "version": v2_EXPECTED_RESPONSE
}

v3_MEDIA_TYPES = [
    {
        "base": "application/json",
        "type": "application/"
                "vnd.openstack.identity-v3+json"
    }, {
        "base": "application/xml",
        "type": "application/"
                "vnd.openstack.identity-v3+xml"
    }
]

v3_EXPECTED_RESPONSE = {
    "id": "v3.0",
    "status": "stable",
    "updated": "2013-03-06T00:00:00Z",
    "links": [
        {
            "rel": "self",
            "href": "",     # Will get filled in after initialization
        }
    ],
    "media-types": v3_MEDIA_TYPES
}

v3_VERSION_RESPONSE = {
    "version": v3_EXPECTED_RESPONSE
}

VERSIONS_RESPONSE = {
    "versions": {
        "values": [
            v3_EXPECTED_RESPONSE,
            v2_EXPECTED_RESPONSE
        ]
    }
}


class VersionTestCase(test.TestCase):
    def setUp(self):
        super(VersionTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.public_server = self.serveapp('keystone', name='main')
        self.admin_server = self.serveapp('keystone', name='admin')

    def _paste_in_port(self, response, port):
        for link in response['links']:
            if link['rel'] == 'self':
                link['href'] = port

    def test_public_versions(self):
        client = self.client(self.public_app)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'] == 'v3.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' % CONF.public_port)
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' % CONF.public_port)
        self.assertEqual(data, expected)

    def test_admin_versions(self):
        client = self.client(self.admin_app)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'] == 'v3.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' % CONF.admin_port)
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' % CONF.admin_port)
        self.assertEqual(data, expected)

    def test_public_version_v2(self):
        client = self.client(self.public_app)
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' % CONF.public_port)
        self.assertEqual(data, expected)

    def test_admin_version_v2(self):
        client = self.client(self.admin_app)
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' % CONF.admin_port)
        self.assertEqual(data, expected)

    def test_public_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' % CONF.public_port)
        self.assertEqual(data, expected)

    def test_admin_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' % CONF.admin_port)
        self.assertEqual(data, expected)

    def test_v2_disabled(self):
        self.stubs.Set(controllers, '_VERSIONS', ['v3'])
        client = self.client(self.public_app)
        # request to /v2.0 should fail
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 404)

        # request to /v3 should pass
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' % CONF.public_port)
        self.assertEqual(data, expected)

        # only v3 information should be displayed by requests to /
        v3_only_response = {
            "versions": {
                "values": [
                    v3_EXPECTED_RESPONSE
                ]
            }
        }
        self._paste_in_port(v3_only_response['versions']['values'][0],
                            'http://localhost:%s/v3/' % CONF.public_port)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        self.assertEqual(data, v3_only_response)

    def test_v3_disabled(self):
        self.stubs.Set(controllers, '_VERSIONS', ['v2.0'])
        client = self.client(self.public_app)
        # request to /v3 should fail
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 404)

        # request to /v2.0 should pass
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' % CONF.public_port)
        self.assertEqual(data, expected)

        # only v2 information should be displayed by requests to /
        v2_only_response = {
            "versions": {
                "values": [
                    v2_EXPECTED_RESPONSE
                ]
            }
        }
        self._paste_in_port(v2_only_response['versions']['values'][0],
                            'http://localhost:%s/v2.0/' % CONF.public_port)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        self.assertEqual(data, v2_only_response)


class XmlVersionTestCase(test.TestCase):

    REQUEST_HEADERS = {'Accept': 'application/xml'}

    DOC_INTRO = '<?xml version="1.0" encoding="UTF-8"?>'
    XML_NAMESPACE_ATTR = 'xmlns="http://docs.openstack.org/identity/api/v2.0"'

    v2_VERSION_DATA = """
<version %(v2_namespace)s status="stable" updated="2013-03-06T00:00:00Z"
         id="v2.0">
  <media-types>
    <media-type base="application/json" type="application/\
vnd.openstack.identity-v2.0+json"/>
    <media-type base="application/xml" type="application/\
vnd.openstack.identity-v2.0+xml"/>
  </media-types>
  <links>
    <link href="http://localhost:%%(port)s/v2.0/" rel="self"/>
    <link href="http://docs.openstack.org/api/openstack-identity-service/\
2.0/content/" type="text/html" rel="describedby"/>
    <link href="http://docs.openstack.org/api/openstack-identity-service/\
2.0/identity-dev-guide-2.0.pdf" type="application/pdf" rel="describedby"/>
  </links>
  <link href="http://localhost:%%(port)s/v2.0/" rel="self"/>
  <link href="http://docs.openstack.org/api/openstack-identity-service/\
2.0/content/" type="text/html" rel="describedby"/>
  <link href="http://docs.openstack.org/api/openstack-identity-service/\
2.0/identity-dev-guide-2.0.pdf" type="application/pdf" rel="describedby"/>
</version>
"""

    v2_VERSION_RESPONSE = ((DOC_INTRO + v2_VERSION_DATA) %
                           dict(v2_namespace=XML_NAMESPACE_ATTR))

    v3_VERSION_DATA = """
<version %(v3_namespace)s status="stable" updated="2013-03-06T00:00:00Z"
         id="v3.0">
  <media-types>
    <media-type base="application/json" type="application/\
vnd.openstack.identity-v3+json"/>
    <media-type base="application/xml" type="application/\
vnd.openstack.identity-v3+xml"/>
  </media-types>
  <links>
    <link href="http://localhost:%%(port)s/v3/" rel="self"/>
  </links>
</version>
"""

    v3_VERSION_RESPONSE = ((DOC_INTRO + v3_VERSION_DATA) %
                           dict(v3_namespace=XML_NAMESPACE_ATTR))

    VERSIONS_RESPONSE = ((DOC_INTRO + """
<versions %(namespace)s>
""" +
                          v3_VERSION_DATA +
                          v2_VERSION_DATA + """
</versions>
""") % dict(namespace=XML_NAMESPACE_ATTR, v3_namespace='', v2_namespace=''))

    def setUp(self):
        super(XmlVersionTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.public_server = self.serveapp('keystone', name='main')
        self.admin_server = self.serveapp('keystone', name='admin')

    def test_public_versions(self):
        client = self.client(self.public_app)
        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        expected = self.VERSIONS_RESPONSE % dict(port=CONF.public_port)
        self.assertEqualXML(data, expected)

    def test_admin_versions(self):
        client = self.client(self.admin_app)
        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        expected = self.VERSIONS_RESPONSE % dict(port=CONF.admin_port)
        self.assertEqualXML(data, expected)

    def test_public_version_v2(self):
        client = self.client(self.public_app)
        resp = client.get('/v2.0/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v2_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertEqualXML(data, expected)

    def test_admin_version_v2(self):
        client = self.client(self.admin_app)
        resp = client.get('/v2.0/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v2_VERSION_RESPONSE % dict(port=CONF.admin_port)
        self.assertEqualXML(data, expected)

    def test_public_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v3_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertEqualXML(data, expected)

    def test_admin_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v3_VERSION_RESPONSE % dict(port=CONF.admin_port)
        self.assertEqualXML(data, expected)

    def test_v2_disabled(self):
        self.stubs.Set(controllers, '_VERSIONS', ['v3'])
        client = self.client(self.public_app)

        # request to /v3 should pass
        resp = client.get('/v3/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v3_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertEqualXML(data, expected)

        # only v3 information should be displayed by requests to /
        v3_only_response = ((self.DOC_INTRO + '<versions %(namespace)s>' +
                             self.v3_VERSION_DATA + '</versions>') %
                            dict(namespace=self.XML_NAMESPACE_ATTR,
                                 v3_namespace='') %
                            dict(port=CONF.public_port))

        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        self.assertEqualXML(data, v3_only_response)

    def test_v3_disabled(self):
        self.stubs.Set(controllers, '_VERSIONS', ['v2.0'])
        client = self.client(self.public_app)

        # request to /v2.0 should pass
        resp = client.get('/v2.0/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v2_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertEqualXML(data, expected)

        # only v2 information should be displayed by requests to /
        v2_only_response = ((self.DOC_INTRO + '<versions %(namespace)s>' +
                             self.v2_VERSION_DATA + '</versions>') %
                            dict(namespace=self.XML_NAMESPACE_ATTR,
                                 v2_namespace='') %
                            dict(port=CONF.public_port))

        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        self.assertEqualXML(data, v2_only_response)
