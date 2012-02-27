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

import json

from keystone import test
from keystone import config


CONF = config.CONF


class VersionTestCase(test.TestCase):
    def setUp(self):
        super(VersionTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.public_server = self.serveapp('keystone', name='main')
        self.admin_server = self.serveapp('keystone', name='admin')

    def test_public_versions(self):
        client = self.client(self.public_app)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = json.loads(resp.body)
        expected = {
            "versions": {
                "values": [
                    {
                        "id": "v2.0",
                        "status": "beta",
                        "updated": "2011-11-19T00:00:00Z",
                        "links": [
                            {
                                "rel": "self",
                                "href": "http://localhost:%s/v2.0/" %
                                        CONF.public_port,
                            }, {
                                "rel": "describedby",
                                "type": "text/html",
                                "href": "http://docs.openstack.org/api/"
                                        "openstack-identity-service/2.0/"
                                        "content/"
                            }, {
                                "rel": "describedby",
                                "type": "application/pdf",
                                "href": "http://docs.openstack.org/api/"
                                        "openstack-identity-service/2.0/"
                                        "identity-dev-guide-2.0.pdf"
                            }
                        ],
                        "media-types": [
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
                    }
                ]
            }
        }
        self.assertEqual(data, expected)

    def test_admin_versions(self):
        client = self.client(self.admin_app)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = json.loads(resp.body)
        expected = {
            "versions": {
                "values": [
                    {
                        "id": "v2.0",
                        "status": "beta",
                        "updated": "2011-11-19T00:00:00Z",
                        "links": [
                            {
                                "rel": "self",
                                "href": "http://localhost:%s/v2.0/" %
                                        CONF.admin_port,
                            }, {
                                "rel": "describedby",
                                "type": "text/html",
                                "href": "http://docs.openstack.org/api/"
                                        "openstack-identity-service/2.0/"
                                        "content/"
                            }, {
                                "rel": "describedby",
                                "type": "application/pdf",
                                "href": "http://docs.openstack.org/api/"
                                        "openstack-identity-service/2.0/"
                                        "identity-dev-guide-2.0.pdf"
                            }
                        ],
                        "media-types": [
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
                    }
                ]
            }
        }
        self.assertEqual(data, expected)
