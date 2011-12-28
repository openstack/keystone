# vim: tabstop=4 shiftwidth=4 softtabstop=4
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


import unittest2 as unittest
from keystone.frontends.normalizer import NormalizingFilter


class MockWsgiApp(object):

    def __init__(self):
        pass

    def __call__(self, env, start_response):
        pass


def _start_response():
    pass


class NormalizingFilterTest(unittest.TestCase):

    def setUp(self):
        self.filter = NormalizingFilter(MockWsgiApp(), {})

    def test_trailing_slash(self):
        env = {'PATH_INFO': '/v2.0/'}
        self.filter(env, _start_response)
        self.assertEqual('/', env['PATH_INFO'])

    def test_remove_trailing_slash_from_empty_path(self):
        """Empty paths should still equate to a slash"""
        env = {'PATH_INFO': '/'}
        self.filter(env, _start_response)
        self.assertEqual('/', env['PATH_INFO'])

    def test_no_extension(self):
        env = {'PATH_INFO': '/v2.0/someresource'}
        self.filter(env, _start_response)
        self.assertEqual('/someresource', env['PATH_INFO'])
        self.assertEqual('application/json', env['HTTP_ACCEPT'])

    def test_xml_extension(self):
        env = {'PATH_INFO': '/v2.0/someresource.xml'}
        self.filter(env, _start_response)
        self.assertEqual('/someresource', env['PATH_INFO'])
        self.assertEqual('application/xml', env['HTTP_ACCEPT'])

    def test_atom_extension(self):
        env = {'PATH_INFO': '/v2.0/someresource.atom'}
        self.filter(env, _start_response)
        self.assertEqual('/someresource', env['PATH_INFO'])
        self.assertEqual('application/atom+xml', env['HTTP_ACCEPT'])

    def test_json_extension(self):
        env = {'PATH_INFO': '/v2.0/someresource.json'}
        self.filter(env, _start_response)
        self.assertEqual('/someresource', env['PATH_INFO'])
        self.assertEqual('application/json', env['HTTP_ACCEPT'])

    def test_version_header(self):
        env = {'PATH_INFO': '/someresource',
               'HTTP_ACCEPT':
                    'application/vnd.openstack.identity+xml;version=2.0'}
        self.filter(env, _start_response)
        self.assertEqual('/someresource', env['PATH_INFO'])
        self.assertEqual('application/xml', env['HTTP_ACCEPT'])
        self.assertEqual('2.0', env['KEYSTONE_API_VERSION'])

    def test_extension_overrides_header(self):
        env = {
            'PATH_INFO': '/v2.0/someresource.json',
            'HTTP_ACCEPT': 'application/xml'}
        self.filter(env, _start_response)
        self.assertEqual('/someresource', env['PATH_INFO'])
        self.assertEqual('application/json', env['HTTP_ACCEPT'])


if __name__ == '__main__':
    unittest.main()
