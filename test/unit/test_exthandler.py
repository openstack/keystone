import os
import sys
# Need to access identity module
sys.path.append(os.path.abspath(os.path.join(
    os.getcwd(), '..', '..', 'keystone')))
from queryext.exthandler import UrlExtensionFilter
import unittest


class MockWsgiApp(object):

    def __init__(self):
        pass

    def __call__(self, env, start_response):
        pass


def _start_response():
    pass


class UrlExtensionFilterTest(unittest.TestCase):

    def setUp(self):
        self.filter = UrlExtensionFilter(MockWsgiApp(), {})

    def test_xml_extension(self):
        env = {'PATH_INFO': '/v1.0/someresource.xml'}
        self.filter(env, _start_response)
        self.assertEqual('/v1.0/someresource', env['PATH_INFO'])
        self.assertEqual('application/xml', env['HTTP_ACCEPT'])

    def test_json_extension(self):
        env = {'PATH_INFO': '/v1.0/someresource.json'}
        self.filter(env, _start_response)
        self.assertEqual('/v1.0/someresource', env['PATH_INFO'])
        self.assertEqual('application/json', env['HTTP_ACCEPT'])

    def test_extension_overrides_header(self):
        env = {'PATH_INFO': '/v1.0/someresource.json',
                'HTTP_ACCEPT': 'application/xml'}
        self.filter(env, _start_response)
        self.assertEqual('/v1.0/someresource', env['PATH_INFO'])
        self.assertEqual('application/json', env['HTTP_ACCEPT'])


if __name__ == '__main__':
    unittest.main()
