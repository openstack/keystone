# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import webtest

import pecan.testing

from keystone.contrib.kds.common import paths
from keystone.openstack.common import jsonutils
from keystone.tests.contrib.kds import base


def urljoin(*args):
    return "/%s/" % "/".join([a.strip("/") for a in args])


def method_func(method):
    def func(self, url, **kwargs):
        kwargs['method'] = method
        return self.request(url, **kwargs)

    return func


class BaseTestCase(base.BaseTestCase):

    METHODS = {'get': webtest.TestApp.get,
               'post': webtest.TestApp.post,
               'put': webtest.TestApp.put,
               'patch': webtest.TestApp.patch,
               'delete': webtest.TestApp.delete,
               'options': webtest.TestApp.options,
               'head': webtest.TestApp.head}

    def setUp(self):
        super(BaseTestCase, self).setUp()
        root = 'keystone.contrib.kds.api.root.RootController'

        self.app_config = {
            'app': {
                'root': root,
                'modules': ['keystone.contrib.kds.api'],
                'static_root': paths.root_path('public'),
                'template_path': paths.root_path('kds', 'api', 'templates'),
            },
        }

        self.app = pecan.testing.load_test_app(self.app_config)
        self.addCleanup(pecan.set_config, {}, overwrite=True)

    def request(self, url, method, **kwargs):
        try:
            json = kwargs.pop('json')
        except KeyError:
            pass
        else:
            kwargs['content_type'] = 'application/json'
            kwargs['params'] = jsonutils.dumps(json)

        try:
            func = self.METHODS[method.lower()]
        except KeyError:
            self.fail("Unsupported HTTP Method: %s" % method)
        else:
            return func(self.app, url, **kwargs)

    get = method_func('get')
    post = method_func('post')
    put = method_func('put')
    delete = method_func('delete')
    options = method_func('options')
    head = method_func('head')
