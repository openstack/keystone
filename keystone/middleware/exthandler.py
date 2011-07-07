#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2010 OpenStack, LLC.
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


"""
Auth Middleware that accepts URL query extension.

This module can be installed as a filter in front of your service to
detect extension in the resource URI (e.g., foo/resource.xml) to
specify HTTP response body type. If an extension is specified, it
overwrites the Accept header in the request, if present.

"""

CONTENT_TYPES = {'json': 'application/json', 'xml': 'application/xml'}
DEFAULT_CONTENT_TYPE = CONTENT_TYPES['json']

class UrlExtensionFilter(object):

    def __init__(self, app, conf):
        # app is the next app in WSGI chain - eventually the OpenStack service
        self.app = app
        self.conf = conf

    def __call__(self, env, start_response):
        uri = env['PATH_INFO']
        (path, ext) = uri.rsplit('.', 1)
        if ext in CONTENT_TYPES:
            env['HTTP_ACCEPT'] = CONTENT_TYPES[ext]
            env['PATH_INFO'] = path
        elif 'HTTP_ACCEPT' not in env:
            env['HTTP_ACCEPT'] = DEFAULT_CONTENT_TYPE
        
        return self.app(env, start_response)

def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def ext_filter(app):
        return UrlExtensionFilter(app, conf)
    return ext_filter
