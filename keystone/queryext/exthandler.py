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


# Does this need to be configurable?
DEFAULT_EXTS = {'xml': 'application/xml', 'json': 'application/json'}


def scrub(uri, ext):
    urisegs = uri.split('?')
    first = urisegs[0][0: -(len(ext) + 1)]
    if len(urisegs) > 1:
        return '?'.join((first, urisegs[1], ))
    else:
        return first


class UrlExtensionFilter(object):

    def __init__(self, app, conf):
        # app is the next app in WSGI chain - eventually the OpenStack service
        self.app = app
        self.conf = conf

        print 'Starting extension handler middleware'

    def __call__(self, env, start_response):
        uri = env['PATH_INFO']
        querysegs = uri.split('?')
        ressegs = querysegs[0].split('.')
        if len(ressegs) > 1:  # (Maybe) has an extension
            ext = ressegs[-1]
            if ext in DEFAULT_EXTS:
                env['HTTP_ACCEPT'] = DEFAULT_EXTS[ext]
                scrubbed = querysegs[0][0: -(len(ext) + 1)]  # Remove extension
                if len(querysegs) > 1:  # Has query string
                    env['PATH_INFO'] = '?'.join((scrubbed, querysegs[1], ))
                else:
                    env['PATH_INFO'] = scrubbed

        return self.app(env, start_response)
