#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

"""
RACKSPACE API KEY EXTENSION

This WSGI component
- detects calls with extensions in them.
- processes the necessary components
"""

import json
import os
import logging
from lxml import etree
from webob.exc import Request, Response

from keystone import utils

EXTENSION_ALIAS = "OS-EC2"

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class FrontEndFilter(object):
    """API Key Middleware that handles authentication with API Key"""

    def __init__(self, app, conf):
        """ Common initialization code """
        logger.info(_("Starting the %s extension" %
                                 EXTENSION_ALIAS))
        self.conf = conf
        self.app = app

    def __call__(self, env, start_response):
        """ Handle incoming request. Transform. And send downstream. """
        request = Request(env)
        if request.path == "/extensions":
            if env['KEYSTONE_API_VERSION'] == '2.0':
                request = Request(env)
                response = request.get_response(self.app)
                if response.status_int == 200:
                    if response.content_type == 'application/json':
                        #load json for this extension from file
                        thisextension = open(os.path.join(
                                                    os.path.dirname(__file__),
                                                   "extension.json")).read()
                        thisextensionjson = json.loads(thisextension)

                        #load json in response
                        body = json.loads(response.body)
                        extensionsarray = body["extensions"]["values"]

                        #add this extension and return the response
                        extensionsarray.append(thisextensionjson)
                        newresp = Response(
                            content_type='application/json',
                            body=json.dumps(body))
                        return newresp(env, start_response)
                    elif response.content_type == 'application/xml':
                        #load xml for this extension from file
                        thisextensionxml = etree.parse(os.path.join(
                                                    os.path.dirname(__file__),
                                                   "extension.xml")).getroot()
                        #load xml being returned in response
                        body = etree.fromstring(response.body)

                        #add this extension and return the response
                        body.append(thisextensionxml)
                        newresp = Response(
                            content_type='application/xml',
                            body=etree.tostring(body))
                        return newresp(env, start_response)

                # return the response
                return response(env, start_response)

        #default action, bypass
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def ext_filter(app):
        """Closure to return"""
        return FrontEndFilter(app, conf)
    return ext_filter
