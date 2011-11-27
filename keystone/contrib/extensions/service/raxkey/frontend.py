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

Soon to be deprecated middleware.
"""
import logging

EXTENSION_ALIAS = "RAX-KEY"

LOG = logging.getLogger('keystone.contrib.extensions')


class FrontEndFilter(object):
    """API Key Middleware that handles authentication with API Key"""

    def __init__(self, app, conf):
        """ Common initialization code """
        print "Starting the %s extension" % EXTENSION_ALIAS
        self.conf = conf
        self.app = app

    def __call__(self, env, start_response):
        LOG.warn('This middleware is soon to be deprecated." +\
            "Please remove related entries from conf files.')
        #Kept for backward compatibility.Does nothing as of now.
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def ext_filter(app):
        """Closure to return"""
        return FrontEndFilter(app, conf)
    return ext_filter
