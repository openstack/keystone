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

Deprecated middleware. We still have it here to not break compatiblity with
configuration files that add it to the pipeline.
"""
import logging

from keystone import utils

EXTENSION_ALIAS = "RAX-KEY"

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class FrontEndFilter(object):
    """API Key Middleware that handles authentication with API Key"""

    def __init__(self, app, conf):
        """ Common initialization code """
        logger.warn(_("WARNING: Starting the %s extension which "
                                 "is deprecated" %
                                 EXTENSION_ALIAS))
        self.conf = conf
        self.app = app

    def __call__(self, env, start_response):
        logger.warn("%s middleware is deprecated and will be removed in "
                 "Essex+1 (Fall fo 2012). Remove it from your "
                 "configuration files." % EXTENSION_ALIAS)
        #Kept for backward compatibility with existing configuration files.
        #Does nothing now.
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def ext_filter(app):
        """Closure to return"""
        return FrontEndFilter(app, conf)
    return ext_filter
