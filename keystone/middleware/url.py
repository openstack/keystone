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
DEPRECATED - moved to keystone.frontends.normalizer

This file only exists to maintain compatibility with configuration files
that load keystone.middleware.url
"""

import logging

from keystone.frontends.normalizer import filter_factory\
        as new_filter_factory

logger = logging.getLogger(__name__)  # pylint: disable=C0103


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy.

    In this case, we return the class that has been moved"""
    logger.warning("'%s' has been moved to 'keystone.frontends.normalizer'. "
                   "Update your configuration file to reflect the change" %
                   __name__)
    return new_filter_factory(global_conf, **local_conf)
