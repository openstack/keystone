# Copyright (c) 2011 OpenStack, LLC.
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
Base Class Controller

"""
import functools
import logging

from keystone import utils
from keystone.common import wsgi

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class BaseController(wsgi.Controller):
    """Base Controller class for Keystone"""

    @staticmethod
    def get_url(req):
        return '%s://%s:%s%s' % (
            req.environ['wsgi.url_scheme'],
            req.environ.get("SERVER_NAME"),
            req.environ.get("SERVER_PORT"),
            req.environ['PATH_INFO'])

    def get_marker_limit_and_url(self, req):
        marker = req.GET["marker"] if "marker" in req.GET else None
        limit = req.GET["limit"] if "limit" in req.GET else 10
        url = self.get_url(req)
        return (marker, limit, url)
