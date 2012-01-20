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
Version Controller

"""
import logging
import os
from webob import Response

from keystone import utils
from keystone import version
from keystone.common import template
from keystone.controllers.base_controller import BaseController

# Calculate root path (to get to static files)
POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                                os.pardir,
                                                os.pardir))

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class VersionController(BaseController):
    """Controller for version related methods"""
    @utils.wrap_error
    def get_version_info(self, req, file="version"):
        resp = Response()
        resp.charset = 'UTF-8'
        if utils.is_xml_response(req):
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                "keystone/content/%s.xml.tpl" % file)
            resp.content_type = "application/xml"
        elif utils.is_atom_response(req):
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                "keystone/content/%s.atom.tpl" % file)
            resp.content_type = "application/atom+xml"
        else:
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                "keystone/content/%s.json.tpl" % file)
            resp.content_type = "application/json"

        hostname = req.environ.get("SERVER_NAME")
        port = req.environ.get("SERVER_PORT")
        if 'HTTPS' in req.environ:
            protocol = 'https'
        else:
            protocol = 'http'

        resp.unicode_body = template.template(resp_file,
            PROTOCOL=protocol,
            HOST=hostname,
            PORT=port,
            API_VERSION=version.API_VERSION,
            API_VERSION_STATUS=version.API_VERSION_STATUS,
            API_VERSION_DATE=version.API_VERSION_DATE)

        return resp

    @utils.wrap_error
    def get_multiple_choice(self, req, file="multiple_choice", path=None):
        """ Returns a multiple-choices response based on API spec

        Response will include in it only one choice, which is for the
        current API version. The response is a 300 Multiple Choice
        response with either an XML or JSON body.

        """
        if path is None:
            path = ''
        logger.debug("300 Multiple Choices response: %s" % path)
        resp = Response(status="300 Multiple Choices")
        resp.charset = 'UTF-8'
        if utils.is_xml_response(req):
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                "keystone/content/%s.xml.tpl" % file)
            resp.content_type = "application/xml"
        else:
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                "keystone/content/%s.json.tpl" % file)
            resp.content_type = "application/json"

        hostname = req.environ.get("SERVER_NAME")
        port = req.environ.get("SERVER_PORT")
        if 'HTTPS' in req.environ:
            protocol = 'https'
        else:
            protocol = 'http'

        resp.unicode_body = template.template(resp_file,
            PROTOCOL=protocol,
            HOST=hostname,
            PORT=port,
            API_VERSION=version.API_VERSION,
            API_VERSION_STATUS=version.API_VERSION_STATUS,
            API_VERSION_DATE=version.API_VERSION_DATE,
            RESOURCE_PATH=path
            )

        return resp
