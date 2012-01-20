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
Static Files Controller

Serves static files like PDF, WADL, etc...
"""
import logging
import os
from webob import Response

from keystone import utils
from keystone.common import template
from keystone.controllers.base_controller import BaseController

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class StaticFilesController(BaseController):
    """Controller for contract documents"""
    @staticmethod
    @utils.wrap_error
    def get_pdf_contract(req, pdf, root="content/"):
        resp = Response()
        filepath = root + pdf
        return template.static_file(resp, req, filepath,
            root=utils.get_app_root(), mimetype="application/pdf")

    @staticmethod
    @utils.wrap_error
    def get_wadl_contract(req, wadl, root):
        resp = Response()
        return template.static_file(resp, req, root + wadl,
            root=utils.get_app_root(), mimetype="application/vnd.sun.wadl+xml")

    @staticmethod
    @utils.wrap_error
    def get_xsd_contract(req, xsd, root="content/"):
        resp = Response()
        return template.static_file(resp, req, root + "xsd/" + xsd,
            root=utils.get_app_root(), mimetype="application/xml")

    @staticmethod
    @utils.wrap_error
    def get_xsd_atom_contract(req, xsd, root="content/"):
        resp = Response()
        return template.static_file(resp, req, root + "xsd/atom/" + xsd,
            root=utils.get_app_root(), mimetype="application/xml")

    @staticmethod
    @utils.wrap_error
    def get_static_file(req, path, file, mimetype=None, root="content/"):
        resp = Response()

        if mimetype is None:
            if utils.is_xml_response(req):
                mimetype = "application/xml"
            elif utils.is_json_response(req):
                mimetype = "application/json"
            else:
                logger.debug("Unhandled mime type: %s" % req.content_type)

        basename, extension = os.path.splitext(file)
        resp_file = "%s%s%s" % (root, path, file)
        if extension is None or extension == '':
            if mimetype == "application/xml":
                resp_file = "%s.xml" % resp_file
            elif mimetype == "application/json":
                resp_file = "%s.json" % resp_file

        logger.debug("Returning contents from file '%s'" % resp_file)
        return template.static_file(resp, req, resp_file,
            root=utils.get_app_root(), mimetype=mimetype)
