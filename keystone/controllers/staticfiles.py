# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from webob import Response

from keystone import utils
from keystone.common import template, wsgi


class StaticFilesController(wsgi.Controller):
    """Controller for contract documents"""

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def get_pdf_contract(self, req, pdf):
        resp = Response()
        return template.static_file(resp, req, "content/" + pdf,
            root=utils.get_app_root(), mimetype="application/pdf")

    @utils.wrap_error
    def get_wadl_contract(self, req, wadl):
        resp = Response()
        return template.static_file(resp, req, "content/" + wadl,
            root=utils.get_app_root(), mimetype="application/vnd.sun.wadl+xml")

    @utils.wrap_error
    def get_xsd_contract(self, req, xsd):
        resp = Response()
        return template.static_file(resp, req, "content/xsd/" + xsd,
            root=utils.get_app_root(), mimetype="application/xml")

    @utils.wrap_error
    def get_xsd_atom_contract(self, req, xsd):
        resp = Response()
        return template.static_file(resp, req, "content/xsd/atom/" + xsd,
            root=utils.get_app_root(), mimetype="application/xml")
