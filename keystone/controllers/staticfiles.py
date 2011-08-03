from webob import Response

from keystone import utils
from keystone.common import template, wsgi


class StaticFilesController(wsgi.Controller):
    """Controller for contract documents"""

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def get_pdf_contract(self, req):
        resp = Response()
        return template.static_file(resp, req, "content/identitydevguide.pdf",
            root=utils.get_app_root(), mimetype="application/pdf")

    @utils.wrap_error
    def get_wadl_contract(self, req):
        resp = Response()
        return template.static_file(resp, req, "content/identity.wadl",
            root=utils.get_app_root(), mimetype="application/vnd.sun.wadl+xml")

    @utils.wrap_error
    def get_xsd_contract(self, req, xsd):
        resp = Response()
        return template.static_file(resp, req, "/xsd/" + xsd,
            root=utils.get_app_root(), mimetype="application/xml")

    @utils.wrap_error
    def get_xsd_atom_contract(self, req, xsd):
        resp = Response()
        return template.static_file(resp, req, "/xsd/atom/" + xsd,
            root=utils.get_app_root(), mimetype="application/xml")
