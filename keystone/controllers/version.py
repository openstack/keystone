import os
from webob import Response

# Calculate root path (to get to static files)
POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                                os.pardir,
                                                os.pardir))

from keystone import version
from keystone import utils
from keystone.common import template, wsgi


class VersionController(wsgi.Controller):
    """Controller for version related methods"""

    def __init__(self, options):
        self.options = options

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
