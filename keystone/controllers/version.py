import os
from webob import Response

# Calculate root path (to get to static files)
possible_topdir = os.path.normpath(os.path.join(os.path.dirname(__file__),
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
    def  get_version_info(self, req, file="version"):
        resp = Response()
        resp.charset = 'UTF-8'
        if utils.is_xml_response(req):
            resp_file = os.path.join(possible_topdir,
                "keystone/content/%s.xml.tpl" % file)
            resp.content_type = "application/xml"
        elif utils.is_atom_response(req):
            resp_file = os.path.join(possible_topdir,
                "keystone/content/%s.atom.tpl" % file)
            resp.content_type = "application/atom+xml"
        else:
            resp_file = os.path.join(possible_topdir,
                "keystone/content/%s.json.tpl" % file)
            resp.content_type = "application/json"

        hostname = req.environ.get("SERVER_NAME")
        port = req.environ.get("SERVER_PORT")

        resp.unicode_body = template.template(resp_file,
            HOST=hostname,
            PORT=port,
            API_VERSION=version.API_VERSION,
            API_VERSION_STATUS=version.API_VERSION_STATUS,
            API_VERSION_DATE=version.API_VERSION_DATE)

        return resp
