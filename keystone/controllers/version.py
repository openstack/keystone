import os
from webob import Response

# If ../../keystone/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
possible_topdir = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                                os.pardir,
                                                os.pardir))

import keystone
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
        else:
            resp_file = os.path.join(possible_topdir,
                "keystone/content/%s.json.tpl" % file)
            resp.content_type = "application/json"

        hostname = req.environ.get("SERVER_NAME")
        port = req.environ.get("SERVER_PORT")

        resp.unicode_body = template.template(resp_file,
            HOST=hostname,
            PORT=port,
            API_VERSION=keystone.API_VERSION,
            API_VERSION_STATUS=keystone.API_VERSION_STATUS,
            API_VERSION_DATE=keystone.API_VERSION_DATE)

        return resp
