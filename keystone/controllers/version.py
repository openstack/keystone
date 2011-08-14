import os
import sys
from webob import Response

# If ../../keystone/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
possible_topdir = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))

from keystone import utils
from keystone.common import template, wsgi
import keystone.config as config


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
            VERSION_STATUS=config.VERSION_STATUS,
            VERSION_DATE=config.VERSION_DATE)

        return resp
