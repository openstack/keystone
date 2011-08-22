from webob import Response

from keystone import utils
from keystone.common import template, wsgi


class ExtensionsController(wsgi.Controller):
    """Controller for extensions related methods"""

    def __init__(self, options):
        super(ExtensionsController, self).__init__()
        self.options = options

    @utils.wrap_error
    def get_extensions_info(self, req, path):
        resp = Response()

        if utils.is_xml_response(req):
            resp_file = "%s.xml" % path
            mime_type = "application/xml"
        else:
            resp_file = "%s.json" % path
            mime_type = "application/json"

        return template.static_file(resp, req, resp_file,
                root=utils.get_app_root(), mimetype=mime_type)
