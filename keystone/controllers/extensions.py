from keystone import utils
from keystone.common import wsgi
from keystone.logic.extension_reader import ExtensionsReader
from keystone.contrib.extensions.admin import EXTENSION_ADMIN_PREFIX
from keystone.contrib.extensions.service import EXTENSION_SERVICE_PREFIX


class ExtensionsController(wsgi.Controller):
    """Controller for extensions related methods"""

    def __init__(self, options, is_service_operation=None):
        super(ExtensionsController, self).__init__()
        self.options = options
        if is_service_operation:
            self.extension_prefix = EXTENSION_SERVICE_PREFIX
        else:
            self.extension_prefix = EXTENSION_ADMIN_PREFIX
        self.extension_reader = ExtensionsReader(options,
            self.extension_prefix)

    @utils.wrap_error
    def get_extensions_info(self, req):
                return utils.send_result(200, req,
                    self.extension_reader.get_extensions())
