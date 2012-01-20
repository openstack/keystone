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
Extensions Controller

"""
import logging

from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.logic.extension_reader import ExtensionsReader
from keystone.contrib.extensions.admin import EXTENSION_ADMIN_PREFIX
from keystone.contrib.extensions.service import EXTENSION_SERVICE_PREFIX

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class ExtensionsController(BaseController):
    """Controller for extensions related methods"""

    def __init__(self, is_service_operation=None):
        super(ExtensionsController, self).__init__()
        if is_service_operation:
            self.extension_prefix = EXTENSION_SERVICE_PREFIX
        else:
            self.extension_prefix = EXTENSION_ADMIN_PREFIX
        self.extension_reader = ExtensionsReader(self.extension_prefix)

    @utils.wrap_error
    def get_extensions_info(self, req):
        return utils.send_result(200, req,
            self.extension_reader.get_extensions())
