# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
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

from keystone.contrib.extensions.admin.extension import BaseExtensionHandler
from keystone.contrib.extensions.admin.osksvalidate import handler


class ExtensionHandler(BaseExtensionHandler):
    def map_extension_methods(self, mapper):
        extension_controller = handler.SecureValidationController()

        # Token Operations
        mapper.connect("/OS-KSVALIDATE/token/validate",
                       controller=extension_controller,
                       action="handle_validate_request",
                       conditions=dict(method=["GET"]))

        mapper.connect("/OS-KSVALIDATE/token/endpoints",
                       controller=extension_controller,
                       action="handle_endpoints_request",
                       conditions=dict(method=["GET"]))
        # TODO(zns): make this handle all routes by using the mapper
