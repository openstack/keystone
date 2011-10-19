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
from keystone.controllers.endpointtemplates import EndpointTemplatesController


class ExtensionHandler(BaseExtensionHandler):
    def map_extension_methods(self, mapper, options):
        #EndpointTemplates Calls
        endpoint_templates_controller = EndpointTemplatesController(options)
        mapper.connect("/OS-KSCATALOG/endpointTemplates",
            controller=endpoint_templates_controller,
                action="get_endpoint_templates",
                    conditions=dict(method=["GET"]))
        mapper.connect("/OS-KSCATALOG/endpointTemplates",
            controller=endpoint_templates_controller,
                action="add_endpoint_template",
                    conditions=dict(method=["POST"]))
        mapper.connect(
            "/OS-KSCATALOG/endpointTemplates/{endpoint_template_id}",
             controller=endpoint_templates_controller,
             action="get_endpoint_template",
                        conditions=dict(method=["GET"]))
        mapper.connect(
            "/OS-KSCATALOG/endpointTemplates/{endpoint_template_id}",
             controller=endpoint_templates_controller,
             action="modify_endpoint_template",
                        conditions=dict(method=["PUT"]))
        mapper.connect(
            "/OS-KSCATALOG/endpointTemplates/{endpoint_template_id}",
            controller=endpoint_templates_controller,
            action="delete_endpoint_template",
                        conditions=dict(method=["DELETE"]))
        #Endpoint Calls
        mapper.connect("/tenants/{tenant_id}/OS-KSCATALOG/endpoints",
                       controller=endpoint_templates_controller,
                    action="get_endpoints_for_tenant",
                    conditions=dict(method=["GET"]))
        mapper.connect("/tenants/{tenant_id}/OS-KSCATALOG/endpoints",
                       controller=endpoint_templates_controller,
                     action="add_endpoint_to_tenant",
                     conditions=dict(method=["POST"]))
        mapper.connect(
                "/tenants/{tenant_id}/OS-KSCATALOG/endpoints/{endpoint_id}",
                controller=endpoint_templates_controller,
                action="remove_endpoint_from_tenant",
                conditions=dict(method=["DELETE"]))
