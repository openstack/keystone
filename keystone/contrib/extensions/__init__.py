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
# limitations under the License

import ast
import logging
from keystone import utils
EXTENSION_PREFIX = 'keystone.contrib.extensions.'


class BaseExtensionConfigurer(object):
    def configure_extensions(self, extension_property, extension_type,
        extension_defaults, mapper, options):
        supported_extensions = options.get(
            extension_property, extension_defaults)
        for supported_extension in supported_extensions.split(','):
            self.extension_handlers = []
            supported_extension = EXTENSION_PREFIX\
            + extension_type + '.' + supported_extension.strip()\
            + '.ExtensionHandler'
            try:
                extenion_handler = utils.import_module(supported_extension)()
                extenion_handler.map_extension_methods(mapper, options)
                self.extension_handlers.append(extenion_handler)
            except Exception as err:
                logging.exception("Could not load extension for " +\
                    extension_type + ':' + supported_extension + str(err))

    def get_extension_handlers(self):
        return self.extension_handlers
