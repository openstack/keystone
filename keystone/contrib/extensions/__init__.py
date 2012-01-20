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

import logging

from keystone import config
from keystone import utils

CONF = config.CONF
EXTENSION_PREFIX = 'keystone.contrib.extensions.'
DEFAULT_EXTENSIONS = ['osksadm', 'oskscatalog']
CONFIG_EXTENSION_PROPERTY = 'extensions'

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class BaseExtensionConfigurer(object):
    def configure_extensions(self, extension_type, mapper):
        extensions = CONF[CONFIG_EXTENSION_PROPERTY] or \
                DEFAULT_EXTENSIONS
        extensions = [extension.strip() for extension in extensions]
        for supported_extension in extensions:
            self.extension_handlers = []
            supported_extension = "%s%s.%s" % (
                EXTENSION_PREFIX, extension_type, supported_extension.strip())
            try:
                extension_module = utils.import_module(supported_extension)
                if hasattr(extension_module, 'ExtensionHandler'):
                    extension_class = extension_module.ExtensionHandler()
                    extension_class.map_extension_methods(mapper)
                    self.extension_handlers.append(extension_class)
            except Exception as err:
                logger.exception("Could not load extension for %s:%s %s" %
                    (extension_type, supported_extension, err))

    def get_extension_handlers(self):
        return self.extension_handlers
