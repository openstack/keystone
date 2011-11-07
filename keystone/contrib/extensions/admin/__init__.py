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
from keystone.contrib.extensions import BaseExtensionConfigurer
DEFAULT_EXTENSIONS = 'osksadm,oskscatalog'
CONFIGURER = None
CONFIG_EXTENSION_PROPERTY = 'extensions'
EXTENSION_ADMIN_PREFIX = 'admin'


class AdminExtensionConfigurer(BaseExtensionConfigurer):
    def configure(self, mapper, options):
        self.configure_extensions(CONFIG_EXTENSION_PROPERTY,
                EXTENSION_ADMIN_PREFIX,
                DEFAULT_EXTENSIONS, mapper, options)


def get_extension_configurer():
    global CONFIGURER
    if not CONFIGURER:
        CONFIGURER = AdminExtensionConfigurer()
    return CONFIGURER
