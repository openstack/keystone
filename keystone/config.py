# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""Wrapper for keystone.common.config that configures itself on import."""

import os

from keystone.common import config
from keystone import exception


config.configure()
CONF = config.CONF

setup_logging = config.setup_logging
setup_authentication = config.setup_authentication
configure = config.configure


def find_paste_config():
    """Find Keystone's paste.deploy configuration file.

    Keystone's paste.deploy configuration file is specified in the
    ``[paste_deploy]`` section of the main Keystone configuration file,
    ``keystone.conf``.

    For example::

        [paste_deploy]
        config_file = keystone-paste.ini

    :returns: The selected configuration filename
    :raises: exception.ConfigFileNotFound

    """
    if CONF.paste_deploy.config_file:
        paste_config = CONF.paste_deploy.config_file
        paste_config_value = paste_config
        if not os.path.isabs(paste_config):
            paste_config = CONF.find_file(paste_config)
    elif CONF.config_file:
        paste_config = CONF.config_file[0]
        paste_config_value = paste_config
    else:
        # this provides backwards compatibility for keystone.conf files that
        # still have the entire paste configuration included, rather than just
        # a [paste_deploy] configuration section referring to an external file
        paste_config = CONF.find_file('keystone.conf')
        paste_config_value = 'keystone.conf'
    if not paste_config or not os.path.exists(paste_config):
        raise exception.ConfigFileNotFound(config_file=paste_config_value)
    return paste_config
