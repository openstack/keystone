# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

import oslo_i18n
from oslo_log import log

# NOTE(dstanek): i18n.enable_lazy() must be called before
# keystone.i18n._() is called to ensure it has the desired lazy lookup
# behavior. This includes cases, like keystone.exceptions, where
# keystone.i18n._() is called at import time.
oslo_i18n.enable_lazy()

from keystone.common import profiler
import keystone.conf
from keystone import exception
from keystone.server import common
from keystone.version import service as keystone_service


CONF = keystone.conf.CONF


def initialize_application(name,
                           post_log_configured_function=lambda: None,
                           config_files=None):
    possible_topdir = os.path.normpath(os.path.join(
                                       os.path.abspath(__file__),
                                       os.pardir,
                                       os.pardir,
                                       os.pardir))

    dev_conf = os.path.join(possible_topdir,
                            'etc',
                            'keystone.conf')
    if not config_files:
        config_files = None
        if os.path.exists(dev_conf):
            config_files = [dev_conf]

    common.configure(config_files=config_files)

    # Log the options used when starting if we're in debug mode...
    if CONF.debug:
        CONF.log_opt_values(log.getLogger(CONF.prog), log.DEBUG)

    post_log_configured_function()

    def loadapp():
        return keystone_service.loadapp(
            'config:%s' % find_paste_config(), name)

    _unused, application = common.setup_backends(
        startup_application_fn=loadapp)

    # setup OSprofiler notifier and enable the profiling if that is configured
    # in Keystone configuration file.
    profiler.setup(name)

    return application


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


def _get_config_files(env=None):
    if env is None:
        env = os.environ

    dirname = env.get('OS_KEYSTONE_CONFIG_DIR', '').strip()

    files = [s.strip() for s in
             env.get('OS_KEYSTONE_CONFIG_FILES', '').split(';') if s.strip()]

    if dirname:
        if not files:
            files = ['keystone.conf']
        files = [os.path.join(dirname, fname) for fname in files]

    return files


def initialize_admin_application():
    return initialize_application(name='admin',
                                  config_files=_get_config_files())


def initialize_public_application():
    return initialize_application(name='main',
                                  config_files=_get_config_files())
