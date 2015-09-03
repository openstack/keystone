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

import logging

from oslo_config import cfg
import oslo_i18n
import oslo_middleware.cors as cors


# NOTE(dstanek): i18n.enable_lazy() must be called before
# keystone.i18n._() is called to ensure it has the desired lazy lookup
# behavior. This includes cases, like keystone.exceptions, where
# keystone.i18n._() is called at import time.
oslo_i18n.enable_lazy()


from keystone.common import environment
from keystone import config
import keystone.middleware.core as middleware_core
from keystone.server import common
from keystone import service as keystone_service


CONF = cfg.CONF

KEYSTONE_HEADERS = [
    middleware_core.AUTH_TOKEN_HEADER,
    middleware_core.SUBJECT_TOKEN_HEADER,
    'X-Project-Id',
    'X-Project-Name',
    'X-Project-Domain-Id',
    'X-Project-Domain-Name',
    'X-Domain-Id',
    'X-Domain-Name'
]


def initialize_application(name):
    common.configure()

    # Log the options used when starting if we're in debug mode...
    if CONF.debug:
        CONF.log_opt_values(logging.getLogger(CONF.prog), logging.DEBUG)

    environment.use_stdlib()

    def loadapp():
        return keystone_service.loadapp(
            'config:%s' % config.find_paste_config(), name)

    _unused, application = common.setup_backends(
        startup_application_fn=loadapp)

    # Create a CORS wrapper, and attach keystone-specific defaults that must be
    # included in all CORS responses
    application = cors.CORS(application, CONF)
    application.set_latent(
        allow_headers=KEYSTONE_HEADERS,
        allow_methods=['GET', 'PUT', 'POST', 'DELETE', 'PATCH'],
        expose_headers=KEYSTONE_HEADERS
    )
    return application


def initialize_admin_application():
    return initialize_application('admin')


def initialize_public_application():
    return initialize_application('main')
