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

import sys

import functools
import routes

from keystone import assignment
from keystone import auth
from keystone import catalog
from keystone.common import wsgi
from keystone import config
from keystone import controllers
from keystone import credential
from keystone import identity
from keystone.openstack.common import log
from keystone import policy
from keystone import routers
from keystone import token
from keystone import trust


CONF = config.CONF
LOG = log.getLogger(__name__)


def fail_gracefully(f):
    """Logs exceptions and aborts."""
    @functools.wraps(f)
    def wrapper(*args, **kw):
        try:
            return f(*args, **kw)
        except Exception as e:
            LOG.debug(e, exc_info=True)

            # exception message is printed to all logs
            LOG.critical(e)
            sys.exit(1)

    return wrapper


@fail_gracefully
def public_app_factory(global_conf, **local_conf):
    controllers.register_version('v2.0')
    return wsgi.ComposingRouter(routes.Mapper(),
                                [assignment.routers.Public(),
                                 token.routers.Router(),
                                 routers.VersionV2('public'),
                                 routers.Extension(False)])


@fail_gracefully
def admin_app_factory(global_conf, **local_conf):
    return wsgi.ComposingRouter(routes.Mapper(),
                                [identity.routers.Admin(),
                                 assignment.routers.Admin(),
                                    token.routers.Router(),
                                    routers.VersionV2('admin'),
                                    routers.Extension()])


@fail_gracefully
def public_version_app_factory(global_conf, **local_conf):
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('public')])


@fail_gracefully
def admin_version_app_factory(global_conf, **local_conf):
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('admin')])


@fail_gracefully
def v3_app_factory(global_conf, **local_conf):
    controllers.register_version('v3')
    mapper = routes.Mapper()
    v3routers = []
    for module in [assignment, auth, catalog, credential, identity, policy]:
        module.routers.append_v3_routers(mapper, v3routers)

    if CONF.trust.enabled:
        trust.routers.append_v3_routers(mapper, v3routers)

    # Add in the v3 version api
    v3routers.append(routers.VersionV3('admin'))
    v3routers.append(routers.VersionV3('public'))
    # TODO(ayoung): put token routes here
    return wsgi.ComposingRouter(mapper, v3routers)
